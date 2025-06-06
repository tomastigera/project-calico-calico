// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	kcpcfg "github.com/projectcalico/calico/key-cert-provisioner/pkg/cfg"
	kcpk8s "github.com/projectcalico/calico/key-cert-provisioner/pkg/k8s"
	kcptls "github.com/projectcalico/calico/key-cert-provisioner/pkg/tls"
)

const (
	caBundleName       = "tigera-ca-bundle"
	configMapNamespace = "calico-system"
)

type CertificateManager struct {
	ctx context.Context
	cfg *kcpcfg.Config

	k8sClientSet *kubernetes.Clientset
}

func NewCertificateManager(ctx context.Context, caFile, pkFile, certFile string) (*CertificateManager, error) {
	// Create k8s clientset
	kubeConfigPath := os.Getenv("KUBECONFIG")
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	// Create key-cert-provisioner config
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	// Must be in "<secretName>:<hostname>" format
	csrName := "node-certs-noncluster-host:" + hostname

	kcpConfig := &kcpcfg.Config{
		AppName:             "calico-node",
		CACertPath:          caFile,
		CSRName:             csrName,
		CSRLabels:           map[string]string{"nonclusterhost.tigera.io/hostname": hostname},
		CertPath:            certFile,
		CommonName:          "typha-client-noncluster-host",
		DNSNames:            []string{"typha-client-noncluster-host"},
		KeyPath:             pkFile,
		PrivateKeyAlgorithm: "RSAWithSize2048",
		SignatureAlgorithm:  "SHA256WithRSA",
		Signer:              "tigera.io/operator-signer",
	}

	return &CertificateManager{
		ctx: ctx,
		cfg: kcpConfig,

		k8sClientSet: clientset,
	}, nil
}

func (m *CertificateManager) IsCertificateValid(renewalThreshold time.Duration) (bool, error) {
	certData, err := os.ReadFile(m.cfg.CertPath)
	if err != nil {
		return false, err
	}

	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("failed to decode certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return false, errors.New("certificate is not valid yet")
	} else if now.After(cert.NotAfter.Add(-renewalThreshold)) {
		return false, errors.New("certificate has reached its renewal threshold or has expired")
	}
	return true, nil
}

func (m *CertificateManager) RequestAndWriteCertificate() error {
	caCertPEM, err := m.requestCABundle()
	if err != nil {
		return err
	}
	m.cfg.CACertPEM = caCertPEM

	csr, err := kcptls.CreateX509CSR(m.cfg)
	if err != nil {
		return err
	}

	if err := kcpk8s.SubmitCSR(m.ctx, m.cfg, m.k8sClientSet, csr); err != nil {
		return err
	}

	if err := kcpk8s.WatchAndWriteCSR(m.ctx, m.k8sClientSet, m.cfg, csr); err != nil {
		return err
	}

	return nil
}

func (m *CertificateManager) requestCABundle() ([]byte, error) {
	cm, err := m.k8sClientSet.CoreV1().ConfigMaps(configMapNamespace).Get(m.ctx, caBundleName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	v, ok := cm.Data[caBundleName+".crt"]
	if !ok {
		err := errors.New("could not find Tigera CA bundle key in the ConfigMap")
		return nil, err
	}
	return []byte(v), nil
}
