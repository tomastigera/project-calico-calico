// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
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

	nodeCertSecretName    = "node-certs"
	typhaCertSecretName   = "typha-certs"
	typhaCAName           = "typha-ca"
	typhaClientCommonName = "typha-client"

	nonClusterHostSuffix = "-noncluster-host"
)

type byo struct {
	typhaCA    *corev1.ConfigMap
	nodeSecret *corev1.Secret

	typhaCN     string
	typhaURISAN string
}

type CertificateManager struct {
	ctx context.Context
	cfg *kcpcfg.Config

	k8sClientSet kubernetes.Interface

	nodeEnvironmentFilePath string
}

func NewCertificateManager(ctx context.Context, caFile, pkFile, certFile string, envFilePath string) (*CertificateManager, error) {
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
	csrName := fmt.Sprintf("%s%s:%s", nodeCertSecretName, nonClusterHostSuffix, hostname)

	kcpConfig := &kcpcfg.Config{
		AppName:             "calico-node",
		CACertPath:          caFile,
		CSRName:             csrName,
		CSRLabels:           map[string]string{"nonclusterhost.tigera.io/hostname": hostname},
		CertPath:            certFile,
		CommonName:          typhaClientCommonName + nonClusterHostSuffix,
		DNSNames:            []string{typhaClientCommonName + nonClusterHostSuffix},
		KeyPath:             pkFile,
		PrivateKeyAlgorithm: "RSAWithSize2048",
		SignatureAlgorithm:  "SHA256WithRSA",
		Signer:              "tigera.io/operator-signer",
	}

	return &CertificateManager{
		ctx: ctx,
		cfg: kcpConfig,

		k8sClientSet: clientset,

		nodeEnvironmentFilePath: envFilePath,
	}, nil
}

func (m *CertificateManager) MaybeRenewCertificate(renewalThreshold time.Duration) error {
	valid, err := m.isCertificateValid(renewalThreshold)
	if err != nil {
		return err
	}

	if !valid {
		logrus.Info("Certificate is not valid or is nearing expiry, attempting to renew")

		if byo, err := m.fetchBYOSecrets(); err != nil {
			return err
		} else if byo != nil {
			// Use BYO certificate.
			logrus.Info("Using BYO certificate")

			if err := m.writeBYOCertificate(byo); err != nil {
				return err
			}
		} else {
			// Send a CSR to the Tigera Operator signer to request a new certificate.
			logrus.Info("Requesting new certificate from Tigera Operator")

			resCh := make(chan error, 1)
			defer close(resCh)

			go func() {
				// Rotate private key and request a new certificate when the current certificate is expired.
				if err := m.requestAndWriteCertificate(); err != nil {
					resCh <- err
				}
				resCh <- nil
			}()

			select {
			case err := <-resCh:
				if err != nil {
					return err
				}
			case <-m.ctx.Done():
				if err := m.ctx.Err(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *CertificateManager) fetchBYOSecrets() (*byo, error) {
	typhaCA, err := m.k8sClientSet.CoreV1().ConfigMaps(tigeraOperatorNamespace).Get(m.ctx, typhaCAName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	secretName := nodeCertSecretName + nonClusterHostSuffix
	nodeSecret, err := m.k8sClientSet.CoreV1().Secrets(tigeraOperatorNamespace).Get(m.ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	secretName = typhaCertSecretName + nonClusterHostSuffix
	typhaSecret, err := m.k8sClientSet.CoreV1().Secrets(tigeraOperatorNamespace).Get(m.ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	typhaCN, typhaURISAN, err := parseCommonNameAndURISAN(typhaSecret)
	if err != nil {
		return nil, err
	}

	return &byo{
		typhaCA:    typhaCA,
		nodeSecret: nodeSecret,

		typhaCN:     typhaCN,
		typhaURISAN: typhaURISAN,
	}, nil
}

func (m *CertificateManager) isCertificateValid(renewalThreshold time.Duration) (bool, error) {
	// Validate both the certificate and CA bundle
	certs := []string{m.cfg.CertPath, m.cfg.CACertPath}
	for _, cert := range certs {
		certData, err := os.ReadFile(cert)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}

		cert, err := parseCertificate(certData)
		if err != nil {
			return false, err
		}

		now := time.Now()
		if now.Before(cert.NotBefore) {
			return false, errors.New("certificate is not valid yet")
		} else if now.After(cert.NotAfter.Add(-renewalThreshold)) {
			return false, errors.New("certificate has reached its renewal threshold or has expired")
		}
	}
	return true, nil
}

func (m *CertificateManager) requestAndWriteCertificate() error {
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

func (m *CertificateManager) updateNodeEnvironmentFile(key, value string) error {
	envFile, err := os.Open(m.nodeEnvironmentFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Create the file if it doesn't exist
			return os.WriteFile(m.nodeEnvironmentFilePath, fmt.Appendf(nil, "%s=%s\n", key, value), 0644)
		}
		return err
	}
	defer func() { _ = envFile.Close() }()

	var lines []string
	found := false

	scanner := bufio.NewScanner(envFile)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lines = append(lines, line)
			continue
		}

		parts := strings.SplitN(trimmed, "=", 2)
		if len(parts) != 2 {
			lines = append(lines, line)
			continue
		}

		k := strings.TrimSpace(parts[0])
		if k == key {
			lines = append(lines, fmt.Sprintf("%s=%s", key, value))
			found = true
		} else {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if !found {
		lines = append(lines, fmt.Sprintf("%s=%s", key, value))
	}

	output := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(m.nodeEnvironmentFilePath, []byte(output), 0644)
}

func (m *CertificateManager) writeBYOCertificate(byo *byo) error {
	if byo == nil {
		return errors.New("failed to get BYO certificates")
	}

	// write certificate files to disk
	if err := os.WriteFile(m.cfg.KeyPath, byo.nodeSecret.Data[corev1.TLSPrivateKeyKey], 0600); err != nil {
		return err
	}
	if err := os.WriteFile(m.cfg.CertPath, byo.nodeSecret.Data[corev1.TLSCertKey], 0644); err != nil {
		return err
	}
	if err := os.WriteFile(m.cfg.CACertPath, []byte(byo.typhaCA.Data["caBundle"]), 0644); err != nil {
		return err
	}

	// update environment file
	if byo.typhaCN != "" {
		if err := m.updateNodeEnvironmentFile("FELIX_TYPHACN", byo.typhaCN); err != nil {
			return err
		}
	}
	if byo.typhaURISAN != "" {
		if err := m.updateNodeEnvironmentFile("FELIX_TYPHAURISAN", byo.typhaURISAN); err != nil {
			return err
		}
	}
	return nil
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

func parseCommonNameAndURISAN(secret *corev1.Secret) (string, string, error) {
	certData, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return "", "", errors.New("failed to get TLS certificate from Typha certificate secret")
	}

	cert, err := parseCertificate(certData)
	if err != nil {
		return "", "", err
	}

	var cn, urisan string
	if cert.Subject.CommonName != "" {
		cn = cert.Subject.CommonName
	}
	if len(cert.URIs) > 0 {
		urisan = cert.URIs[0].String()
	}

	return cn, urisan, nil
}
