// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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
	caBundleKey          = "caBundle"
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
	renew, err := m.shouldRenewCertificate(renewalThreshold)
	if err != nil {
		logrus.WithError(err).Warn("Certificate validation failed")
	}

	if renew {
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
			// Note: requestAndWriteCertificate already uses m.ctx internally, so
			// context cancellation is handled within the called functions.
			logrus.Info("Requesting new certificate from Tigera Operator")

			if err := m.requestAndWriteCertificate(); err != nil {
				return err
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

	// At this point the typha-ca ConfigMap exists, indicating BYO is intended.
	// If subsequent resources are missing, log a warning so partial BYO
	// misconfigurations are visible rather than silently falling through to
	// operator-signed CSR.
	secretName := nodeCertSecretName + nonClusterHostSuffix
	nodeSecret, err := m.k8sClientSet.CoreV1().Secrets(tigeraOperatorNamespace).Get(m.ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logrus.Warnf("BYO typha-ca ConfigMap exists but secret %q not found; falling back to operator-signed certificate", secretName)
			return nil, nil
		}
		return nil, err
	}

	secretName = typhaCertSecretName + nonClusterHostSuffix
	typhaSecret, err := m.k8sClientSet.CoreV1().Secrets(tigeraOperatorNamespace).Get(m.ctx, secretName, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			logrus.Warnf("BYO typha-ca ConfigMap and node secret exist but secret %q not found; falling back to operator-signed certificate", secretName)
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

// shouldRenewCertificate checks whether the certificate or CA bundle needs renewal.
// It returns true if any certificate is missing, not yet valid, expired, or within
// the renewal threshold window.
func (m *CertificateManager) shouldRenewCertificate(renewalThreshold time.Duration) (bool, error) {
	certPaths := []string{m.cfg.CertPath, m.cfg.CACertPath}
	for _, certPath := range certPaths {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			if os.IsNotExist(err) {
				return true, nil
			}
			return true, err
		}

		certs, err := parseCertificates(certData)
		if err != nil {
			return true, err
		}

		now := time.Now()
		for _, cert := range certs {
			if now.Before(cert.NotBefore) {
				return true, fmt.Errorf("certificate %s (CN=%s) is not valid yet (notBefore=%s)", certPath, cert.Subject.CommonName, cert.NotBefore)
			} else if now.After(cert.NotAfter.Add(-renewalThreshold)) {
				return true, fmt.Errorf("certificate %s (CN=%s) has reached its renewal threshold or has expired (notAfter=%s)", certPath, cert.Subject.CommonName, cert.NotAfter)
			}
		}
	}
	return false, nil
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
	return os.WriteFile(m.nodeEnvironmentFilePath, []byte(output), 0o644)
}

func (m *CertificateManager) writeBYOCertificate(byo *byo) error {
	if byo == nil {
		return errors.New("failed to get BYO certificates")
	}

	// write certificate files to disk
	keyData, ok := byo.nodeSecret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return errors.New("TLS private key not found in node secret")
	}
	if err := os.WriteFile(m.cfg.KeyPath, keyData, 0o600); err != nil {
		return err
	}
	certData, ok := byo.nodeSecret.Data[corev1.TLSCertKey]
	if !ok {
		return errors.New("TLS certificate not found in node secret")
	}
	if err := os.WriteFile(m.cfg.CertPath, certData, 0o644); err != nil {
		return err
	}
	caBundle, ok := byo.typhaCA.Data[caBundleKey]
	if !ok {
		return fmt.Errorf("CA bundle key %q not found in ConfigMap", caBundleKey)
	}
	if err := os.WriteFile(m.cfg.CACertPath, []byte(caBundle), 0o644); err != nil {
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

// parseCertificates parses all PEM-encoded certificates in the given data.
// This handles CA bundles that may contain multiple certificates in a chain.
func parseCertificates(certPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("failed to decode any certificate from PEM data")
	}
	return certs, nil
}

// parseCertificate parses the first PEM-encoded certificate from the given data.
func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	certs, err := parseCertificates(certPEM)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func parseCommonNameAndURISAN(secret *corev1.Secret) (string, string, error) {
	if secret == nil {
		return "", "", errors.New("secret is nil")
	}
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
