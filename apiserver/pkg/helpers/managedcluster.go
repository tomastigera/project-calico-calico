// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package helpers

import (
	"context"
	"crypto/sha256"
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const AnnotationActiveCertificateFingerprint = "certs.tigera.io/active-fingerprint"

// PrepareManagedCluster generates credentials and installation manifest for a ManagedCluster.
// It returns the fingerprint and the installation manifest.
func PrepareManagedCluster(
	ctx context.Context,
	k8sClient kubernetes.Interface,
	mc *v3.ManagedCluster,
	tunnelSecretName string,
	tunnelSecretNamespace string,
	managementClusterAddr string,
	managementClusterCAType string,
) (string, string, error) {
	// Determine operator namespace
	operatorNs := mc.Spec.OperatorNamespace
	if operatorNs == "" {
		operatorNs = "tigera-operator"
	}

	// Query the CA secret.
	secret, err := k8sClient.CoreV1().Secrets(tunnelSecretNamespace).Get(ctx, tunnelSecretName, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("cannot get CA secret (%s) in namespace %s: %w", tunnelSecretName, tunnelSecretNamespace, err)
	}

	// Parse the certificate data into an x509 certificate.
	caCert, caKey, err := DecodeCertAndKey(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return "", "", fmt.Errorf("cannot parse CA certificate: %w", err)
	}

	// Generate x509 certificate and private key for the managed cluster
	certificate, privKey, err := Generate(caCert, caKey, mc.Name)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate client credentials for %s: %w", mc.Name, err)
	}

	// Calculate the hash of the certificate
	fingerprint := fmt.Sprintf("%x", sha256.Sum256(certificate.Raw))

	// Generate the installation manifest
	manifest := InstallationManifest(caCert, certificate, privKey, managementClusterAddr, managementClusterCAType, operatorNs)

	return fingerprint, manifest, nil
}
