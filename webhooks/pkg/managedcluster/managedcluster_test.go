// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package managedcluster

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	_ "github.com/projectcalico/calico/webhooks/pkg/utils"
)

func generateCA() ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM, nil
}

func TestAdmit(t *testing.T) {
	testCases := []bool{true, false}

	for _, multiTenant := range testCases {
		t.Run(fmt.Sprintf("multiTenant=%v", multiTenant), func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset()
			h := &ManagedClusterHook{
				k8sClient:               k8sClient,
				managementClusterAddr:   "1.2.3.4:5678",
				managementClusterCAType: "custom",
				tunnelSecretName:        "test-secret",
				multiTenant:             multiTenant,
			}

			secretNamespace := "calico-system"
			if multiTenant {
				secretNamespace = "test-ns"
			}

			// Create the secret with invalid data
			_, err := k8sClient.CoreV1().Secrets(secretNamespace).Create(context.Background(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: secretNamespace},
				Data: map[string][]byte{
					"tls.crt": []byte("invalid-cert"),
					"tls.key": []byte("invalid-key"),
				},
			}, metav1.CreateOptions{})
			assert.NoError(t, err)

			mc := &v3.ManagedCluster{
				TypeMeta: metav1.TypeMeta{
					Kind:       v3.KindManagedCluster,
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "test-ns",
				},
			}
			raw, err := json.Marshal(mc)
			assert.NoError(t, err)

			ar := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:  "test-uid",
					Kind: metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindManagedCluster},
					Object: runtime.RawExtension{
						Raw: raw,
					},
					Operation: v1.Create,
					Namespace: "test-ns",
				},
			}

			// This should fail because of invalid cert data
			resp := h.admit(ar)
			assert.False(t, resp.Allowed)
			assert.Contains(t, resp.Result.Message, "Failed to prepare managed cluster")
		})
	}
}

func TestAdmitSuccess(t *testing.T) {
	testCases := []bool{true, false}

	for _, multiTenant := range testCases {
		t.Run(fmt.Sprintf("multiTenant=%v", multiTenant), func(t *testing.T) {
			k8sClient := fake.NewSimpleClientset()
			h := &ManagedClusterHook{
				k8sClient:               k8sClient,
				managementClusterAddr:   "1.2.3.4:5678",
				managementClusterCAType: "custom",
				tunnelSecretName:        "test-secret",
				multiTenant:             multiTenant,
			}

			secretNamespace := "calico-system"
			if multiTenant {
				secretNamespace = "test-ns"
			}

			cert, key, err := generateCA()
			assert.NoError(t, err)

			// Create the secret with VALID data
			_, err = k8sClient.CoreV1().Secrets(secretNamespace).Create(context.Background(), &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "test-secret", Namespace: secretNamespace},
				Data: map[string][]byte{
					"tls.crt": cert,
					"tls.key": key,
				},
			}, metav1.CreateOptions{})
			assert.NoError(t, err)

			mc := &v3.ManagedCluster{
				TypeMeta: metav1.TypeMeta{
					Kind:       v3.KindManagedCluster,
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-cluster",
					Namespace: "test-ns",
				},
			}
			raw, err := json.Marshal(mc)
			assert.NoError(t, err)

			ar := v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					UID:  "test-uid-success",
					Kind: metav1.GroupVersionKind{Group: "projectcalico.org", Version: "v3", Kind: v3.KindManagedCluster},
					Object: runtime.RawExtension{
						Raw: raw,
					},
					Operation: v1.Create,
					Namespace: "test-ns",
				},
			}

			resp := h.admit(ar)
			assert.True(t, resp.Allowed)
			assert.NotNil(t, resp.Patch)
			assert.Equal(t, v1.PatchTypeJSONPatch, *resp.PatchType)

			var patch []map[string]interface{}
			err = json.Unmarshal(resp.Patch, &patch)
			assert.NoError(t, err)
			assert.Len(t, patch, 2)

			// One patch for annotations, one for installationManifest
			paths := []string{patch[0]["path"].(string), patch[1]["path"].(string)}
			assert.Contains(t, paths, "/metadata/annotations")
			assert.Contains(t, paths, "/spec/installationManifest")
		})
	}
}
