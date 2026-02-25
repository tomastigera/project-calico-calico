// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	_ "embed"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/lib/std/cryptoutils"
)

var (
	//go:embed testdata/kubeconfig
	validKubeconfig string
	//go:embed testdata/calico-node.env
	validEnvFile string
	//go:embed testdata/custom-node-certs.crt
	customNodeCert []byte
	//go:embed testdata/custom-typha-certs.crt
	customTyphaCert []byte
)

var _ = Describe("NonClusterHost Certificate Manager Tests", func() {
	var (
		fakeClientSet *fake.Clientset

		tmpDir string

		caFilePath   string
		certFilePath string
		pkFilePath   string

		envFilePath string
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "caFile")
		Expect(err).NotTo(HaveOccurred())

		caFilePath = filepath.Join(tmpDir, "ca.crt")
		certFilePath = filepath.Join(tmpDir, "calico-node.crt")
		pkFilePath = filepath.Join(tmpDir, "calico-node.key")

		envFilePath = filepath.Join(tmpDir, "calico-node.env")

		// write kubeconfig and export KUBECONFIG environment variable
		kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
		kubeconfigFile, err := os.OpenFile(kubeconfigPath, os.O_CREATE|os.O_WRONLY, 0o600)
		defer func() { Expect(kubeconfigFile.Close()).NotTo(HaveOccurred()) }()
		Expect(err).NotTo(HaveOccurred())
		_, err = kubeconfigFile.WriteString(validKubeconfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.Setenv("KUBECONFIG", kubeconfigPath)).NotTo(HaveOccurred())

		fakeClientSet = fake.NewSimpleClientset()
	})

	AfterEach(func() {
		Expect(os.RemoveAll(tmpDir)).NotTo(HaveOccurred())
	})

	It("should create a new certificate manager", func() {
		certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
		Expect(err).NotTo(HaveOccurred())
		Expect(certMan).NotTo(BeNil())

		certMan.k8sClientSet = fakeClientSet
		byo, err := certMan.fetchBYOSecrets()
		Expect(err).NotTo(HaveOccurred())
		Expect(byo).To(BeNil())
	})

	Context("certificate validation", func() {
		It("should validate an existing certificate", func() {
			// write valid certificate files
			ca, err := cryptoutils.NewCA("nch-certman-test-ca")
			Expect(err).NotTo(HaveOccurred())

			tlsCert, err := ca.CreateServerCert("some-nch", []string{"some-nch"})
			Expect(err).NotTo(HaveOccurred())

			certFile, err := os.OpenFile(certFilePath, os.O_CREATE|os.O_WRONLY, 0o644)
			defer func() { Expect(certFile.Close()).NotTo(HaveOccurred()) }()
			Expect(err).NotTo(HaveOccurred())
			Expect(tlsCert.WriteCertificates(certFile)).NotTo(HaveOccurred())

			pkFile, err := os.OpenFile(pkFilePath, os.O_CREATE|os.O_WRONLY, 0o600)
			defer func() { Expect(pkFile.Close()).NotTo(HaveOccurred()) }()
			Expect(err).NotTo(HaveOccurred())
			Expect(tlsCert.WritePrivateKey(pkFile)).NotTo(HaveOccurred())

			caFile, err := os.OpenFile(caFilePath, os.O_CREATE|os.O_WRONLY, 0o644)
			defer func() { Expect(caFile.Close()).NotTo(HaveOccurred()) }()
			Expect(err).NotTo(HaveOccurred())
			Expect(ca.WriteCertificates(caFile)).NotTo(HaveOccurred())

			certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certMan).NotTo(BeNil())

			// The certificate created by cryptoutils is valid for 10 years,
			// so it should be valid even with a 90-day renewal threshold
			renewalThreshold := 90 * 24 * time.Hour
			valid, err := certMan.isCertificateValid(renewalThreshold)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeTrue())

			// A very long renewal threshold should invalidate the certificate
			renewalThreshold = 11 * 365 * 24 * time.Hour
			valid, err = certMan.isCertificateValid(renewalThreshold)
			Expect(err).To(HaveOccurred())
			Expect(valid).To(BeFalse())
		})

		It("should return false but no error for missing certificate files", func() {
			certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certMan).NotTo(BeNil())

			renewalThreshold := 9 * 24 * time.Hour
			valid, err := certMan.isCertificateValid(renewalThreshold)
			Expect(err).NotTo(HaveOccurred())
			Expect(valid).To(BeFalse())
		})

		It("should return false and error for invalid certificate files", func() {
			certFile, err := os.OpenFile(certFilePath, os.O_CREATE|os.O_WRONLY, 0o644)
			defer func() { Expect(certFile.Close()).NotTo(HaveOccurred()) }()
			Expect(err).NotTo(HaveOccurred())
			_, err = certFile.WriteString("invalid-cert")
			Expect(err).NotTo(HaveOccurred())

			certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certMan).NotTo(BeNil())

			renewalThreshold := 9 * 24 * time.Hour
			valid, err := certMan.isCertificateValid(renewalThreshold)
			Expect(err).To(HaveOccurred())
			Expect(valid).To(BeFalse())
		})
	})

	Context("BYO", func() {
		var (
			typhaCA    *corev1.ConfigMap
			nodeSecret *corev1.Secret
		)

		BeforeEach(func() {
			var err error

			// create tigera-operator/typha-ca configmap
			typhaCAConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "typha-ca",
					Namespace: "tigera-operator",
				},
				Data: map[string]string{
					"caBundle": "some-ca-data",
				},
			}
			typhaCA, err = fakeClientSet.CoreV1().ConfigMaps("tigera-operator").Create(context.TODO(), typhaCAConfigMap, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(typhaCA).NotTo(BeNil())

			// create tigera-operator/node-certs-noncluster-host certificate secret
			nodeCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "node-certs-noncluster-host",
					Namespace: "tigera-operator",
				},
				Data: map[string][]byte{
					"tls.crt": customNodeCert,
					"tls.key": []byte("some-node-tls-key"),
				},
			}
			nodeSecret, err = fakeClientSet.CoreV1().Secrets("tigera-operator").Create(context.TODO(), nodeCertSecret, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(nodeSecret).NotTo(BeNil())

			// create tigera-operator/typha-certs-noncluster-host certificate secret
			typhaCertSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "typha-certs-noncluster-host",
					Namespace: "tigera-operator",
				},
				Data: map[string][]byte{
					"tls.crt": customTyphaCert,
					"tls.key": []byte("some-typha-tls-key"),
				},
			}
			typhaSecret, err := fakeClientSet.CoreV1().Secrets("tigera-operator").Create(context.TODO(), typhaCertSecret, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(typhaSecret).NotTo(BeNil())
		})

		AfterEach(func() {
			_ = fakeClientSet.CoreV1().ConfigMaps("tigera-operator").Delete(context.TODO(), "typha-ca", metav1.DeleteOptions{})
			_ = fakeClientSet.CoreV1().Secrets("tigera-operator").Delete(context.TODO(), "node-certs-noncluster-host", metav1.DeleteOptions{})
		})

		It("should detect BYO when resources are present", func() {
			certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certMan).NotTo(BeNil())

			certMan.k8sClientSet = fakeClientSet
			byo, err := certMan.fetchBYOSecrets()
			Expect(err).NotTo(HaveOccurred())
			Expect(byo).NotTo(BeNil())

			Expect(byo).NotTo(BeNil())
			Expect(byo.typhaCA).NotTo(BeNil())
			Expect(byo.typhaCA).To(Equal(typhaCA))
			Expect(byo.nodeSecret).NotTo(BeNil())
			Expect(byo.nodeSecret).To(Equal(nodeSecret))
		})

		It("should detect non-BYO when resources are absent", func() {
			// delete the typha-ca configmap
			err := fakeClientSet.CoreV1().ConfigMaps("tigera-operator").Delete(context.TODO(), "typha-ca", metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certMan).NotTo(BeNil())
			certMan.k8sClientSet = fakeClientSet

			byo, err := certMan.fetchBYOSecrets()
			Expect(err).NotTo(HaveOccurred())
			Expect(byo).To(BeNil())

			// recreate the typha-ca configmap, but delete the node-certs-noncluster-host secret
			_, err = fakeClientSet.CoreV1().ConfigMaps("tigera-operator").Create(context.TODO(), typhaCA, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			err = fakeClientSet.CoreV1().Secrets("tigera-operator").Delete(context.TODO(), "node-certs-noncluster-host", metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			byo, err = certMan.fetchBYOSecrets()
			Expect(err).NotTo(HaveOccurred())
			Expect(byo).To(BeNil())
		})

		It("should write certificates from BYO resources", func() {
			// create an env file
			envFile, err := os.OpenFile(envFilePath, os.O_CREATE|os.O_WRONLY, 0o644)
			defer func() { Expect(envFile.Close()).NotTo(HaveOccurred()) }()
			Expect(err).NotTo(HaveOccurred())
			_, err = envFile.WriteString(validEnvFile)
			Expect(err).NotTo(HaveOccurred())

			certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certMan).NotTo(BeNil())

			certMan.k8sClientSet = fakeClientSet
			byo, err := certMan.fetchBYOSecrets()
			Expect(err).NotTo(HaveOccurred())
			Expect(byo).NotTo(BeNil())

			err = certMan.writeBYOCertificate(byo)
			Expect(err).NotTo(HaveOccurred())

			// verify certificate files
			certBytes, err := os.ReadFile(certFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certBytes).To(Equal(customNodeCert))

			pkBytes, err := os.ReadFile(pkFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(pkBytes)).To(Equal("some-node-tls-key"))

			caBytes, err := os.ReadFile(caFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(caBytes)).To(Equal("some-ca-data"))

			// verify env file
			envBytes, err := os.ReadFile(envFilePath)
			Expect(err).NotTo(HaveOccurred())
			envStr := string(envBytes)
			Expect(envStr).To(ContainSubstring("FELIX_TYPHACN=custom-typha-certs"))
		})

		It("should create env file if it does not exist", func() {
			_, err := os.Stat(envFilePath)
			Expect(os.IsNotExist(err)).To(BeTrue())

			certMan, err := NewCertificateManager(context.TODO(), caFilePath, pkFilePath, certFilePath, envFilePath)
			Expect(err).NotTo(HaveOccurred())
			Expect(certMan).NotTo(BeNil())

			certMan.k8sClientSet = fakeClientSet
			byo, err := certMan.fetchBYOSecrets()
			Expect(err).NotTo(HaveOccurred())
			Expect(byo).NotTo(BeNil())

			err = certMan.writeBYOCertificate(byo)
			Expect(err).NotTo(HaveOccurred())
			envBytes, err := os.ReadFile(envFilePath)
			Expect(err).NotTo(HaveOccurred())
			envStr := string(envBytes)
			Expect(envStr).To(Equal("FELIX_TYPHACN=custom-typha-certs\n"))
		})
	})
})
