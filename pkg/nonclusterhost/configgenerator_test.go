// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/golang-jwt/jwt/v4"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dyfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/lib/std/cryptoutils"
)

var _ = Describe("NonClusterHost Config Generator Tests", func() {
	var (
		fakeDynamicClient *dyfake.FakeDynamicClient
		fakeClientSet     *fake.Clientset

		opts *ConfigGeneratorOptions
	)

	BeforeEach(func() {
		gvrListKind := map[schema.GroupVersionResource]string{
			NonClusterHostGVR: "NonClusterHostList",
		}

		scheme := runtime.NewScheme()
		scheme.AddKnownTypes(NonClusterHostGVR.GroupVersion(), &unstructured.Unstructured{})
		fakeDynamicClient = dyfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrListKind)
		Expect(fakeDynamicClient).NotTo(BeNil())

		fakeClientSet = fake.NewSimpleClientset()

		opts = &ConfigGeneratorOptions{
			Namespace:      "calico-system",
			ServiceAccount: "tigera-noncluster-host",
			CertFile:       "",
		}
	})

	It("should generate a valid Kubeconfig for non-cluster hosts", func() {
		// Create the NonClusterHost resource
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "operator.tigera.io/v1",
				"kind":       "NonClusterHost",
				"metadata": map[string]interface{}{
					"name": "tigera-secure",
				},
				"spec": map[string]interface{}{
					"endpoint": "https://some.endpoint:1234",
				},
			},
		}
		nch, err := fakeDynamicClient.Resource(NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(nch).NotTo(BeNil())

		// Create the tigera-ca-private secret
		ca, err := cryptoutils.NewCA("nch-cfggen-test-ca")
		Expect(err).NotTo(HaveOccurred())
		tlscert, err := ca.CreateServerCert("some-name", []string{"some-host"})
		Expect(err).NotTo(HaveOccurred())

		certsBuf := &bytes.Buffer{}
		err = tlscert.WriteCertificates(certsBuf)
		Expect(err).NotTo(HaveOccurred())
		keyBuf := &bytes.Buffer{}
		err = tlscert.WritePrivateKey(keyBuf)
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-ca-private",
				Namespace: "tigera-operator",
			},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certsBuf.Bytes(),
				corev1.TLSPrivateKeyKey: keyBuf.Bytes(),
			},
			Type: corev1.SecretTypeTLS,
		}
		_, err = fakeClientSet.CoreV1().Secrets("tigera-operator").Create(context.TODO(), secret, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create the service account
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-noncluster-host",
				Namespace: "calico-system",
			},
		}
		_, err = fakeClientSet.CoreV1().ServiceAccounts("calico-system").Create(context.TODO(), sa, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Now generate the Kubeconfig
		gen := &ConfigGenerator{
			dynamicClient: fakeDynamicClient,
			k8sClient:     fakeClientSet,
			options:       opts,
		}
		yaml, err := gen.Generate(context.TODO())
		Expect(err).NotTo(HaveOccurred())
		Expect(len(yaml)).NotTo(BeZero())

		config, err := clientcmd.Load(yaml)
		Expect(err).NotTo(HaveOccurred())
		Expect(config).NotTo(BeNil())

		Expect(config.CurrentContext).To(Equal("noncluster-hosts"))
		Expect(config.Clusters).To(HaveLen(1))
		cluster, ok := config.Clusters["noncluster-hosts"]
		Expect(ok).To(BeTrue())
		Expect(cluster.Server).To(Equal("https://some.endpoint:1234"))
		Expect(cluster.CertificateAuthorityData).To(Equal(certsBuf.Bytes()))

		Expect(config.AuthInfos).To(HaveLen(1))
		authInfo, ok := config.AuthInfos["tigera-noncluster-host"]
		Expect(ok).To(BeTrue())

		claims := jwt.RegisteredClaims{}
		tkn, err := jwt.ParseWithClaims(authInfo.Token, &claims, func(token *jwt.Token) (interface{}, error) {
			block, _ := pem.Decode(certsBuf.Bytes())
			Expect(block).NotTo(BeNil())
			Expect(block.Type).To(Equal("CERTIFICATE"))
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
			Expect(ok).To(BeTrue())
			return pubKey, nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(tkn).NotTo(BeNil())
		Expect(tkn.Valid).To(BeTrue())

		Expect(claims.Issuer).To(Equal("tigera.io/operator-signer"))
		Expect(claims.Subject).To(Equal("system:serviceaccount:calico-system:tigera-noncluster-host"))
		Expect(claims.Audience).To(HaveLen(1))
		Expect(claims.Audience[0]).To(Equal("tigera-manager"))
	})

	It("should generate a valid Kubeconfig for non-cluster hosts and read certificate from file", func() {
		// Create the NonClusterHost resource
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "operator.tigera.io/v1",
				"kind":       "NonClusterHost",
				"metadata": map[string]interface{}{
					"name": "tigera-secure",
				},
				"spec": map[string]interface{}{
					"endpoint": "https://some.endpoint:1234",
				},
			},
		}
		nch, err := fakeDynamicClient.Resource(NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(nch).NotTo(BeNil())

		// Create the tigera-ca-private secret
		ca, err := cryptoutils.NewCA("nch-cfggen-test-ca")
		Expect(err).NotTo(HaveOccurred())
		tlscert, err := ca.CreateServerCert("some-name", []string{"some-host"})
		Expect(err).NotTo(HaveOccurred())

		certsBuf := &bytes.Buffer{}
		err = tlscert.WriteCertificates(certsBuf)
		Expect(err).NotTo(HaveOccurred())
		keyBuf := &bytes.Buffer{}
		err = tlscert.WritePrivateKey(keyBuf)
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-ca-private",
				Namespace: "tigera-operator",
			},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certsBuf.Bytes(),
				corev1.TLSPrivateKeyKey: keyBuf.Bytes(),
			},
			Type: corev1.SecretTypeTLS,
		}
		_, err = fakeClientSet.CoreV1().Secrets("tigera-operator").Create(context.TODO(), secret, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create the service account
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-noncluster-host",
				Namespace: "calico-system",
			},
		}
		_, err = fakeClientSet.CoreV1().ServiceAccounts("calico-system").Create(context.TODO(), sa, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Read certificate from a file
		tmpFile, err := os.CreateTemp("", "nch-ca.crt")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		_, err = tmpFile.Write([]byte("some-ca-cert-in-pem"))
		Expect(err).NotTo(HaveOccurred())
		err = tmpFile.Close()
		Expect(err).NotTo(HaveOccurred())

		opts.CertFile = tmpFile.Name()

		// Now generate the Kubeconfig
		gen := &ConfigGenerator{
			dynamicClient: fakeDynamicClient,
			k8sClient:     fakeClientSet,
			options:       opts,
		}
		yaml, err := gen.Generate(context.TODO())
		Expect(err).NotTo(HaveOccurred())
		Expect(len(yaml)).NotTo(BeZero())

		config, err := clientcmd.Load(yaml)
		Expect(err).NotTo(HaveOccurred())
		Expect(config).NotTo(BeNil())

		Expect(config.CurrentContext).To(Equal("noncluster-hosts"))
		Expect(config.Clusters).To(HaveLen(1))
		cluster, ok := config.Clusters["noncluster-hosts"]
		Expect(ok).To(BeTrue())
		Expect(cluster.Server).To(Equal("https://some.endpoint:1234"))
		Expect(cluster.CertificateAuthorityData).To(Equal([]byte("some-ca-cert-in-pem")))

		Expect(config.AuthInfos).To(HaveLen(1))
		authInfo, ok := config.AuthInfos["tigera-noncluster-host"]
		Expect(ok).To(BeTrue())

		claims := jwt.RegisteredClaims{}
		tkn, err := jwt.ParseWithClaims(authInfo.Token, &claims, func(token *jwt.Token) (interface{}, error) {
			block, _ := pem.Decode(certsBuf.Bytes())
			Expect(block).NotTo(BeNil())
			Expect(block.Type).To(Equal("CERTIFICATE"))
			cert, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
			Expect(ok).To(BeTrue())
			return pubKey, nil
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(tkn).NotTo(BeNil())
		Expect(tkn.Valid).To(BeTrue())

		Expect(claims.Issuer).To(Equal("tigera.io/operator-signer"))
		Expect(claims.Subject).To(Equal("system:serviceaccount:calico-system:tigera-noncluster-host"))
		Expect(claims.Audience).To(HaveLen(1))
		Expect(claims.Audience[0]).To(Equal("tigera-manager"))
	})

	It("should return error when NonClusterHost resource is missing", func() {
		// Create the tigera-ca-private secret
		ca, err := cryptoutils.NewCA("nch-cfggen-test-ca")
		Expect(err).NotTo(HaveOccurred())
		tlscert, err := ca.CreateServerCert("some-name", []string{"some-host"})
		Expect(err).NotTo(HaveOccurred())

		certsBuf := &bytes.Buffer{}
		err = tlscert.WriteCertificates(certsBuf)
		Expect(err).NotTo(HaveOccurred())
		keyBuf := &bytes.Buffer{}
		err = tlscert.WritePrivateKey(keyBuf)
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-ca-private",
				Namespace: "tigera-operator",
			},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certsBuf.Bytes(),
				corev1.TLSPrivateKeyKey: keyBuf.Bytes(),
			},
			Type: corev1.SecretTypeTLS,
		}
		_, err = fakeClientSet.CoreV1().Secrets("tigera-operator").Create(context.TODO(), secret, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Create the service account
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-noncluster-host",
				Namespace: "calico-system",
			},
		}
		_, err = fakeClientSet.CoreV1().ServiceAccounts("calico-system").Create(context.TODO(), sa, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Now generate the Kubeconfig
		gen := &ConfigGenerator{
			dynamicClient: fakeDynamicClient,
			k8sClient:     fakeClientSet,
			options:       opts,
		}
		yaml, err := gen.Generate(context.TODO())
		Expect(err).To(HaveOccurred())
		Expect(yaml).To(BeNil())
	})

	It("should return error when tigera-ca-private secret is missing", func() {
		// Create the NonClusterHost resource
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "operator.tigera.io/v1",
				"kind":       "NonClusterHost",
				"metadata": map[string]interface{}{
					"name": "tigera-secure",
				},
				"spec": map[string]interface{}{
					"endpoint": "https://some.endpoint:1234",
				},
			},
		}
		nch, err := fakeDynamicClient.Resource(NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(nch).NotTo(BeNil())

		// Create the service account
		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-noncluster-host",
				Namespace: "calico-system",
			},
		}
		_, err = fakeClientSet.CoreV1().ServiceAccounts("calico-system").Create(context.TODO(), sa, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Now generate the Kubeconfig
		gen := &ConfigGenerator{
			dynamicClient: fakeDynamicClient,
			k8sClient:     fakeClientSet,
			options:       opts,
		}
		yaml, err := gen.Generate(context.TODO())
		Expect(err).To(HaveOccurred())
		Expect(yaml).To(BeNil())
	})

	It("should return error when service account is missing", func() {
		// Create the NonClusterHost resource
		obj := &unstructured.Unstructured{
			Object: map[string]interface{}{
				"apiVersion": "operator.tigera.io/v1",
				"kind":       "NonClusterHost",
				"metadata": map[string]interface{}{
					"name": "tigera-secure",
				},
				"spec": map[string]interface{}{
					"endpoint": "https://some.endpoint:1234",
				},
			},
		}
		nch, err := fakeDynamicClient.Resource(NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(nch).NotTo(BeNil())

		// Create the tigera-ca-private secret
		ca, err := cryptoutils.NewCA("nch-cfggen-test-ca")
		Expect(err).NotTo(HaveOccurred())
		tlscert, err := ca.CreateServerCert("some-name", []string{"some-host"})
		Expect(err).NotTo(HaveOccurred())

		certsBuf := &bytes.Buffer{}
		err = tlscert.WriteCertificates(certsBuf)
		Expect(err).NotTo(HaveOccurred())
		keyBuf := &bytes.Buffer{}
		err = tlscert.WritePrivateKey(keyBuf)
		Expect(err).NotTo(HaveOccurred())

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tigera-ca-private",
				Namespace: "tigera-operator",
			},
			Data: map[string][]byte{
				corev1.TLSCertKey:       certsBuf.Bytes(),
				corev1.TLSPrivateKeyKey: keyBuf.Bytes(),
			},
			Type: corev1.SecretTypeTLS,
		}
		_, err = fakeClientSet.CoreV1().Secrets("tigera-operator").Create(context.TODO(), secret, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Now generate the Kubeconfig
		gen := &ConfigGenerator{
			dynamicClient: fakeDynamicClient,
			k8sClient:     fakeClientSet,
			options:       opts,
		}
		yaml, err := gen.Generate(context.TODO())
		Expect(err).To(HaveOccurred())
		Expect(yaml).To(BeNil())
	})
})
