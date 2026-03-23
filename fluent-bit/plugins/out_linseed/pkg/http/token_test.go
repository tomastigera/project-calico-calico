// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
package http

import (
	"context"
	_ "embed"
	"os"
	"time"
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/config"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

var (
	//go:embed testdata/kubeconfig
	validKubeconfig string
)

var _ = Describe("Linseed out plugin token tests", func() {
	var (
		f                 *os.File
		pluginConfigKeyFn config.PluginConfigKeyFunc
		serviceAccount    *corev1.ServiceAccount
		stopCh            chan struct{}
	)

	BeforeEach(func() {
		var err error
		f, err = os.CreateTemp("", "kubeconfig")
		Expect(err).NotTo(HaveOccurred())

		pluginConfigKeyFn = func(plugin unsafe.Pointer, key string) string {
			if key == "tls.verify" {
				return "true"
			}
			return ""
		}

		serviceAccount = &corev1.ServiceAccount{
			TypeMeta: resources.TypeK8sServiceAccounts,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "noncluster-serviceaccount",
				Namespace: "calico-system",
			},
		}

		stopCh = make(chan struct{})
	})

	AfterEach(func() {
		close(stopCh)
		_ = os.Remove(f.Name())
	})

	Context("Token tests", func() {
		It("should fetch token when the current one is expired", func() {
			_, err := f.WriteString(validKubeconfig)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())
			err = os.Setenv("ENDPOINT", "https://1.2.3.4:5678")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.NewConfig(nil, pluginConfigKeyFn)
			Expect(err).NotTo(HaveOccurred())

			tc, err := NewToken(cfg)
			Expect(err).NotTo(HaveOccurred())

			mockClientSet := lmak8s.NewMockClientSet(GinkgoT())
			// returns a fake CoreV1Interface that implements ServiceAccounts(namespace).CreateToken
			mockClientSet.On("CoreV1").Return(&fakeCoreV1{})
			tc.clientset = mockClientSet

			tc.serviceAccountName = serviceAccount.GetName()
			tc.expiration = time.Now().Add(-2 * tokenExpiration) // must be expired
			tc.token = "some-token"

			_, err = tc.Token()
			Expect(err).NotTo(HaveOccurred())
			// createToken from corev1 must be called
			Expect(mockClientSet.AssertCalled(GinkgoT(), "CoreV1")).To(BeTrue())
		})

		It("should reuse the token when it is still valid", func() {
			_, err := f.WriteString(validKubeconfig)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())
			err = os.Setenv("ENDPOINT", "https://1.2.3.4:5678")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.NewConfig(nil, pluginConfigKeyFn)
			Expect(err).NotTo(HaveOccurred())

			tc, err := NewToken(cfg)
			Expect(err).NotTo(HaveOccurred())

			mockClientSet := lmak8s.NewMockClientSet(GinkgoT())
			tc.clientset = mockClientSet

			tc.serviceAccountName = serviceAccount.GetName()
			tc.expiration = time.Now().Add(1 * time.Hour) // must not be expired
			tc.token = "some-token"

			token, err := tc.Token()
			Expect(err).NotTo(HaveOccurred())
			// should not call createToken
			Expect(mockClientSet.AssertNotCalled(GinkgoT(), "CoreV1")).To(BeTrue())
			Expect(token).To(Equal("some-token"))
		})

		It("should return error when the token is invalid", func() {
			_, err := f.WriteString(validKubeconfig)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())
			err = os.Setenv("ENDPOINT", "https://1.2.3.4:5678")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.NewConfig(nil, pluginConfigKeyFn)
			Expect(err).NotTo(HaveOccurred())

			tc, err := NewToken(cfg)
			Expect(err).NotTo(HaveOccurred())

			mockClientSet := lmak8s.NewMockClientSet(GinkgoT())
			fakeCoreV1 := fake.NewClientset().CoreV1()
			_, err = fakeCoreV1.ServiceAccounts("calico-system").Create(context.Background(), serviceAccount, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			// k8s fake corev1 will return an empty jwt token which is invalid
			mockClientSet.On("CoreV1").Return(fakeCoreV1)
			tc.clientset = mockClientSet

			tc.serviceAccountName = serviceAccount.GetName()
			tc.expiration = time.Now().Add(-2 * tokenExpiration) // must be expired
			tc.token = "some-token"

			_, err = tc.Token()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not a compact JWS"))
		})

		It("should return error when missing serviceaccount", func() {
			_, err := f.WriteString(validKubeconfig)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())
			err = os.Setenv("ENDPOINT", "https://1.2.3.4:5678")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.NewConfig(nil, pluginConfigKeyFn)
			Expect(err).NotTo(HaveOccurred())

			tc, err := NewToken(cfg)
			Expect(err).NotTo(HaveOccurred())

			mockClientSet := lmak8s.NewMockClientSet(GinkgoT())
			fakeCoreV1 := fake.NewClientset().CoreV1()
			_, err = fakeCoreV1.ServiceAccounts("calico-system").Create(context.Background(), serviceAccount, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			mockClientSet.On("CoreV1").Return(fakeCoreV1)
			tc.clientset = mockClientSet

			tc.serviceAccountName = "invalid-service-account"
			tc.expiration = time.Now().Add(-2 * tokenExpiration) // must be expired
			tc.token = "some-token"

			_, err = tc.Token()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`"invalid-service-account" not found`))
		})
	})
})
