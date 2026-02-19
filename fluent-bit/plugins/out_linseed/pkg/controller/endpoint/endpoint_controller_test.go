// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
package endpoint

import (
	"context"
	_ "embed"
	"os"
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/dynamic/fake"

	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/config"
)

var (
	//go:embed testdata/kubeconfig
	validKubeconfig string
)

var _ = Describe("Linseed out plugin endpoint controller tests", func() {
	var (
		f                 *os.File
		pluginConfigKeyFn config.PluginConfigKeyFunc
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

		stopCh = make(chan struct{})
	})

	AfterEach(func() {
		close(stopCh)
		_ = os.Remove(f.Name())
	})

	Context("Endpoint tests", func() {
		It("should use endpoint from config if not empty", func() {
			_, err := f.WriteString(validKubeconfig)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())
			err = os.Setenv("ENDPOINT", "https://1.2.3.4:5678")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.NewConfig(nil, pluginConfigKeyFn)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Endpoint).To(Equal("https://1.2.3.4:5678"))

			ec, err := NewController(cfg)
			Expect(err).NotTo(HaveOccurred())

			err = ec.Run(stopCh)
			Expect(err).NotTo(HaveOccurred())
			Expect(ec.Endpoint()).To(Equal("https://1.2.3.4:5678"))
		})

		It("should update endpoint when an update event is received", func() {
			_, err := f.WriteString(validKubeconfig)
			_ = f.Close()
			Expect(err).NotTo(HaveOccurred())

			err = os.Setenv("KUBECONFIG", f.Name())
			Expect(err).NotTo(HaveOccurred())
			err = os.Setenv("ENDPOINT", "")
			Expect(err).NotTo(HaveOccurred())

			cfg, err := config.NewConfig(nil, pluginConfigKeyFn)
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg.Endpoint).To(BeEmpty())

			ec, err := NewController(cfg)
			Expect(err).NotTo(HaveOccurred())

			gvr := schema.GroupVersionResource{
				Group:    "operator.tigera.io",
				Version:  "v1",
				Resource: "nonclusterhosts",
			}
			gvrListKind := map[schema.GroupVersionResource]string{
				gvr: "NonClusterHostList",
			}

			scheme := runtime.NewScheme()
			scheme.AddKnownTypes(gvr.GroupVersion())
			ec.dynamicClient = fake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrListKind)
			Expect(ec.dynamicClient).NotTo(BeNil())
			ec.dynamicFactory = dynamicinformer.NewDynamicSharedInformerFactory(ec.dynamicClient, 0)
			Expect(ec.dynamicFactory).NotTo(BeNil())

			obj := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "operator.tigera.io/v1",
					"kind":       "NonClusterHost",
					"metadata": map[string]interface{}{
						"name": "tigera-secure",
					},
					"spec": map[string]interface{}{
						"endpoint": "https://5.6.7.8:9012",
					},
				},
			}
			ctx := context.Background()
			_, err = ec.dynamicClient.Resource(gvr).Create(ctx, obj, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			err = ec.Run(stopCh)
			Expect(err).NotTo(HaveOccurred())
			Expect(ec.Endpoint()).To(Equal("https://5.6.7.8:9012"))

			obj2 := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "operator.tigera.io/v1",
					"kind":       "NonClusterHost",
					"metadata": map[string]interface{}{
						"name": "tigera-secure",
					},
					"spec": map[string]interface{}{
						"endpoint": "https://3.4.5.6:7890",
					},
				},
			}
			_, err = ec.dynamicClient.Resource(gvr).Update(ctx, obj2, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() string {
				return ec.Endpoint()
			}).Should(Equal("https://3.4.5.6:7890"))
		})
	})
})
