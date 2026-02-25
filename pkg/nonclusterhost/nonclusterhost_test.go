// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"

	"github.com/projectcalico/calico/pkg/nonclusterhost"
)

var _ = Describe("NonClusterHost Custom Resource Tests", func() {
	var (
		fakeDynamicClient *fake.FakeDynamicClient
	)

	BeforeEach(func() {
		gvrListKind := map[schema.GroupVersionResource]string{
			nonclusterhost.NonClusterHostGVR: "NonClusterHostList",
		}

		scheme := runtime.NewScheme()
		scheme.AddKnownTypes(nonclusterhost.NonClusterHostGVR.GroupVersion(), &unstructured.Unstructured{})
		fakeDynamicClient = fake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrListKind)
		Expect(fakeDynamicClient).NotTo(BeNil())
	})

	Context("Read NonClusterHost resource", func() {
		It("should extract fieldName from NonClusterHost custom resource", func() {
			obj := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "operator.tigera.io/v1",
					"kind":       "NonClusterHost",
					"metadata": map[string]any{
						"name": "tigera-secure",
					},
					"spec": map[string]any{
						"some-field": "some-value",
					},
				},
			}
			nch, err := fakeDynamicClient.Resource(nonclusterhost.NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(nch).NotTo(BeNil())

			Expect(nch.GetName()).To(Equal("tigera-secure"))
			val, err := nonclusterhost.ExtractFromNonClusterHostSpec(nch, "some-field", nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(val).To(Equal("some-value"))
		})

		It("should return error when object is nil", func() {
			val, err := nonclusterhost.ExtractFromNonClusterHostSpec(nil, "some-field", nil)
			Expect(err).To(HaveOccurred())
			Expect(val).To(BeEmpty())
		})

		It("should return error when spec is missing from NonClusterHost custom resource", func() {
			obj := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "operator.tigera.io/v1",
					"kind":       "NonClusterHost",
					"metadata": map[string]any{
						"name": "tigera-secure",
					},
				},
			}
			nch, err := fakeDynamicClient.Resource(nonclusterhost.NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(nch).NotTo(BeNil())

			val, err := nonclusterhost.ExtractFromNonClusterHostSpec(nch, "some-field", nil)
			Expect(err).To(HaveOccurred())
			Expect(val).To(BeEmpty())
		})

		It("should return error when field is missing from NonClusterHost custom resource", func() {
			obj := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "operator.tigera.io/v1",
					"kind":       "NonClusterHost",
					"metadata": map[string]any{
						"name": "tigera-secure",
					},
					"spec": map[string]any{
						"invalid-field": "https://5.6.7.8:9012",
					},
				},
			}
			nch, err := fakeDynamicClient.Resource(nonclusterhost.NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(nch).NotTo(BeNil())

			val, err := nonclusterhost.ExtractFromNonClusterHostSpec(nch, "some-field", nil)
			Expect(err).To(HaveOccurred())
			Expect(val).To(BeEmpty())
		})

		It("should return error when validation failed", func() {
			obj := &unstructured.Unstructured{
				Object: map[string]any{
					"apiVersion": "operator.tigera.io/v1",
					"kind":       "NonClusterHost",
					"metadata": map[string]any{
						"name": "tigera-secure",
					},
					"spec": map[string]any{
						"some-field": "some-value",
					},
				},
			}
			nch, err := fakeDynamicClient.Resource(nonclusterhost.NonClusterHostGVR).Create(context.TODO(), obj, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(nch).NotTo(BeNil())

			Expect(nch.GetName()).To(Equal("tigera-secure"))
			validator := func(endpoint string) error {
				return errors.New("validation failed")
			}
			val, err := nonclusterhost.ExtractFromNonClusterHostSpec(nch, "some-field", validator)
			Expect(err).To(HaveOccurred())
			Expect(val).To(BeEmpty())
		})
	})
})
