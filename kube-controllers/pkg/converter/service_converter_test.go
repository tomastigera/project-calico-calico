// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package converter_test

import (
	"math/rand"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
)

var _ = Describe("Service/Endpoint to NetworkSet conversion tests", func() {

	serviceConverter := converter.NewServiceConverter()

	It("should parse a basic Service", func() {
		service := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
				Labels: map[string]string{
					"foo.org/bar": "baz",
					"champions":   "juventus",
				},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					corev1.ServicePort{Protocol: "TCP", TargetPort: intstr.FromInt(80)},
				},
			},
		}

		ns, err := serviceConverter.Convert(&service)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert networkset name.
		By("returning a networkset with expected name", func() {
			Expect(ns.(api.NetworkSet).Name).To(Equal(converter.NetworkSetNamePrefix + "testPolicy"))
		})

		// Assert networkset namespace
		By("returning a networkset with expected namespace", func() {
			Expect(ns.(api.NetworkSet).Namespace).To(Equal("default"))
		})

		annotations := ns.(api.NetworkSet).Annotations
		By("returning a networkset with correct annotations", func() {
			Expect(annotations[converter.NsServiceNameAnnotation]).To(Equal("testPolicy"))
			Expect(annotations[converter.NsPortsAnnotation]).To(Equal("80"))
			Expect(annotations[converter.NsProtocolsAnnotation]).To(Equal("TCP"))
		})

		labels := ns.(api.NetworkSet).Labels
		By("returning a networkset with the correct labels", func() {
			Expect(labels["foo.org/bar"]).To(Equal("baz"))
			Expect(labels["champions"]).To(Equal("juventus"))
			Expect(labels[converter.NsServiceNameLabel]).To(Equal("testPolicy"))
		})
	})

	It("should parse a Service with multiple ports", func() {
		service := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					corev1.ServicePort{Protocol: "TCP", TargetPort: intstr.FromInt(443)},
					corev1.ServicePort{Protocol: "TCP", TargetPort: intstr.FromInt(80)},
					corev1.ServicePort{Protocol: "UDP", TargetPort: intstr.FromInt(123)},
					corev1.ServicePort{Protocol: "TCP", TargetPort: intstr.FromInt(9000)},
				},
			},
		}

		ns, err := serviceConverter.Convert(&service)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert networkset name.
		By("returning a networkset with expected name", func() {
			Expect(ns.(api.NetworkSet).Name).To(Equal(converter.NetworkSetNamePrefix + "testPolicy"))
		})

		// Assert networkset namespace
		By("returning a networkset with expected namespace", func() {
			Expect(ns.(api.NetworkSet).Namespace).To(Equal("default"))
		})

		annotations := ns.(api.NetworkSet).Annotations
		By("returning a networkset with correct annotations", func() {
			Expect(annotations[converter.NsServiceNameAnnotation]).To(Equal("testPolicy"))
			Expect(annotations[converter.NsPortsAnnotation]).To(Equal("80,123,443,9000"))
			Expect(annotations[converter.NsProtocolsAnnotation]).To(Equal("TCP,UDP"))
		})

		labels := ns.(api.NetworkSet).Labels
		By("returning a networkset with empty labels", func() {
			Expect(len(labels)).To(Equal(1))
			Expect(labels[converter.NsServiceNameLabel]).To(Equal("testPolicy"))
		})
	})

	It("should parse a Service with no ports/protocols", func() {
		service := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
			},
		}

		ns, err := serviceConverter.Convert(&service)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert networkset name.
		By("returning a networkset with expected name", func() {
			Expect(ns.(api.NetworkSet).Name).To(Equal(converter.NetworkSetNamePrefix + "testPolicy"))
		})

		// Assert networkset namespace
		By("returning a networkset with expected namespace", func() {
			Expect(ns.(api.NetworkSet).Namespace).To(Equal("default"))
		})

		annotations := ns.(api.NetworkSet).Annotations
		By("returning a networkset with correct annotations", func() {
			Expect(annotations[converter.NsServiceNameAnnotation]).To(Equal("testPolicy"))
			Expect(annotations[converter.NsPortsAnnotation]).To(BeZero())
			Expect(annotations[converter.NsProtocolsAnnotation]).To(BeZero())
		})

		labels := ns.(api.NetworkSet).Labels
		By("returning a networkset with empty labels", func() {
			Expect(len(labels)).To(Equal(1))
			Expect(labels[converter.NsServiceNameLabel]).To(Equal("testPolicy"))
		})
	})

	It("should ignore a federated service with ", func() {
		service := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
				Annotations: map[string]string{
					converter.ExcludeFederetedServiceAnnotation: "",
				},
			},
		}

		_, err := serviceConverter.Convert(&service)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should ignore a service with proper annotation", func() {
		service := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testPolicy",
				Namespace: "default",
				Annotations: map[string]string{
					converter.ExcludeServiceAnnotation: "xyz",
				},
			},
		}

		_, err := serviceConverter.Convert(&service)
		By("generating a conversion error", func() {
			Expect(err).To(HaveOccurred())
		})
	})

	It("should parse a service with name longer than max", func() {
		var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
		length := k8svalidation.DNS1123SubdomainMaxLength
		b := make([]rune, length)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		longName := string(b)

		service := corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      longName,
				Namespace: "default",
			},
		}

		ns, err := serviceConverter.Convert(&service)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		By("returning a networkset with expected name length", func() {
			Expect(len(ns.(api.NetworkSet).Name)).To(Equal(len(converter.NetworkSetNamePrefix) + converter.HashedNameLength))
		})

		ns2, err := serviceConverter.Convert(&service)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		//Hashing should always return same output for same input
		By("returning a networkset with expected name", func() {
			Expect(ns2.(api.NetworkSet).Name).To(Equal(ns.(api.NetworkSet).Name))
		})

	})

	endpointConverter := converter.NewEndpointConverter()

	It("should parse a basic Endpoints", func() {
		endpoints := corev1.Endpoints{ //nolint:staticcheck
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testEndpoint",
				Namespace: "policy-demo",
				Labels: map[string]string{
					"foo.org/bar": "baz",
					"champions":   "juventus",
				},
				Annotations: map[string]string{
					"country": "italy",
				},
			},
			Subsets: []corev1.EndpointSubset{ //nolint:staticcheck
				{
					Addresses: []corev1.EndpointAddress{ //nolint:staticcheck
						{
							IP: "1.1.1.1",
						},
						{
							IP: "2.2.2.2",
						},
					},
					NotReadyAddresses: []corev1.EndpointAddress{ //nolint:staticcheck
						{
							IP: "3.3.3.3",
						},
					},
				},
			},
		}

		ns, err := endpointConverter.Convert(&endpoints)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert networkset name.
		By("returning a networkset with expected name", func() {
			Expect(ns.(api.NetworkSet).Name).To(Equal(converter.NetworkSetNamePrefix + "testEndpoint"))
		})

		// Assert networkset namespace
		By("returning a networkset with expected namespace", func() {
			Expect(ns.(api.NetworkSet).Namespace).To(Equal("policy-demo"))
		})

		//Labels are not copied over from Endpoints to NetworkSet
		//If this changes, both converter k8sEndpointToNetworkSet and controller onEndpointsUpdate need to be updated
		By("returning a networkset with expected labels", func() {
			Expect(len(ns.(api.NetworkSet).Labels)).To(Equal(0))
		})

		//Annotations are not copied over from Endpoints to NetworkSet
		//If this changes, both converter k8sEndpointToNetworkSet and controller onEndpointsUpdate need to be updated
		By("returning a networkset with expected annotations", func() {
			Expect(len(ns.(api.NetworkSet).Annotations)).To(Equal(0))
		})

		nets := ns.(api.NetworkSet).Spec.Nets
		By("returning a networkset with the nets", func() {
			Expect(nets[0]).To(Equal("1.1.1.1"))
			Expect(nets[1]).To(Equal("2.2.2.2"))
			Expect(nets[2]).To(Equal("3.3.3.3"))
		})
	})

	It("should parse a basic Endpoints with multiple addresses", func() {
		endpoints := corev1.Endpoints{ //nolint:staticcheck
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testEndpoint",
				Namespace: "policy-demo",
			},
			Subsets: []corev1.EndpointSubset{ //nolint:staticcheck
				{
					Addresses: []corev1.EndpointAddress{ //nolint:staticcheck
						{
							IP: "1.1.1.1",
						},
						{
							IP: "2.2.2.2",
						},
					},
					NotReadyAddresses: []corev1.EndpointAddress{ //nolint:staticcheck
						{
							IP: "3.3.3.3",
						},
					},
				},
				{
					Addresses: []corev1.EndpointAddress{ //nolint:staticcheck
						{
							IP: "10.10.10.10",
						},
					},
				},
				{
					NotReadyAddresses: []corev1.EndpointAddress{ //nolint:staticcheck
						{
							IP: "20.20.20.20",
						},
					},
				},
			},
		}

		ns, err := endpointConverter.Convert(&endpoints)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert networkset name.
		By("returning a networkset with expected name", func() {
			Expect(ns.(api.NetworkSet).Name).To(Equal(converter.NetworkSetNamePrefix + "testEndpoint"))
		})

		// Assert networkset namespace
		By("returning a networkset with expected namespace", func() {
			Expect(ns.(api.NetworkSet).Namespace).To(Equal("policy-demo"))
		})

		nets := ns.(api.NetworkSet).Spec.Nets
		By("returning a networkset with the nets", func() {
			Expect(nets[0]).To(Equal("1.1.1.1"))
			Expect(nets[1]).To(Equal("10.10.10.10"))
			Expect(nets[2]).To(Equal("2.2.2.2"))
			Expect(nets[3]).To(Equal("20.20.20.20"))
			Expect(nets[4]).To(Equal("3.3.3.3"))
		})
	})

	It("should parse an Endpoints with no addresses", func() {
		endpoints := corev1.Endpoints{ //nolint:staticcheck
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testEndpoint",
				Namespace: "policy-demo",
			},
		}

		ns, err := endpointConverter.Convert(&endpoints)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert networkset name.
		By("returning a networkset with expected name", func() {
			Expect(ns.(api.NetworkSet).Name).To(Equal(converter.NetworkSetNamePrefix + "testEndpoint"))
		})

		// Assert networkset namespace
		By("returning a networkset with expected namespace", func() {
			Expect(ns.(api.NetworkSet).Namespace).To(Equal("policy-demo"))
		})

		nets := ns.(api.NetworkSet).Spec.Nets
		By("returning a networkset with the nets", func() {
			Expect(len(nets)).To(BeZero())
		})
	})

	It("should parse an Endpoints with no addresses just ports", func() {
		endpoints := corev1.Endpoints{ //nolint:staticcheck
			ObjectMeta: metav1.ObjectMeta{
				Name:      "testEndpoint",
				Namespace: "policy-demo",
			},
			Subsets: []corev1.EndpointSubset{ //nolint:staticcheck
				{
					Ports: []corev1.EndpointPort{ //nolint:staticcheck
						{
							Name:     "http",
							Protocol: "TCP",
							Port:     80,
						},
					},
				},
			},
		}

		ns, err := endpointConverter.Convert(&endpoints)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		// Assert networkset name.
		By("returning a networkset with expected name", func() {
			Expect(ns.(api.NetworkSet).Name).To(Equal(converter.NetworkSetNamePrefix + "testEndpoint"))
		})

		// Assert networkset namespace
		By("returning a networkset with expected namespace", func() {
			Expect(ns.(api.NetworkSet).Namespace).To(Equal("policy-demo"))
		})

		nets := ns.(api.NetworkSet).Spec.Nets
		By("returning a networkset with the nets", func() {
			Expect(len(nets)).To(BeZero())
		})
	})
})
