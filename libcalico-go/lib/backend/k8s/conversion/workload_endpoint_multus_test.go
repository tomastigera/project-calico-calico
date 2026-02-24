// Copyright (c) 2016-2020 Tigera, Inc. All rights reserved.

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

package conversion

import (
	"encoding/json"
	"net"

	nettypes "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8sapi "k8s.io/api/core/v1"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("multusWorkloadEndpointConverter", func() {
	Describe("InterfacesForPod", func() {
		Context("without the k8s.v1.cni.cncf.io/networks-status annotation", func() {
			Context("without the k8s.v1.cni.cncf.io/networks annotation", func() {
				When("there are no IPs in the PodStatus", func() {
					It("it returns the default interface without IPNets set", func() {
						pod := &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
							},
						}

						podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
						Expect(err).ShouldNot(HaveOccurred())
						Expect(podInterfaces).Should(Equal([]*PodInterface{
							{
								IsDefault:          true,
								NetworkName:        "k8s-pod-network",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "eth0",
								HostSideIfaceName:  "cali7f94ce7c295",
								InsidePodGW:        net.IPv4(169, 254, 1, 1),
							},
						}))
					})
				})
				When("there are IPs in the status", func() {
					It("it returns only the default interface with IPNets set", func() {
						pod := &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
							},
							Status: kapiv1.PodStatus{
								PodIP: "192.168.0.1",
							},
						}

						podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
						Expect(err).ShouldNot(HaveOccurred())
						Expect(podInterfaces).Should(Equal([]*PodInterface{
							{
								IsDefault:          true,
								NetworkName:        "k8s-pod-network",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "eth0",
								HostSideIfaceName:  "cali7f94ce7c295",
								InsidePodGW:        net.IPv4(169, 254, 1, 1),
								IPNets: []*cnet.IPNet{{
									IPNet: net.IPNet{
										IP:   []byte{192, 168, 0, 1},
										Mask: net.IPMask("\xff\xff\xff\xff"),
									},
								}},
							},
						}))
					})
				})
			})
			Context("with the k8s.v1.cni.cncf.io/networks annotation present", func() {
				When("none of the networks have explicit interface names", func() {
					DescribeTable("uses the default naming scheme for the inside pod interfaces", func(pod *kapiv1.Pod) {
						podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
						Expect(err).ShouldNot(HaveOccurred())
						Expect(podInterfaces).Should(Equal([]*PodInterface{
							{
								IsDefault:          true,
								NetworkName:        "k8s-pod-network",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "eth0",
								HostSideIfaceName:  "cali7f94ce7c295",
								InsidePodGW:        net.IPv4(169, 254, 1, 1),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico1",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "net1",
								HostSideIfaceName:  "calim1P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 2),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico2",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "net2",
								HostSideIfaceName:  "calim2P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 3),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico3",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "net3",
								HostSideIfaceName:  "calim3P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 4),
							},
						}))
					},
						Entry("using common delimited annotation format", &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: "calico1,calico2,calico3",
								},
							},
						}),
						Entry("using json list annotation format", &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: mustMarshal([]*nettypes.NetworkSelectionElement{
										{Name: "calico1"},
										{Name: "calico2"},
										{Name: "calico3"},
									}),
								},
							},
						}),
					)
				})
				When("all of the networks have explicit interface names", func() {
					DescribeTable("uses the explicit interface names for the inside pod interfaces", func(pod *kapiv1.Pod) {
						podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
						Expect(err).ShouldNot(HaveOccurred())
						Expect(podInterfaces).Should(Equal([]*PodInterface{
							{
								IsDefault:          true,
								NetworkName:        "k8s-pod-network",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "eth0",
								HostSideIfaceName:  "cali7f94ce7c295",
								InsidePodGW:        net.IPv4(169, 254, 1, 1),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico1",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "cali1",
								HostSideIfaceName:  "calim1P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 2),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico2",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "cali2",
								HostSideIfaceName:  "calim2P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 3),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico3",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "cali3",
								HostSideIfaceName:  "calim3P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 4),
							},
						}))
					},
						Entry("using common delimited annotation format", &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: "calico1@cali1,calico2@cali2,calico3@cali3",
								},
							},
						}),
						Entry("using json list annotation format", &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: mustMarshal([]*nettypes.NetworkSelectionElement{
										{Name: "calico1", InterfaceRequest: "cali1"},
										{Name: "calico2", InterfaceRequest: "cali2"},
										{Name: "calico3", InterfaceRequest: "cali3"},
									}),
								},
							},
						}),
					)
				})
				When("when the middle few networks have explicit names", func() {
					DescribeTable("uses the default naming scheme for the inside pod interfaces where appropriate", func(pod *kapiv1.Pod) {
						podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
						Expect(err).ShouldNot(HaveOccurred())
						Expect(podInterfaces).Should(Equal([]*PodInterface{
							{
								IsDefault:          true,
								NetworkName:        "k8s-pod-network",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "eth0",
								HostSideIfaceName:  "cali7f94ce7c295",
								InsidePodGW:        net.IPv4(169, 254, 1, 1),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico1",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "net1",
								HostSideIfaceName:  "calim1P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 2),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico2",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "cali2",
								HostSideIfaceName:  "calim2P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 3),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico3",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "net3",
								HostSideIfaceName:  "calim3P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 4),
							},
						}))
					},
						Entry("using common delimited annotation format", &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: "calico1,calico2@cali2,calico3",
								},
							},
						}),
						Entry("using json list annotation format", &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: mustMarshal([]*nettypes.NetworkSelectionElement{
										{Name: "calico1"},
										{Name: "calico2", InterfaceRequest: "cali2"},
										{Name: "calico3"},
									}),
								},
							},
						}),
					)
				})
				When("a namespace is specified on a network", func() {
					It("uses the default naming scheme for the inside pod interfaces where appropriate", func() {
						pod := &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: "namespace/calico1",
								},
							},
						}

						podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
						Expect(err).ShouldNot(HaveOccurred())
						Expect(podInterfaces).Should(Equal([]*PodInterface{
							{
								IsDefault:          true,
								NetworkName:        "k8s-pod-network",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "eth0",
								HostSideIfaceName:  "cali7f94ce7c295",
								InsidePodGW:        net.IPv4(169, 254, 1, 1),
							},
							{
								IsDefault:          false,
								NetworkName:        "calico1",
								NetworkNamespace:   "namespace",
								InsidePodIfaceName: "net1",
								HostSideIfaceName:  "calim1P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 2),
							},
						}))
					})
				})
				When("the status contains the Pod IP", func() {
					It("populates the IPNets for the default PodInterface", func() {
						pod := &kapiv1.Pod{
							ObjectMeta: metav1.ObjectMeta{
								Name:      "podA",
								Namespace: "default",
								Annotations: map[string]string{
									nettypes.NetworkAttachmentAnnot: "calico",
								},
							},
							Status: kapiv1.PodStatus{
								PodIP: "192.168.0.1",
							},
						}

						podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
						Expect(err).ShouldNot(HaveOccurred())
						Expect(podInterfaces).Should(Equal([]*PodInterface{
							{
								IsDefault:          true,
								NetworkName:        "k8s-pod-network",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "eth0",
								HostSideIfaceName:  "cali7f94ce7c295",
								InsidePodGW:        net.IPv4(169, 254, 1, 1),
								IPNets: []*cnet.IPNet{{
									IPNet: net.IPNet{
										IP:   []byte{192, 168, 0, 1},
										Mask: net.IPMask("\xff\xff\xff\xff"),
									},
								}},
							},
							{
								IsDefault:          false,
								NetworkName:        "calico",
								NetworkNamespace:   "default",
								InsidePodIfaceName: "net1",
								HostSideIfaceName:  "calim1P6KM47BJK",
								InsidePodGW:        net.IPv4(169, 254, 1, 2),
							},
						}))
					})
				})
			})
		})
		Context("with the k8s.v1.cni.cncf.io/network-status annotation", func() {
			It("falls back to the networks annotation if the content of the networks-status annotation is empty", func() {
				pod := &kapiv1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "podA",
						Namespace: "default",
						Annotations: map[string]string{
							nettypes.NetworkAttachmentAnnot: "calico1,calico2",
							nettypes.NetworkStatusAnnot:     "",
						},
					},
					Status: kapiv1.PodStatus{
						PodIP: "192.168.91.113",
					},
				}

				podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(podInterfaces).Should(Equal([]*PodInterface{
					{
						IsDefault:          true,
						NetworkName:        "k8s-pod-network",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "eth0",
						HostSideIfaceName:  "cali7f94ce7c295",
						InsidePodGW:        net.IPv4(169, 254, 1, 1),
						IPNets: []*cnet.IPNet{{
							IPNet: net.IPNet{
								IP:   []byte{192, 168, 91, 113},
								Mask: net.IPMask("\xff\xff\xff\xff"),
							},
						}},
					},
					{
						IsDefault:          false,
						NetworkName:        "calico1",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "net1",
						HostSideIfaceName:  "calim1P6KM47BJK",
						InsidePodGW:        net.IPv4(169, 254, 1, 2),
					},
					{
						IsDefault:          false,
						NetworkName:        "calico2",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "net2",
						HostSideIfaceName:  "calim2P6KM47BJK",
						InsidePodGW:        net.IPv4(169, 254, 1, 3),
					},
				}))
			})
			It("falls back to the networks annotation if the content of the networks-status annotation is invalid json", func() {
				pod := &kapiv1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "podA",
						Namespace: "default",
						Annotations: map[string]string{
							nettypes.NetworkAttachmentAnnot: "calico1,calico2",
							nettypes.NetworkStatusAnnot:     "}[{dsfewc",
						},
					},
					Status: kapiv1.PodStatus{
						PodIP: "192.168.91.113",
					},
				}

				podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(podInterfaces).Should(Equal([]*PodInterface{
					{
						IsDefault:          true,
						NetworkName:        "k8s-pod-network",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "eth0",
						HostSideIfaceName:  "cali7f94ce7c295",
						InsidePodGW:        net.IPv4(169, 254, 1, 1),
						IPNets: []*cnet.IPNet{{
							IPNet: net.IPNet{
								IP:   []byte{192, 168, 91, 113},
								Mask: net.IPMask("\xff\xff\xff\xff"),
							},
						}},
					},
					{
						IsDefault:          false,
						NetworkName:        "calico1",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "net1",
						HostSideIfaceName:  "calim1P6KM47BJK",
						InsidePodGW:        net.IPv4(169, 254, 1, 2),
					},
					{
						IsDefault:          false,
						NetworkName:        "calico2",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "net2",
						HostSideIfaceName:  "calim2P6KM47BJK",
						InsidePodGW:        net.IPv4(169, 254, 1, 3),
					},
				}))
			})
			It("populates the PodInterface using k8s.v1.cni.cncf.io/networks-status annotation", func() {
				// The exception to this population is with the default interface, as it gets its IPs from the pod Status
				// IP annotations
				pod := &kapiv1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "podA",
						Namespace: "default",
						Annotations: map[string]string{
							nettypes.NetworkAttachmentAnnot: "calico1,calico2",
							nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
								{
									Name:      "calico-default-network",
									Interface: "ens4",
									IPs:       []string{"192.168.91.113"},
									Mac:       "9e:e7:7e:9d:8f:e0",
								},
								{
									Name:      "calico1",
									Interface: "net1",
									IPs:       []string{"192.168.91.114"},
									Mac:       "62:45:f5:10:97:c1",
								},
								{
									Name:      "calico2",
									Interface: "net2",
									IPs:       []string{"192.168.91.115"},
									Mac:       "62:76:f5:90:27:c1",
								},
							}),
						},
					},
					Status: kapiv1.PodStatus{
						PodIP: "192.168.91.113",
					},
				}
				podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
				Expect(err).ShouldNot(HaveOccurred())
				Expect(podInterfaces).Should(Equal([]*PodInterface{
					{
						IsDefault:          true,
						NetworkName:        "calico-default-network",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "ens4",
						HostSideIfaceName:  "cali7f94ce7c295",
						InsidePodGW:        net.IPv4(169, 254, 1, 1),
						IPNets: []*cnet.IPNet{{
							IPNet: net.IPNet{
								IP:   []byte{192, 168, 91, 113},
								Mask: net.IPMask("\xff\xff\xff\xff"),
							},
						}},
					},
					{
						IsDefault:          false,
						NetworkName:        "calico1",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "net1",
						HostSideIfaceName:  "calim1P6KM47BJK",
						InsidePodGW:        net.IPv4(169, 254, 1, 2),
						IPNets: []*cnet.IPNet{{
							IPNet: net.IPNet{
								IP:   []byte{192, 168, 91, 114},
								Mask: net.IPMask("\xff\xff\xff\xff"),
							},
						}},
					},
					{
						IsDefault:          false,
						NetworkName:        "calico2",
						NetworkNamespace:   "default",
						InsidePodIfaceName: "net2",
						HostSideIfaceName:  "calim2P6KM47BJK",
						InsidePodGW:        net.IPv4(169, 254, 1, 3),
						IPNets: []*cnet.IPNet{{
							IPNet: net.IPNet{
								IP:   []byte{192, 168, 91, 115},
								Mask: net.IPMask("\xff\xff\xff\xff"),
							},
						}},
					},
				}))
			})
			When("the Pod Status is available", func() {
				It("uses the Status to get the IPs for the default PodInterface", func() {
					pod := &kapiv1.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "podA",
							Namespace: "default",
							Annotations: map[string]string{
								nettypes.NetworkAttachmentAnnot: "calico",
								nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
									{
										Name:      "calico-default-network",
										Interface: "ens4",
										IPs:       []string{"192.168.91.111"},
										Mac:       "9e:e7:7e:9d:8f:e0",
									},
								}),
							},
						},
						Status: kapiv1.PodStatus{
							PodIP: "192.168.91.113",
						},
					}
					podInterfaces, err := multusWorkloadEndpointConverter{}.InterfacesForPod(pod)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(podInterfaces).Should(Equal([]*PodInterface{
						{
							IsDefault:          true,
							NetworkName:        "calico-default-network",
							NetworkNamespace:   "default",
							InsidePodIfaceName: "ens4",
							HostSideIfaceName:  "cali7f94ce7c295",
							InsidePodGW:        net.IPv4(169, 254, 1, 1),
							IPNets: []*cnet.IPNet{{
								IPNet: net.IPNet{
									IP:   []byte{192, 168, 91, 113},
									Mask: net.IPMask("\xff\xff\xff\xff"),
								},
							}},
						},
					}))
				})
			})
		})
	})
	Describe("PodToWorkloadEndpoints", func() {
		Context("no CNCF annotations on Pod", func() {
			It("returns a single WorkloadEndpoint for the default interface", func() {
				kvps, err := multusWorkloadEndpointConverter{}.PodToWorkloadEndpoints(&k8sapi.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "simplePod",
						Namespace: "testNamespace",
					},
					Spec: k8sapi.PodSpec{
						NodeName: "test-node",
					},
				})
				Expect(err).ShouldNot(HaveOccurred())

				var weps []*internalapi.WorkloadEndpoint
				for _, kvp := range kvps {
					weps = append(weps, kvp.Value.(*internalapi.WorkloadEndpoint))
				}

				Expect(weps).Should(Equal([]*internalapi.WorkloadEndpoint{{
					TypeMeta: metav1.TypeMeta{
						Kind:       internalapi.KindWorkloadEndpoint,
						APIVersion: apiv3.GroupVersionCurrent,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test--node-k8s-simplePod-eth0",
						Namespace: "testNamespace",
						Labels: map[string]string{
							apiv3.LabelNamespace:        "testNamespace",
							apiv3.LabelOrchestrator:     "k8s",
							apiv3.LabelNetwork:          "k8s-pod-network",
							apiv3.LabelNetworkNamespace: "testNamespace",
							apiv3.LabelNetworkInterface: "eth0",
						},
					},
					Spec: internalapi.WorkloadEndpointSpec{
						Orchestrator:  "k8s",
						Node:          "test-node",
						Pod:           "simplePod",
						Endpoint:      "eth0",
						Profiles:      []string{"kns.testNamespace"},
						IPNetworks:    []string{},
						InterfaceName: "caliedff4356bd6",
					},
				}}))
			})
		})
		Context("network-status annotation on Pod", func() {
			When("the pods default calico interface is not eth0", func() {
				It("the default WorkloadEndpoint returned has the non eth0 interface", func() {
					kvps, err := multusWorkloadEndpointConverter{}.PodToWorkloadEndpoints(&k8sapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "simplePod",
							Namespace: "testNamespace",
							Annotations: map[string]string{
								nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
									{
										Name:      "calico-default-network",
										Interface: "ens4",
										IPs:       []string{"192.168.91.113"},
										Mac:       "9e:e7:7e:9d:8f:e0",
									},
								}),
							},
						},
						Spec: k8sapi.PodSpec{
							NodeName: "test-node",
						},
						Status: k8sapi.PodStatus{
							PodIP: "192.168.91.113",
						},
					})

					Expect(err).ShouldNot(HaveOccurred())

					var weps []*internalapi.WorkloadEndpoint
					for _, kvp := range kvps {
						weps = append(weps, kvp.Value.(*internalapi.WorkloadEndpoint))
					}

					Expect(weps).Should(Equal([]*internalapi.WorkloadEndpoint{{
						TypeMeta: metav1.TypeMeta{
							Kind:       internalapi.KindWorkloadEndpoint,
							APIVersion: apiv3.GroupVersionCurrent,
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "test--node-k8s-simplePod-ens4",
							Namespace: "testNamespace",
							Labels: map[string]string{
								apiv3.LabelNamespace:        "testNamespace",
								apiv3.LabelOrchestrator:     "k8s",
								apiv3.LabelNetwork:          "calico-default-network",
								apiv3.LabelNetworkNamespace: "testNamespace",
								apiv3.LabelNetworkInterface: "ens4",
							},
							Annotations: map[string]string{
								nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
									{
										Name:      "calico-default-network",
										Interface: "ens4",
										IPs:       []string{"192.168.91.113"},
										Mac:       "9e:e7:7e:9d:8f:e0",
									},
								}),
							},
						},
						Spec: internalapi.WorkloadEndpointSpec{
							Orchestrator:  "k8s",
							Node:          "test-node",
							Pod:           "simplePod",
							Endpoint:      "ens4",
							Profiles:      []string{"kns.testNamespace"},
							IPNetworks:    []string{"192.168.91.113/32"},
							InterfaceName: "caliedff4356bd6",
						},
					}}))
				})
			})
			When("when the pod has multiple interfaces", func() {
				It("returns the correct Workload endpoint", func() {
					kvps, err := multusWorkloadEndpointConverter{}.PodToWorkloadEndpoints(&k8sapi.Pod{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "simplePod",
							Namespace: "testNamespace",
							Annotations: map[string]string{
								nettypes.NetworkAttachmentAnnot: "calico1,calico2",
								nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
									{
										Name:      "calico-default-network",
										Interface: "ens4",
										IPs:       []string{"192.168.91.113"},
										Mac:       "9e:e7:7e:9d:8f:e0",
									},
									{
										Name:      "calico1",
										Interface: "net1",
										IPs:       []string{"192.168.91.114"},
										Mac:       "62:45:f5:10:97:c1",
									},
									{
										Name:      "calico2",
										Interface: "net2",
										IPs:       []string{"192.168.91.115"},
										Mac:       "62:76:f5:90:27:c1",
									},
								}),
							},
							Labels: map[string]string{
								"pod": "simplePod",
							},
						},
						Spec: k8sapi.PodSpec{
							NodeName: "test-node",
						},
						Status: k8sapi.PodStatus{
							PodIP: "192.168.91.113",
						},
					})

					Expect(err).ShouldNot(HaveOccurred())

					var weps []*internalapi.WorkloadEndpoint
					for _, kvp := range kvps {
						weps = append(weps, kvp.Value.(*internalapi.WorkloadEndpoint))
					}

					Expect(weps).Should(Equal([]*internalapi.WorkloadEndpoint{
						{
							TypeMeta: metav1.TypeMeta{
								Kind:       internalapi.KindWorkloadEndpoint,
								APIVersion: apiv3.GroupVersionCurrent,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test--node-k8s-simplePod-ens4",
								Namespace: "testNamespace",
								Labels: map[string]string{
									apiv3.LabelNamespace:        "testNamespace",
									apiv3.LabelOrchestrator:     "k8s",
									apiv3.LabelNetwork:          "calico-default-network",
									apiv3.LabelNetworkNamespace: "testNamespace",
									apiv3.LabelNetworkInterface: "ens4",
									"pod":                       "simplePod",
								},
								Annotations: map[string]string{
									nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
										{
											Name:      "calico-default-network",
											Interface: "ens4",
											IPs:       []string{"192.168.91.113"},
											Mac:       "9e:e7:7e:9d:8f:e0",
										},
										{
											Name:      "calico1",
											Interface: "net1",
											IPs:       []string{"192.168.91.114"},
											Mac:       "62:45:f5:10:97:c1",
										},
										{
											Name:      "calico2",
											Interface: "net2",
											IPs:       []string{"192.168.91.115"},
											Mac:       "62:76:f5:90:27:c1",
										},
									}),
								},
							},
							Spec: internalapi.WorkloadEndpointSpec{
								Orchestrator:  "k8s",
								Node:          "test-node",
								Pod:           "simplePod",
								Endpoint:      "ens4",
								Profiles:      []string{"kns.testNamespace"},
								IPNetworks:    []string{"192.168.91.113/32"},
								InterfaceName: "caliedff4356bd6",
							},
						},
						{
							TypeMeta: metav1.TypeMeta{
								Kind:       internalapi.KindWorkloadEndpoint,
								APIVersion: apiv3.GroupVersionCurrent,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test--node-k8s-simplePod-net1",
								Namespace: "testNamespace",
								Labels: map[string]string{
									apiv3.LabelNamespace:        "testNamespace",
									apiv3.LabelOrchestrator:     "k8s",
									apiv3.LabelNetwork:          "calico1",
									apiv3.LabelNetworkNamespace: "testNamespace",
									apiv3.LabelNetworkInterface: "net1",
									"pod":                       "simplePod",
								},
								Annotations: map[string]string{
									nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
										{
											Name:      "calico-default-network",
											Interface: "ens4",
											IPs:       []string{"192.168.91.113"},
											Mac:       "9e:e7:7e:9d:8f:e0",
										},
										{
											Name:      "calico1",
											Interface: "net1",
											IPs:       []string{"192.168.91.114"},
											Mac:       "62:45:f5:10:97:c1",
										},
										{
											Name:      "calico2",
											Interface: "net2",
											IPs:       []string{"192.168.91.115"},
											Mac:       "62:76:f5:90:27:c1",
										},
									}),
								},
							},
							Spec: internalapi.WorkloadEndpointSpec{
								Orchestrator:  "k8s",
								Node:          "test-node",
								Pod:           "simplePod",
								Endpoint:      "net1",
								Profiles:      []string{"kns.testNamespace"},
								IPNetworks:    []string{"192.168.91.114/32"},
								InterfaceName: "calim15X7UGVV5N",
							},
						},
						{
							TypeMeta: metav1.TypeMeta{
								Kind:       internalapi.KindWorkloadEndpoint,
								APIVersion: apiv3.GroupVersionCurrent,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name:      "test--node-k8s-simplePod-net2",
								Namespace: "testNamespace",
								Labels: map[string]string{
									apiv3.LabelNamespace:        "testNamespace",
									apiv3.LabelOrchestrator:     "k8s",
									apiv3.LabelNetwork:          "calico2",
									apiv3.LabelNetworkNamespace: "testNamespace",
									apiv3.LabelNetworkInterface: "net2",
									"pod":                       "simplePod",
								},
								Annotations: map[string]string{
									nettypes.NetworkStatusAnnot: mustMarshal([]*nettypes.NetworkStatus{
										{
											Name:      "calico-default-network",
											Interface: "ens4",
											IPs:       []string{"192.168.91.113"},
											Mac:       "9e:e7:7e:9d:8f:e0",
										},
										{
											Name:      "calico1",
											Interface: "net1",
											IPs:       []string{"192.168.91.114"},
											Mac:       "62:45:f5:10:97:c1",
										},
										{
											Name:      "calico2",
											Interface: "net2",
											IPs:       []string{"192.168.91.115"},
											Mac:       "62:76:f5:90:27:c1",
										},
									}),
								},
							},
							Spec: internalapi.WorkloadEndpointSpec{
								Orchestrator:  "k8s",
								Node:          "test-node",
								Pod:           "simplePod",
								Endpoint:      "net2",
								Profiles:      []string{"kns.testNamespace"},
								IPNetworks:    []string{"192.168.91.115/32"},
								InterfaceName: "calim25X7UGVV5N",
							},
						},
					}))
				})
			})
		})
	})
})

func mustMarshal(v any) string {
	jsonStr, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(jsonStr)
}
