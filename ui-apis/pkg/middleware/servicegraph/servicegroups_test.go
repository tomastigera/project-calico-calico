// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package servicegraph_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	. "github.com/projectcalico/calico/ui-apis/pkg/middleware/servicegraph"
)

type serviceGroupInput struct {
	v1.ServicePort
	FlowEndpoint
}

var _ = Describe("ServicePort relationships test", func() {
	DescribeTable("Basic service tests",
		func(sgis []serviceGroupInput, results []ServiceGroup) {
			srh := NewServiceGroups()

			for _, sgi := range sgis {
				srh.AddMapping(sgi.ServicePort, sgi.FlowEndpoint)
			}
			srh.FinishMappings()
			actualMap := make(map[v1.GraphNodeID]ServiceGroup)
			err := srh.Iter(func(sg *ServiceGroup) error {
				actualMap[sg.ID] = *sg
				return nil
			})
			Expect(err).ToNot(HaveOccurred())

			for i := range results {
				Expect(actualMap).To(HaveKey(results[i].ID))
				actual := actualMap[results[i].ID]

				Expect(actual.Namespace).To(Equal(results[i].Namespace))
				Expect(actual.Name).To(Equal(results[i].Name))
				Expect(actual.Services).To(ConsistOf(results[i].Services))
				Expect(actual.ServicePorts).To(Equal(results[i].ServicePorts))
			}
		},
		Entry("Two services related by a third through Endpoints",
			[]serviceGroupInput{{
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service1",
					},
					PortName: "",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name1*",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}, {
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service1",
					},
					PortName: "",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name2*",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}, {
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service2",
					},
					PortName: "",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name3*",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}, {
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service2",
					},
					PortName: "",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name4*",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}, {
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service3",
					},
					PortName: "",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name1*",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}, {
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service3",
					},
					PortName: "",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name4*",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}},
			[]ServiceGroup{{
				ID:        "svcgp;svc/namespace1/service1;svc/namespace1/service2;svc/namespace1/service3",
				Name:      "service1/service2/service3",
				Namespace: "namespace1",
				Services: []v1.NamespacedName{{
					Namespace: "namespace1", Name: "service1",
				}, {
					Namespace: "namespace1", Name: "service2",
				}, {
					Namespace: "namespace1", Name: "service3",
				}},
				ServicePorts: map[v1.ServicePort]map[FlowEndpoint]struct{}{
					{
						NamespacedName: v1.NamespacedName{
							Name: "service1", Namespace: "namespace1",
						},
						Protocol: "tcp",
					}: {
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name1*", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name2*", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
					},
					{
						NamespacedName: v1.NamespacedName{
							Name: "service2", Namespace: "namespace1",
						},
						Protocol: "tcp",
					}: {
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name3*", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name4*", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
					},
					{
						NamespacedName: v1.NamespacedName{
							Name: "service3", Namespace: "namespace1",
						},
						Protocol: "tcp",
					}: {
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name1*", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name4*", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
					},
				},
			}},
		),

		Entry("Two services different ports related by service",
			[]serviceGroupInput{{
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service1",
					},
					PortName: "port1",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name1*",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}, {
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service1",
					},
					PortName: "port2",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "rep",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "name2*",
					PortNum:   9444,
					Protocol:  "tcp",
				},
			}},
			[]ServiceGroup{{
				ID:        "svcgp;svc/namespace1/service1",
				Name:      "service1",
				Namespace: "namespace1",
				Services: []v1.NamespacedName{{
					Namespace: "namespace1", Name: "service1",
				}},
				ServicePorts: map[v1.ServicePort]map[FlowEndpoint]struct{}{
					{
						NamespacedName: v1.NamespacedName{
							Name: "service1", Namespace: "namespace1",
						},
						PortName: "port1", Protocol: "tcp",
					}: {
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name1*", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
					},
					{
						NamespacedName: v1.NamespacedName{
							Name: "service1", Namespace: "namespace1",
						},
						PortName: "port2", Protocol: "tcp",
					}: {
						FlowEndpoint{
							Type: "rep", Namespace: "namespace1", NameAggr: "name2*", Name: "", PortNum: 9444, Protocol: "tcp",
						}: struct{}{},
					},
				},
			}},
		),

		Entry("Two services using different ports in the same network set",
			[]serviceGroupInput{{
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service1",
					},
					PortName: "port1",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "ns",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "net1",
					PortNum:   9443,
					Protocol:  "tcp",
				},
			}, {
				v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Namespace: "namespace1",
						Name:      "service2",
					},
					PortName: "port2",
					Protocol: "tcp",
				},
				FlowEndpoint{
					Type:      "ns",
					Namespace: "namespace1",
					Name:      "",
					NameAggr:  "net1",
					PortNum:   9444,
					Protocol:  "tcp",
				},
			}},
			// Different ports in the same network set are not treated as identical Endpoints so these services will
			// not be grouped together.
			[]ServiceGroup{{
				ID:        "svcgp;svc/namespace1/service1",
				Name:      "service1",
				Namespace: "namespace1",
				Services: []v1.NamespacedName{{
					Namespace: "namespace1", Name: "service1",
				}},
				ServicePorts: map[v1.ServicePort]map[FlowEndpoint]struct{}{
					{
						NamespacedName: v1.NamespacedName{
							Name: "service1", Namespace: "namespace1",
						},
						PortName: "port1", Protocol: "tcp",
					}: {
						FlowEndpoint{
							Type: "ns", Namespace: "namespace1", NameAggr: "net1", Name: "", PortNum: 9443, Protocol: "tcp",
						}: struct{}{},
					},
				},
			}, {
				ID:        "svcgp;svc/namespace1/service2",
				Name:      "service2",
				Namespace: "namespace1",
				Services: []v1.NamespacedName{{
					Namespace: "namespace1", Name: "service2",
				}},
				ServicePorts: map[v1.ServicePort]map[FlowEndpoint]struct{}{
					{
						NamespacedName: v1.NamespacedName{
							Name: "service2", Namespace: "namespace1",
						},
						PortName: "port2", Protocol: "tcp",
					}: {
						FlowEndpoint{
							Type: "ns", Namespace: "namespace1", NameAggr: "net1", Name: "", PortNum: 9444, Protocol: "tcp",
						}: struct{}{},
					},
				},
			}},
		),
	)
})
