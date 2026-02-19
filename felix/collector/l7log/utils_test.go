// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package l7log

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("L7 log utility functions", func() {
	Describe("utils.AddressAndPort tests", func() {
		Context("With an IP and port", func() {
			It("Should properly split the IP and port", func() {
				addr, port := utils.AddressAndPort("10.10.10.10:80")
				Expect(addr).To(Equal("10.10.10.10"))
				Expect(port).To(Equal(80))
			})
		})

		Context("With an IP without a port", func() {
			It("Should properly return the IP", func() {
				addr, port := utils.AddressAndPort("10.10.10.10")
				Expect(addr).To(Equal("10.10.10.10"))
				Expect(port).To(Equal(0))
			})
		})

		Context("With a service name and port", func() {
			It("Should properly split the service name and port", func() {
				addr, port := utils.AddressAndPort("my-svc:80")
				Expect(addr).To(Equal("my-svc"))
				Expect(port).To(Equal(80))
			})
		})

		Context("With a service name and no port", func() {
			It("Should properly return the service name", func() {
				addr, port := utils.AddressAndPort("my-svc")
				Expect(addr).To(Equal("my-svc"))
				Expect(port).To(Equal(0))
			})
		})

		Context("With a malformed address", func() {
			It("Should not return anything", func() {
				addr, port := utils.AddressAndPort("asdf:qewr:asdf:jkl")
				Expect(addr).To(Equal(""))
				Expect(port).To(Equal(0))
			})
		})
	})

	Describe("utils.ExtractK8sServiceNameAndNamespace tests", func() {
		Context("With a Kubernetes service DNS name", func() {
			It("Should properly extract the service name and namespace", func() {
				name, ns := utils.ExtractK8sServiceNameAndNamespace("my-svc.svc-namespace.svc.cluster.local")
				Expect(name).To(Equal("my-svc"))
				Expect(ns).To(Equal("svc-namespace"))
			})
		})

		Context("With a Kubernetes service DNS name without a namespace", func() {
			It("Should properly extract the service name and namespace", func() {
				name, ns := utils.ExtractK8sServiceNameAndNamespace("my-svc.svc.cluster.local")
				Expect(name).To(Equal("my-svc"))
				Expect(ns).To(Equal(""))
			})
		})

		Context("With a Kubernetes service DNS name with a subdomain", func() {
			It("Should properly extract the service name, subdomain, and namespace", func() {
				name, ns := utils.ExtractK8sServiceNameAndNamespace("my-svc.place.svc-namespace.svc.cluster.local")
				Expect(name).To(Equal("my-svc.place"))
				Expect(ns).To(Equal("svc-namespace"))
			})
		})

		Context("With only the service name and namespace", func() {
			It("Should properly extract the service name and namespace", func() {
				name, ns := utils.ExtractK8sServiceNameAndNamespace("my-svc.svc-namespace")
				Expect(name).To(Equal("my-svc"))
				Expect(ns).To(Equal("svc-namespace"))
			})
		})

		Context("With an invalid Kubernetes service DNS name", func() {
			It("Should return nothing", func() {
				// Pod DNS
				name, ns := utils.ExtractK8sServiceNameAndNamespace("my-pod.pod-namespace.pod.cluster.local")
				Expect(name).To(Equal(""))
				Expect(ns).To(Equal(""))

				// Non Kubernetes DNS
				name, ns = utils.ExtractK8sServiceNameAndNamespace("my-external-svc.random.com")
				Expect(name).To(Equal(""))
				Expect(ns).To(Equal(""))
			})
		})
	})
})

var _ = Describe("Test L7 Aggregation options", func() {
	var update Update
	JustBeforeEach(func() {
		remoteWlEpKey1 := model.WorkloadEndpointKey{
			OrchestratorID: "orchestrator",
			WorkloadID:     "default/remoteworkloadid1",
			EndpointID:     "remoteepid1",
		}
		ed1 := calc.CalculateRemoteEndpoint(remoteWlEpKey1, remoteWlEp1)
		remoteWlEpKey2 := model.WorkloadEndpointKey{
			OrchestratorID: "orchestrator",
			WorkloadID:     "default/remoteworkloadid2",
			EndpointID:     "remoteepid2",
		}
		ed2 := calc.CalculateRemoteEndpoint(remoteWlEpKey2, remoteWlEp2)

		update = Update{
			Tuple:            tuple.Make(remoteIp1, remoteIp2, proto_tcp, srcPort, dstPort),
			SrcEp:            ed1,
			DstEp:            ed2,
			Duration:         10,
			DurationMax:      12,
			BytesReceived:    500,
			BytesSent:        30,
			ResponseCode:     "200",
			RouteName:        "test/route-name",
			GatewayName:      "test-gateway",
			Protocol:         "TCP",
			Method:           "GET",
			Domain:           "www.test.com",
			Path:             "/test/path?val=a",
			UserAgent:        "firefox",
			Type:             "html/1.1",
			Count:            1,
			ServiceName:      "test-service",
			ServiceNamespace: "test-namespace",
			ServicePortName:  "test-port",
		}
	})

	It("Should return all data when there is no aggregation on all fields", func() {
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfo,
			HTTPMethod:      HTTPMethod,
			Service:         ServiceInfo,
			Destination:     DestinationInfo,
			Source:          SourceInfo,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCode,
			NumURLPathParts: -1,
			URLCharLimit:    28,
		}

		meta, _, err := newMetaSpecFromUpdate(update, agg)
		Expect(err).To(BeNil())
		Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
		Expect(meta.Method).To(Equal(update.Method))
		Expect(meta.Domain).To(Equal(update.Domain))
		Expect(meta.Path).To(Equal(update.Path))
		Expect(meta.UserAgent).To(Equal(update.UserAgent))
		Expect(meta.Type).To(Equal(update.Type))

		Expect(meta.ServiceName).To(Equal(update.ServiceName))
		Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
		Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

		Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
		Expect(meta.SrcNamespace).To(Equal("default"))
		Expect(meta.SrcType).To(Equal(endpoint.Wep))
		Expect(meta.SourcePortNum).To(Equal(srcPort))

		Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
		Expect(meta.DestNamespace).To(Equal("default"))
		Expect(meta.DestType).To(Equal(endpoint.Wep))
		Expect(meta.DestPortNum).To(Equal(dstPort))
	})

	It("Should aggregate out the correct HTTP header details appropriately", func() {
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfoNone,
			HTTPMethod:      HTTPMethod,
			Service:         ServiceInfo,
			Destination:     DestinationInfo,
			Source:          SourceInfo,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCode,
			NumURLPathParts: -1,
			URLCharLimit:    28,
		}

		meta, _, err := newMetaSpecFromUpdate(update, agg)
		Expect(err).To(BeNil())
		Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
		Expect(meta.RouteName).To(Equal(update.RouteName))
		Expect(meta.GatewayName).To(Equal(update.GatewayName))
		Expect(meta.Protocol).To(Equal(update.Protocol))
		Expect(meta.Method).To(Equal(update.Method))
		Expect(meta.Domain).To(Equal(update.Domain))
		Expect(meta.Path).To(Equal(update.Path))
		Expect(meta.UserAgent).To(Equal(utils.FieldNotIncluded))
		Expect(meta.Type).To(Equal(utils.FieldNotIncluded))

		Expect(meta.ServiceName).To(Equal(update.ServiceName))
		Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
		Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

		Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
		Expect(meta.SrcNamespace).To(Equal("default"))
		Expect(meta.SrcType).To(Equal(endpoint.Wep))
		Expect(meta.SourcePortNum).To(Equal(srcPort))

		Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
		Expect(meta.DestNamespace).To(Equal("default"))
		Expect(meta.DestType).To(Equal(endpoint.Wep))
		Expect(meta.DestPortNum).To(Equal(dstPort))
	})

	It("Should aggregate out the HTTP method", func() {
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfo,
			HTTPMethod:      HTTPMethodNone,
			Service:         ServiceInfo,
			Destination:     DestinationInfo,
			Source:          SourceInfo,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCode,
			NumURLPathParts: -1,
			URLCharLimit:    28,
		}

		meta, _, err := newMetaSpecFromUpdate(update, agg)
		Expect(err).To(BeNil())
		Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
		Expect(meta.RouteName).To(Equal(update.RouteName))
		Expect(meta.GatewayName).To(Equal(update.GatewayName))
		Expect(meta.Protocol).To(Equal(update.Protocol))
		Expect(meta.Method).To(Equal(utils.FieldNotIncluded))
		Expect(meta.Domain).To(Equal(update.Domain))
		Expect(meta.Path).To(Equal(update.Path))
		Expect(meta.UserAgent).To(Equal(update.UserAgent))
		Expect(meta.Type).To(Equal(update.Type))
		Expect(meta.ServiceName).To(Equal(update.ServiceName))
		Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
		Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

		Expect(meta.ServicePortName).To(Equal(update.ServicePortName))
		Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
		Expect(meta.SrcNamespace).To(Equal("default"))
		Expect(meta.SrcType).To(Equal(endpoint.Wep))
		Expect(meta.SourcePortNum).To(Equal(srcPort))

		Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
		Expect(meta.DestNamespace).To(Equal("default"))
		Expect(meta.DestType).To(Equal(endpoint.Wep))
		Expect(meta.DestPortNum).To(Equal(dstPort))
	})

	It("Should aggregate over service information properly", func() {
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfo,
			HTTPMethod:      HTTPMethod,
			Service:         ServiceInfoNone,
			Destination:     DestinationInfo,
			Source:          SourceInfo,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCode,
			NumURLPathParts: -1,
			URLCharLimit:    28,
		}

		meta, _, err := newMetaSpecFromUpdate(update, agg)
		Expect(err).To(BeNil())
		Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
		Expect(meta.RouteName).To(Equal(update.RouteName))
		Expect(meta.GatewayName).To(Equal(update.GatewayName))
		Expect(meta.Protocol).To(Equal(update.Protocol))
		Expect(meta.Method).To(Equal(update.Method))
		Expect(meta.Domain).To(Equal(update.Domain))
		Expect(meta.Path).To(Equal(update.Path))
		Expect(meta.UserAgent).To(Equal(update.UserAgent))
		Expect(meta.Type).To(Equal(update.Type))
		Expect(meta.ServiceName).To(Equal(utils.FieldNotIncluded))
		Expect(meta.ServiceNamespace).To(Equal(utils.FieldNotIncluded))

		Expect(meta.ServicePortName).To(Equal(utils.FieldNotIncluded))
		Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
		Expect(meta.SrcNamespace).To(Equal("default"))
		Expect(meta.SrcType).To(Equal(endpoint.Wep))
		Expect(meta.SourcePortNum).To(Equal(srcPort))

		Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
		Expect(meta.DestNamespace).To(Equal("default"))
		Expect(meta.DestType).To(Equal(endpoint.Wep))
		Expect(meta.DestPortNum).To(Equal(dstPort))
	})

	It("Should aggregate out the destination information properly", func() {
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfo,
			HTTPMethod:      HTTPMethod,
			Service:         ServiceInfo,
			Destination:     DestinationInfoNone,
			Source:          SourceInfo,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCode,
			NumURLPathParts: -1,
			URLCharLimit:    28,
		}

		meta, _, err := newMetaSpecFromUpdate(update, agg)
		Expect(err).To(BeNil())
		Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
		Expect(meta.RouteName).To(Equal(update.RouteName))
		Expect(meta.GatewayName).To(Equal(update.GatewayName))
		Expect(meta.Protocol).To(Equal(update.Protocol))
		Expect(meta.Method).To(Equal(update.Method))
		Expect(meta.Domain).To(Equal(update.Domain))
		Expect(meta.Path).To(Equal(update.Path))
		Expect(meta.UserAgent).To(Equal(update.UserAgent))
		Expect(meta.Type).To(Equal(update.Type))
		Expect(meta.ServiceName).To(Equal(update.ServiceName))
		Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
		Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

		Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
		Expect(meta.SrcNamespace).To(Equal("default"))
		Expect(meta.SrcType).To(Equal(endpoint.Wep))
		Expect(meta.SourcePortNum).To(Equal(srcPort))

		Expect(meta.DestNameAggr).To(Equal(utils.FieldNotIncluded))
		Expect(meta.DestNamespace).To(Equal(utils.FieldNotIncluded))
		Expect(meta.DestType).To(Equal(endpoint.Type(utils.FieldNotIncluded)))
		Expect(meta.DestPortNum).To(Equal(0))
	})

	It("Should aggregate out the source information properly", func() {
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfo,
			HTTPMethod:      HTTPMethod,
			Service:         ServiceInfo,
			Destination:     DestinationInfo,
			Source:          SourceInfoNone,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCode,
			NumURLPathParts: -1,
			URLCharLimit:    28,
		}

		meta, _, err := newMetaSpecFromUpdate(update, agg)
		Expect(err).To(BeNil())
		Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
		Expect(meta.RouteName).To(Equal(update.RouteName))
		Expect(meta.GatewayName).To(Equal(update.GatewayName))
		Expect(meta.Protocol).To(Equal(update.Protocol))
		Expect(meta.Method).To(Equal(update.Method))
		Expect(meta.Domain).To(Equal(update.Domain))
		Expect(meta.Path).To(Equal(update.Path))
		Expect(meta.UserAgent).To(Equal(update.UserAgent))
		Expect(meta.Type).To(Equal(update.Type))
		Expect(meta.ServiceName).To(Equal(update.ServiceName))
		Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
		Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

		Expect(meta.SrcNameAggr).To(Equal(utils.FieldNotIncluded))
		Expect(meta.SrcNamespace).To(Equal(utils.FieldNotIncluded))
		Expect(meta.SrcType).To(Equal(endpoint.Type(utils.FieldNotIncluded)))
		Expect(meta.SourcePortNum).To(Equal(0))

		Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
		Expect(meta.DestNamespace).To(Equal("default"))
		Expect(meta.DestType).To(Equal(endpoint.Wep))
		Expect(meta.DestPortNum).To(Equal(dstPort))
	})

	It("Should aggregate out the response code", func() {
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfo,
			HTTPMethod:      HTTPMethod,
			Service:         ServiceInfo,
			Destination:     DestinationInfo,
			Source:          SourceInfo,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCodeNone,
			NumURLPathParts: -1,
			URLCharLimit:    28,
		}

		meta, _, err := newMetaSpecFromUpdate(update, agg)
		Expect(err).To(BeNil())
		Expect(meta.ResponseCode).To(Equal(utils.FieldNotIncluded))
		Expect(meta.RouteName).To(Equal(update.RouteName))
		Expect(meta.GatewayName).To(Equal(update.GatewayName))
		Expect(meta.Protocol).To(Equal(update.Protocol))
		Expect(meta.Method).To(Equal(update.Method))
		Expect(meta.Domain).To(Equal(update.Domain))
		Expect(meta.Path).To(Equal(update.Path))
		Expect(meta.UserAgent).To(Equal(update.UserAgent))
		Expect(meta.Type).To(Equal(update.Type))
		Expect(meta.ServiceName).To(Equal(update.ServiceName))
		Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
		Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

		Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
		Expect(meta.SrcNamespace).To(Equal("default"))
		Expect(meta.SrcType).To(Equal(endpoint.Wep))
		Expect(meta.SourcePortNum).To(Equal(srcPort))

		Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
		Expect(meta.DestNamespace).To(Equal("default"))
		Expect(meta.DestType).To(Equal(endpoint.Wep))
		Expect(meta.DestPortNum).To(Equal(dstPort))
	})

	Context("With URL aggregating on", func() {
		It("Should remove the entire URL", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         URLNone,
				ResponseCode:    ResponseCode,
				NumURLPathParts: -1,
				URLCharLimit:    28,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(utils.FieldNotIncluded))
			Expect(meta.Path).To(Equal(utils.FieldNotIncluded))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should remove only the query parameters", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         URLWithoutQuery,
				ResponseCode:    ResponseCode,
				NumURLPathParts: -1,
				URLCharLimit:    28,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal("/test/path"))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should remove the path", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         BaseURL,
				ResponseCode:    ResponseCode,
				NumURLPathParts: -1,
				URLCharLimit:    28,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal(utils.FieldNotIncluded))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should properly truncate parts of the URL path", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         FullURL,
				ResponseCode:    ResponseCode,
				NumURLPathParts: 1,
				URLCharLimit:    28,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal("/test"))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should properly truncate all parts of the URL path", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         FullURL,
				ResponseCode:    ResponseCode,
				NumURLPathParts: 0,
				URLCharLimit:    28,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal(""))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should output full url with query params when URLCharLimit is more than length of the URL", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         FullURL,
				ResponseCode:    ResponseCode,
				NumURLPathParts: -1,
				URLCharLimit:    40,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal(update.Path))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should output truncated domain, empty path when URLCharLimit is less than length of domain", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         FullURL,
				ResponseCode:    ResponseCode,
				NumURLPathParts: -1,
				URLCharLimit:    10,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal("www.test.c"))
			Expect(meta.Path).To(Equal(utils.FieldNotIncluded))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should output full domain, parts of path when URLCharLimit is more than domain length but less than full path url", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         FullURL,
				ResponseCode:    ResponseCode,
				NumURLPathParts: 5,
				URLCharLimit:    15,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal("/te"))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should output empty domain and path for L7URLNone case no matter what URLCharLimit is passed", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         URLNone,
				ResponseCode:    ResponseCode,
				NumURLPathParts: 5,
				URLCharLimit:    15,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(utils.FieldNotIncluded))
			Expect(meta.Path).To(Equal(utils.FieldNotIncluded))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should output full domain and empty path for L7BaseURL case when URLCharLimit is more than domain length", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         BaseURL,
				ResponseCode:    ResponseCode,
				NumURLPathParts: 5,
				URLCharLimit:    20,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal(utils.FieldNotIncluded))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})

		It("Should output full domain and max path for L7URLWithoutQuery case when URLCharLimit is between domain length and full url length", func() {
			agg := AggregationKind{
				HTTPHeader:      HTTPHeaderInfo,
				HTTPMethod:      HTTPMethod,
				Service:         ServiceInfo,
				Destination:     DestinationInfo,
				Source:          SourceInfo,
				TrimURL:         URLWithoutQuery,
				ResponseCode:    ResponseCode,
				NumURLPathParts: 5,
				URLCharLimit:    20,
			}

			meta, _, err := newMetaSpecFromUpdate(update, agg)
			Expect(err).To(BeNil())
			Expect(meta.ResponseCode).To(Equal(update.ResponseCode))
			Expect(meta.RouteName).To(Equal(update.RouteName))
			Expect(meta.GatewayName).To(Equal(update.GatewayName))
			Expect(meta.Protocol).To(Equal(update.Protocol))
			Expect(meta.Method).To(Equal(update.Method))
			Expect(meta.Domain).To(Equal(update.Domain))
			Expect(meta.Path).To(Equal("/test/pa"))
			Expect(meta.UserAgent).To(Equal(update.UserAgent))
			Expect(meta.Type).To(Equal(update.Type))
			Expect(meta.ServiceName).To(Equal(update.ServiceName))
			Expect(meta.ServiceNamespace).To(Equal(update.ServiceNamespace))
			Expect(meta.ServicePortName).To(Equal(update.ServicePortName))

			Expect(meta.SrcNameAggr).To(Equal("remoteworkloadid1"))
			Expect(meta.SrcNamespace).To(Equal("default"))
			Expect(meta.SrcType).To(Equal(endpoint.Wep))
			Expect(meta.SourcePortNum).To(Equal(srcPort))

			Expect(meta.DestNameAggr).To(Equal("remoteworkloadid2"))
			Expect(meta.DestNamespace).To(Equal("default"))
			Expect(meta.DestType).To(Equal(endpoint.Wep))
			Expect(meta.DestPortNum).To(Equal(dstPort))
		})
	})
})
