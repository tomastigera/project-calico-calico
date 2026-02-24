// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package engine

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/lma/pkg/api"
	calicores "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	"github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

var _ = Describe("EngineRules", func() {
	const (
		timeNowRFC3339 = "2022-11-30T09:01:38Z"

		serviceNameSuffix = "svc.cluster.local"
	)

	var (
		er *engineRules

		port45  = uint16(45)
		port48  = uint16(48)
		port443 = uint16(443)
		port444 = uint16(444)
		port445 = uint16(445)
		port55  = uint16(55)
		port56  = uint16(56)
	)

	BeforeEach(func() {
		// Initialize a new engineRules object before each test
		er = NewEngineRules()
	})

	Context("when adding flows to egress to domain rules", func() {
		It("should add the flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.EgressTraffic, flow: api.Flow{}},
				{direction: calicores.IngressTraffic, flow: api.Flow{}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Domains: "www.some-domain.com,service.service-ns.svc.cluster.local", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{Domains: "www.some-empty-protocol-domain.com", Port: &port444}}},                                    // Empty Protocol
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Domains: "service.service-ns.svc.cluster.local,www.empty-ports-domain.com"}}}, // Empty Ports
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Domains: "www.some-domain.com", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Domains: "www.some-other-domain.com,service.service-ns.svc.cluster.local", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Domains: "www.some-domain.com", Port: &port444}}},  // no update necessary
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{Domains: "www.some-icmp-domain.com", Port: nil}}}, // no update necessary
			}

			key1 := engineRuleKey{protocol: protocolUDP, port: numorstring.Port{MinPort: port444, MaxPort: port444}}
			key2 := engineRuleKey{protocol: protocolUDP, port: numorstring.Port{}}
			key3 := engineRuleKey{protocol: protocolICMP, port: numorstring.Port{}}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.egressToDomainRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Domains: []string{"www.some-domain.com", "www.some-other-domain.com"}, Protocol: protocolUDP, Ports: []numorstring.Port{numorstring.Port{MinPort: port444, MaxPort: port444}}, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Domains: []string{"www.empty-ports-domain.com"}, Protocol: protocolUDP, Ports: []numorstring.Port{numorstring.Port{}}, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Domains: []string{"www.some-icmp-domain.com"}, Protocol: protocolICMP, Ports: []numorstring.Port{numorstring.Port{}}, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 3

			for _, td := range testData {
				er.addFlowToEgressToDomainRules(td.direction, td.flow, mockRealClock{}, serviceNameSuffix)
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to domain rules contains the expected rules
			Expect(er.egressToDomainRules).To(HaveKeyWithValue(key1, expectedEngineRules.egressToDomainRules[key1]))
			Expect(er.egressToDomainRules).To(HaveKeyWithValue(key2, expectedEngineRules.egressToDomainRules[key2]))
			Expect(er.egressToDomainRules).To(HaveKeyWithValue(key3, expectedEngineRules.egressToDomainRules[key3]))

			// The other engine rules should be empty
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})
	})

	Context("when adding flow to egress to service rules", func() {
		It("should add the flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.EgressTraffic, flow: api.Flow{}},
				{direction: calicores.IngressTraffic, flow: api.Flow{}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc1", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{ServiceName: "svc2", Port: &port444}}},       // Empty Protocol
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc3"}}}, // Empty Ports
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc4", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc3", Port: &port55}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc4", Port: &port444}}}, // No update necessary
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{ServiceName: "svc5-icmp", Port: nil}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc3", Port: &port45}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc3", Port: &port48}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{ServiceName: "svc3", Port: &port56}}},
			}

			key1 := engineRuleKey{name: "svc1", protocol: protocolUDP}
			key2 := engineRuleKey{name: "svc3", protocol: protocolUDP}
			key3 := engineRuleKey{name: "svc4", protocol: protocolUDP}
			key4 := engineRuleKey{name: "svc5-icmp", protocol: protocolICMP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.egressToServiceRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Name: "svc1", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Name: "svc3", Ports: []numorstring.Port{{}, {MinPort: port55, MaxPort: port55}, {MinPort: port45, MaxPort: port45}, {MinPort: port48, MaxPort: port48}, {MinPort: port56, MaxPort: port56}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Name: "svc4", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key4: {Action: v3.Allow, Name: "svc5-icmp", Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 4

			for _, td := range testData {
				er.addFlowToEgressToServiceRules(td.direction, td.flow, true, mockRealClock{})
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to service rules contains the expected rules
			Expect(er.egressToServiceRules).To(HaveKeyWithValue(key1, expectedEngineRules.egressToServiceRules[key1]))
			Expect(er.egressToServiceRules).To(HaveKeyWithValue(key2, expectedEngineRules.egressToServiceRules[key2]))
			Expect(er.egressToServiceRules).To(HaveKeyWithValue(key3, expectedEngineRules.egressToServiceRules[key3]))
			Expect(er.egressToServiceRules).To(HaveKeyWithValue(key4, expectedEngineRules.egressToServiceRules[key4]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})
	})

	Context("when adding flow namespace rules", func() {
		It("should add the egress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.EgressTraffic, flow: api.Flow{}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns1", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{Namespace: "ns2", Port: &port444}}},       // Empty Protocol
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns3"}}}, // Empty Ports
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns4", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns3", Port: &port55}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns4", Port: &port444}}}, // No update necessary
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{Namespace: "ns5-icmp", Port: nil}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns3", Port: &port45}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns3", Port: &port48}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Namespace: "ns3", Port: &port56}}},
				// Intra-namespace traffic
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns6-intra"}, Destination: api.FlowEndpointData{Namespace: "ns6-intra", Port: &port48}}},
			}

			key1 := engineRuleKey{namespace: "ns1", protocol: protocolUDP}
			key2 := engineRuleKey{namespace: "ns3", protocol: protocolUDP}
			key3 := engineRuleKey{namespace: "ns4", protocol: protocolUDP}
			key4 := engineRuleKey{namespace: "ns5-icmp", protocol: protocolICMP}
			key5 := engineRuleKey{namespace: "ns6-intra", protocol: protocolUDP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.namespaceRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Namespace: "ns1", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Namespace: "ns3", Ports: []numorstring.Port{{}, {MinPort: port55, MaxPort: port55}, {MinPort: port45, MaxPort: port45}, {MinPort: port48, MaxPort: port48}, {MinPort: port56, MaxPort: port56}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Namespace: "ns4", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key4: {Action: v3.Allow, Namespace: "ns5-icmp", Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
				key5: {Action: v3.Pass, Namespace: "ns6-intra", Ports: []numorstring.Port{{MinPort: port48, MaxPort: port48}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
			}

			for _, td := range testData {
				er.addFlowToNamespaceRules(td.direction, td.flow, true, mockRealClock{})
			}

			Expect(er.size).To(Equal(len(expectedEngineRules.namespaceRules)))

			// The egress to service rules contains the expected rules
			Expect(er.namespaceRules).To(HaveKeyWithValue(key1, expectedEngineRules.namespaceRules[key1]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key2, expectedEngineRules.namespaceRules[key2]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key3, expectedEngineRules.namespaceRules[key3]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key4, expectedEngineRules.namespaceRules[key4]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key5, expectedEngineRules.namespaceRules[key5]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})

		It("should add the ingress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.IngressTraffic, flow: api.Flow{}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns1"}, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Source: api.FlowEndpointData{Namespace: "ns2"}, Destination: api.FlowEndpointData{Port: &port444}}},         // Empty Protocol
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns3"}, Destination: api.FlowEndpointData{}}}, // Empty Ports
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns4"}, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns3"}, Destination: api.FlowEndpointData{Port: &port55}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns4"}, Destination: api.FlowEndpointData{Port: &port444}}}, // No update necessary
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Source: api.FlowEndpointData{Namespace: "ns5-icmp"}, Destination: api.FlowEndpointData{Port: nil}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns4"}, Destination: api.FlowEndpointData{Port: &port443}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns4"}, Destination: api.FlowEndpointData{Port: &port445}}},
				// Intra-namespace traffic
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Namespace: "ns6-intra"}, Destination: api.FlowEndpointData{Namespace: "ns6-intra", Port: &port48}}},
			}

			key1 := engineRuleKey{namespace: "ns1", protocol: protocolUDP}
			key2 := engineRuleKey{namespace: "ns3", protocol: protocolUDP}
			key3 := engineRuleKey{namespace: "ns4", protocol: protocolUDP}
			key4 := engineRuleKey{namespace: "ns5-icmp", protocol: protocolICMP}
			key5 := engineRuleKey{namespace: "ns6-intra", protocol: protocolUDP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.namespaceRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Namespace: "ns1", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Namespace: "ns3", Ports: []numorstring.Port{{}, {MinPort: port55, MaxPort: port55}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Namespace: "ns4", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}, {MinPort: port443, MaxPort: port443}, {MinPort: port445, MaxPort: port445}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key4: {Action: v3.Allow, Namespace: "ns5-icmp", Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
				key5: {Action: v3.Pass, Namespace: "ns6-intra", Ports: []numorstring.Port{{MinPort: port48, MaxPort: port48}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
			}

			passIntraNamespaceTraffic := true
			for _, td := range testData {
				er.addFlowToNamespaceRules(td.direction, td.flow, passIntraNamespaceTraffic, mockRealClock{})
			}

			Expect(er.size).To(Equal(len(expectedEngineRules.namespaceRules)))

			// The egress to service rules contains the expected rules
			Expect(er.namespaceRules).To(HaveKeyWithValue(key1, expectedEngineRules.namespaceRules[key1]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key2, expectedEngineRules.namespaceRules[key2]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key3, expectedEngineRules.namespaceRules[key3]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key4, expectedEngineRules.namespaceRules[key4]))
			Expect(er.namespaceRules).To(HaveKeyWithValue(key5, expectedEngineRules.namespaceRules[key5]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})
	})

	Context("when adding flow networkset rules", func() {
		It("should add the egress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.EgressTraffic, flow: api.Flow{}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Name: "netset1", Namespace: "ns1", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{Name: "netset2", Namespace: "ns2", Port: &port444}}},       // Empty Protocol
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Name: "netset3", Namespace: "ns3"}}}, // Empty Ports
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Name: "netset4", Namespace: "ns4", Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Name: "netset5", Namespace: "", Port: &port55}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Name: "netset4", Namespace: "ns4", Port: &port444}}}, // No update necessary
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{Name: "netset6-icmp", Namespace: "ns6", Port: nil}}},
			}

			key1 := engineRuleKey{global: false, name: "netset1", namespace: "ns1", protocol: protocolUDP}
			key2 := engineRuleKey{global: false, name: "netset3", namespace: "ns3", protocol: protocolUDP}
			key3 := engineRuleKey{global: false, name: "netset4", namespace: "ns4", protocol: protocolUDP}
			key4 := engineRuleKey{global: true, name: "netset5", namespace: "", protocol: protocolUDP}
			key5 := engineRuleKey{global: false, name: "netset6-icmp", namespace: "ns6", protocol: protocolICMP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.networkSetRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Global: false, Name: "netset1", Namespace: "ns1", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Global: false, Name: "netset3", Namespace: "ns3", Ports: []numorstring.Port{{}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Global: false, Name: "netset4", Namespace: "ns4", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key4: {Action: v3.Allow, Global: true, Name: "netset5", Namespace: "", Ports: []numorstring.Port{{MinPort: port55, MaxPort: port55}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key5: {Action: v3.Allow, Global: false, Name: "netset6-icmp", Namespace: "ns6", Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 5

			for _, td := range testData {
				er.addFlowToNetworkSetRules(td.direction, td.flow, true, mockRealClock{})
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to service rules contains the expected rules
			Expect(er.networkSetRules).To(HaveKeyWithValue(key1, expectedEngineRules.networkSetRules[key1]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key2, expectedEngineRules.networkSetRules[key2]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key3, expectedEngineRules.networkSetRules[key3]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key4, expectedEngineRules.networkSetRules[key4]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key5, expectedEngineRules.networkSetRules[key5]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})

		It("should add the ingress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.IngressTraffic, flow: api.Flow{}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Name: "netset1", Namespace: "ns1"}, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Source: api.FlowEndpointData{Name: "netset2", Namespace: "ns2"}, Destination: api.FlowEndpointData{Port: &port444}}},         // Empty Protocol
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Name: "netset3", Namespace: "ns3"}, Destination: api.FlowEndpointData{}}}, // Empty Ports
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Name: "netset4", Namespace: "ns4"}, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Name: "netset5", Namespace: ""}, Destination: api.FlowEndpointData{Port: &port55}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Source: api.FlowEndpointData{Name: "netset4", Namespace: "ns4"}, Destination: api.FlowEndpointData{Port: &port444}}}, // No update necessary
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Source: api.FlowEndpointData{Name: "netset6-icmp", Namespace: "ns6"}, Destination: api.FlowEndpointData{Port: nil}}},
			}

			key1 := engineRuleKey{global: false, name: "netset1", namespace: "ns1", protocol: protocolUDP}
			key2 := engineRuleKey{global: false, name: "netset3", namespace: "ns3", protocol: protocolUDP}
			key3 := engineRuleKey{global: false, name: "netset4", namespace: "ns4", protocol: protocolUDP}
			key4 := engineRuleKey{global: true, name: "netset5", namespace: "", protocol: protocolUDP}
			key5 := engineRuleKey{global: false, name: "netset6-icmp", namespace: "ns6", protocol: protocolICMP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.networkSetRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Global: false, Name: "netset1", Namespace: "ns1", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Global: false, Name: "netset3", Namespace: "ns3", Ports: []numorstring.Port{{}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Global: false, Name: "netset4", Namespace: "ns4", Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key4: {Action: v3.Allow, Global: true, Name: "netset5", Namespace: "", Ports: []numorstring.Port{{MinPort: port55, MaxPort: port55}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key5: {Action: v3.Allow, Global: false, Name: "netset6-icmp", Namespace: "ns6", Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 5

			for _, td := range testData {
				er.addFlowToNetworkSetRules(td.direction, td.flow, true, mockRealClock{})
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to service rules contains the expected rules
			Expect(er.networkSetRules).To(HaveKeyWithValue(key1, expectedEngineRules.networkSetRules[key1]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key2, expectedEngineRules.networkSetRules[key2]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key3, expectedEngineRules.networkSetRules[key3]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key4, expectedEngineRules.networkSetRules[key4]))
			Expect(er.networkSetRules).To(HaveKeyWithValue(key5, expectedEngineRules.networkSetRules[key5]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})
	})

	Context("when adding flow to private network rules", func() {
		It("should add the egress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.EgressTraffic, flow: api.Flow{}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{Port: &port444}}},         // Empty Protocol
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{}}}, // Empty Ports
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port55}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}}, // No update necessary
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{Port: nil}}},
			}

			key1 := engineRuleKey{protocol: protocolTCP}
			key2 := engineRuleKey{protocol: protocolUDP}
			key3 := engineRuleKey{protocol: protocolICMP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.privateNetworkRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Ports: []numorstring.Port{{}, {MinPort: port444, MaxPort: port444}}, Protocol: protocolTCP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}, {MinPort: port55, MaxPort: port55}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 3

			for _, td := range testData {
				er.addFlowToPrivateNetworkRules(td.direction, td.flow, mockRealClock{})
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to service rules contains the expected rules
			Expect(er.privateNetworkRules).To(HaveKeyWithValue(key1, expectedEngineRules.privateNetworkRules[key1]))
			Expect(er.privateNetworkRules).To(HaveKeyWithValue(key2, expectedEngineRules.privateNetworkRules[key2]))
			Expect(er.privateNetworkRules).To(HaveKeyWithValue(key3, expectedEngineRules.privateNetworkRules[key3]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})

		It("should add the ingress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.IngressTraffic, flow: api.Flow{}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{Port: &port444}}},         // Empty Protocol
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{}}}, // Empty Ports
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port55}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}}, // No update necessary
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{Port: nil}}},
			}

			key1 := engineRuleKey{protocol: protocolTCP}
			key2 := engineRuleKey{protocol: protocolUDP}
			key3 := engineRuleKey{protocol: protocolICMP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.privateNetworkRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Ports: []numorstring.Port{{}, {MinPort: port444, MaxPort: port444}}, Protocol: protocolTCP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}, {MinPort: port55, MaxPort: port55}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 3

			for _, td := range testData {
				er.addFlowToPrivateNetworkRules(td.direction, td.flow, mockRealClock{})
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to service rules contains the expected rules
			Expect(er.privateNetworkRules).To(HaveKeyWithValue(key1, expectedEngineRules.privateNetworkRules[key1]))
			Expect(er.privateNetworkRules).To(HaveKeyWithValue(key2, expectedEngineRules.privateNetworkRules[key2]))
			Expect(er.privateNetworkRules).To(HaveKeyWithValue(key3, expectedEngineRules.privateNetworkRules[key3]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.publicNetworkRules)).To(Equal(0))
		})
	})

	Context("when adding flow to public network rules", func() {
		It("should add the egress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.EgressTraffic, flow: api.Flow{}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{Port: &port444}}},         // Empty Protocol
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{}}}, // Empty Ports
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port55}}},
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}}, // No update necessary
				{direction: calicores.EgressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{Port: nil}}},
			}

			key1 := engineRuleKey{protocol: protocolTCP}
			key2 := engineRuleKey{protocol: protocolUDP}
			key3 := engineRuleKey{protocol: protocolICMP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.publicNetworkRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Ports: []numorstring.Port{{}, {MinPort: port444, MaxPort: port444}}, Protocol: protocolTCP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}, {MinPort: port55, MaxPort: port55}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 3

			for _, td := range testData {
				er.addFlowToPublicNetworkRules(td.direction, td.flow, mockRealClock{})
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to service rules contains the expected rules
			Expect(er.publicNetworkRules).To(HaveKeyWithValue(key1, expectedEngineRules.publicNetworkRules[key1]))
			Expect(er.publicNetworkRules).To(HaveKeyWithValue(key2, expectedEngineRules.publicNetworkRules[key2]))
			Expect(er.publicNetworkRules).To(HaveKeyWithValue(key3, expectedEngineRules.publicNetworkRules[key3]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
		})

		It("should add the ingress flows correctly", func() {
			testData := []struct {
				direction calicores.DirectionType
				flow      api.Flow
			}{
				{direction: calicores.IngressTraffic, flow: api.Flow{}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Destination: api.FlowEndpointData{Port: &port444}}},         // Empty Protocol
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{}}}, // Empty Ports
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoUDP, Destination: api.FlowEndpointData{Port: &port55}}},
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoTCP, Destination: api.FlowEndpointData{Port: &port444}}}, // No update necessary
				{direction: calicores.IngressTraffic, flow: api.Flow{Proto: &api.ProtoICMP, Destination: api.FlowEndpointData{Port: nil}}},
			}

			key1 := engineRuleKey{protocol: protocolTCP}
			key2 := engineRuleKey{protocol: protocolUDP}
			key3 := engineRuleKey{protocol: protocolICMP}

			expectedEngineRules := NewEngineRules()
			expectedEngineRules.publicNetworkRules = map[engineRuleKey]*types.FlowLogData{
				key1: {Action: v3.Allow, Ports: []numorstring.Port{{}, {MinPort: port444, MaxPort: port444}}, Protocol: protocolTCP, Timestamp: timeNowRFC3339},
				key2: {Action: v3.Allow, Ports: []numorstring.Port{{MinPort: port444, MaxPort: port444}, {MinPort: port55, MaxPort: port55}}, Protocol: protocolUDP, Timestamp: timeNowRFC3339},
				key3: {Action: v3.Allow, Ports: []numorstring.Port{{}}, Protocol: protocolICMP, Timestamp: timeNowRFC3339},
			}

			expectedNumberOfRules := 3

			for _, td := range testData {
				er.addFlowToPublicNetworkRules(td.direction, td.flow, mockRealClock{})
			}

			Expect(er.size).To(Equal(expectedNumberOfRules))

			// The egress to service rules contains the expected rules
			Expect(er.publicNetworkRules).To(HaveKeyWithValue(key1, expectedEngineRules.publicNetworkRules[key1]))
			Expect(er.publicNetworkRules).To(HaveKeyWithValue(key2, expectedEngineRules.publicNetworkRules[key2]))
			Expect(er.publicNetworkRules).To(HaveKeyWithValue(key3, expectedEngineRules.publicNetworkRules[key3]))

			// The other engine rules should be empty
			Expect(len(er.egressToDomainRules)).To(Equal(0))
			Expect(len(er.egressToServiceRules)).To(Equal(0))
			Expect(len(er.namespaceRules)).To(Equal(0))
			Expect(len(er.networkSetRules)).To(Equal(0))
			Expect(len(er.privateNetworkRules)).To(Equal(0))
		})
	})

	Context("getFlowType", func() {
		DescribeTable("Flow to rule mapping",
			func(dir calicores.DirectionType, flow api.Flow, exp flowType) {
				ft := getFlowType(dir, flow, serviceNameSuffix)

				Expect(ft).To(Equal(exp))
			},
			// Egress
			Entry("src/Net/Domain - EgressToDomain", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pub", Domains: "www.tigera.com"},
				ActionFlag:  api.ActionFlagAllow,
			}, egressToDomainFlowType),
			Entry("src/WEP/Service - EgressToService", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pub", ServiceName: "svc-ext"},
				ActionFlag:  api.ActionFlagAllow,
			}, egressToServiceFlowType),
			Entry("src/WEP/Namespace - Namespace (Egress)", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns1"},
				ActionFlag:  api.ActionFlagAllow,
			}, namespaceFlowType),
			Entry("src/NET/Domain - EgressToDomain (Egress)", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pvt", Namespace: "-", Domains: "my.web.com,*.*.svc.cluster.local"},
				ActionFlag:  api.ActionFlagAllow,
			}, privateNetworkFlowType),
			Entry("src/NET/Domain - Suppressed (Egress)", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pvt", Namespace: "-", Domains: "*.*.svc.cluster.local"},
				ActionFlag:  api.ActionFlagAllow,
			}, privateNetworkFlowType),
			Entry("src/NS/Name - NetworkSet", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeNs, Name: "public-ips"},
				ActionFlag:  api.ActionFlagAllow,
			}, networkSetFlowType),
			Entry("src/NET/pvt - Private", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pvt"},
				ActionFlag:  api.ActionFlagAllow,
			}, privateNetworkFlowType),
			Entry("src/NETpub - Public", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pub"},
				ActionFlag:  api.ActionFlagAllow,
			}, publicNetworkFlowType),
			Entry("Hep - Unsupported", calicores.EgressTraffic, api.Flow{
				Reporter:    "src",
				Source:      api.FlowEndpointData{},
				Destination: api.FlowEndpointData{Type: api.EndpointTypeHep},
				ActionFlag:  api.ActionFlagAllow,
			}, unsupportedFlowType),
			// Ingress
			Entry("dst/WEP/Namespace - Namespace (Ingress)", calicores.IngressTraffic, api.Flow{
				Reporter:    "dst",
				Source:      api.FlowEndpointData{Type: api.EndpointTypeWep, Namespace: "ns1"},
				Destination: api.FlowEndpointData{},
				ActionFlag:  api.ActionFlagAllow,
			}, namespaceFlowType),
			Entry("dst/WEP/Namespace - Namespace (Ingress)", calicores.IngressTraffic, api.Flow{
				Reporter:    "dst",
				Source:      api.FlowEndpointData{Type: api.EndpointTypeNs},
				Destination: api.FlowEndpointData{},
				ActionFlag:  api.ActionFlagAllow,
			}, networkSetFlowType),
			Entry("dst/Net/pvt - Private (Ingress)", calicores.IngressTraffic, api.Flow{
				Reporter:    "dst",
				Source:      api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pvt"},
				Destination: api.FlowEndpointData{},
				ActionFlag:  api.ActionFlagAllow,
			}, privateNetworkFlowType),
			Entry("dst/Net/pvt - Public (Ingress)", calicores.IngressTraffic, api.Flow{
				Reporter:    "dst",
				Source:      api.FlowEndpointData{Type: api.EndpointTypeNet, Name: "pub"},
				Destination: api.FlowEndpointData{},
				ActionFlag:  api.ActionFlagAllow,
			}, publicNetworkFlowType),
			Entry("Hep - Unsupported", calicores.IngressTraffic, api.Flow{
				Reporter:    "dst",
				Source:      api.FlowEndpointData{Type: api.EndpointTypeHep},
				Destination: api.FlowEndpointData{},
				ActionFlag:  api.ActionFlagAllow,
			}, unsupportedFlowType),
		)
	})
})
