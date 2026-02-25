// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package engine

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/lma/pkg/api"
	calres "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	enginedata "github.com/projectcalico/calico/policy-recommendation/pkg/engine/testdata"
	"github.com/projectcalico/calico/policy-recommendation/pkg/types"
	testutils "github.com/projectcalico/calico/policy-recommendation/tests/utils"
	"github.com/projectcalico/calico/policy-recommendation/utils"
)

const (
	testDataFile   = "../../tests/data/flows.json"
	timeNowRFC3339 = "2022-11-30T09:01:38Z"
)

var (
	protocolTCP  = numorstring.ProtocolFromString("TCP")
	protocolUDP  = numorstring.ProtocolFromString("UDP")
	protocolICMP = numorstring.ProtocolFromString("ICMP")
)

type mockRealClock struct{}

func (mockRealClock) NowRFC3339() string { return timeNowRFC3339 }

var mrc mockRealClock

var _ = DescribeTable("processFlow",
	func(rec *recommendation, flow *api.Flow, expectedEgress, expectedIngress engineRules) {
		rec.processFlow(flow)

		Expect(rec.egress.size).To(Equal(expectedEgress.size))
		for key, val := range rec.egress.egressToDomainRules {
			Expect(expectedEgress.egressToDomainRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.egressToServiceRules {
			Expect(expectedEgress.egressToServiceRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.namespaceRules {
			Expect(expectedEgress.namespaceRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.networkSetRules {
			Expect(expectedEgress.networkSetRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.privateNetworkRules {
			Expect(expectedEgress.privateNetworkRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.publicNetworkRules {
			Expect(expectedEgress.publicNetworkRules).To(HaveKeyWithValue(key, val))
		}

		Expect(rec.ingress.size).To(Equal(expectedIngress.size))
		for key, val := range rec.ingress.egressToDomainRules {
			Expect(expectedIngress.egressToDomainRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.egressToServiceRules {
			Expect(expectedIngress.egressToServiceRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.namespaceRules {
			Expect(expectedIngress.namespaceRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.networkSetRules {
			Expect(expectedIngress.networkSetRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.privateNetworkRules {
			Expect(expectedIngress.privateNetworkRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.publicNetworkRules {
			Expect(expectedIngress.publicNetworkRules).To(HaveKeyWithValue(key, val))
		}
	},
	Entry("egress-to-public-domain",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "net",
				Domains:   "www.mydomain.com",
				Name:      "pub",
				Namespace: "",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			egressToDomainRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "",
					protocol:  protocolTCP,
					port:      numorstring.Port{MinPort: 8081, MaxPort: 8081},
				}: {
					Action:    v3.Allow,
					Domains:   []string{"www.mydomain.com"},
					Namespace: "",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			publicNetworkRules: map[engineRuleKey]*types.FlowLogData{},
			size:               1,
		},
		engineRules{},
	),
	Entry("egress-to-service",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:        "net",
				Name:        "pub",
				Namespace:   "",
				ServiceName: "some-public-service",
				Port:        getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			egressToServiceRules: map[engineRuleKey]*types.FlowLogData{
				{
					name:      "some-public-service",
					namespace: "",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Name:      "some-public-service",
					Namespace: "",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-local-service",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:        "wep",
				Name:        "my-service.namespace2",
				Namespace:   "namespace2",
				ServiceName: "my-service.namespace2.svc.cluster.local",
				Port:        getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace2",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Name:      "",
					Namespace: "namespace2",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-namespace-allow",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace2",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace2",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Name:      "",
					Namespace: "namespace2",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-namespace-pass",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),

		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace2",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace2",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Name:      "",
					Namespace: "namespace2",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-intra-namespace-allow",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace1",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Name:      "",
					Namespace: "namespace1",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-intra-namespace-pass",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1a-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1b-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace1",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Pass,
					Name:      "",
					Namespace: "namespace1",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "ns",
				Name:      "netset-1-*",
				Namespace: "namespace2",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					name:      "netset-1-*",
					namespace: "namespace2",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Name:      "netset-1-*",
					Namespace: "namespace2",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-global-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type: "ns",
				Name: "global-netset-1-*",
				Port: getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					global:   true,
					name:     "global-netset-1-*",
					protocol: protocolTCP,
				}: {
					Action:    v3.Allow,
					Global:    true,
					Name:      "global-netset-1-*",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-private-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type: "net",
				Name: "pvt",
				Port: getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			privateNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: protocolTCP,
				}: {
					Action:    v3.Allow,
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("egress-to-public-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "src",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type: "net",
				Name: "pub",
				Port: getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{
			publicNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: protocolTCP,
				}: {
					Action:    v3.Allow,
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("ingress-from-namespace-allow",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-2-*",
				Namespace: "namespace2",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace2",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Namespace: "namespace2",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("ingress-from-namespace-pass",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-2-*",
				Namespace: "namespace2",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace2",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Namespace: "namespace2",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("ingress-from-intra-namespace-pass",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-2-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace1",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Namespace: "namespace1",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("ingress-from-intra-namespace-pass",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-2-*",
				Namespace: "namespace1",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace1",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Pass,
					Namespace: "namespace1",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("ingress-from-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type:      "ns",
				Name:      "networkset-1-*",
				Namespace: "namespace2",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					name:      "networkset-1-*",
					namespace: "namespace2",
					protocol:  protocolTCP,
				}: {
					Action:    v3.Allow,
					Name:      "networkset-1-*",
					Namespace: "namespace2",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("ingress-from-global-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type: "ns",
				Name: "global-networkset-1-*",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					global:   true,
					name:     "global-networkset-1-*",
					protocol: protocolTCP,
				}: {
					Action:    v3.Allow,
					Global:    true,
					Name:      "global-networkset-1-*",
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("ingress-from-private-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type: "net",
				Name: "pvt",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			privateNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: protocolTCP,
				}: {
					Action:    v3.Allow,
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("ingress-from-public-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		&api.Flow{
			Reporter: "dst",
			Source: api.FlowEndpointData{
				Type: "net",
				Name: "pub",
			},
			Destination: api.FlowEndpointData{
				Type:      "wep",
				Name:      "pod-1-*",
				Namespace: "namespace1",
				Port:      getPtrUint16(8081),
			},
			ActionFlag: 1,
			Proto:      getPtrUint8(6),
		},
		engineRules{},
		engineRules{
			publicNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: protocolTCP,
				}: {
					Action:    v3.Allow,
					Protocol:  protocolTCP,
					Ports:     []numorstring.Port{{MinPort: 8081, MaxPort: 8081}},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
)

var _ = DescribeTable("buildRules",
	func(rec *recommendation, dir calres.DirectionType, rules []v3.Rule, expectedEgress, expectedIngress engineRules) {
		rec.buildRules(dir, rules)

		Expect(rec.egress.size).To(Equal(expectedEgress.size))
		for key, val := range rec.egress.egressToDomainRules {
			Expect(expectedEgress.egressToDomainRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.egressToServiceRules {
			Expect(expectedEgress.egressToServiceRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.namespaceRules {
			Expect(expectedEgress.namespaceRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.networkSetRules {
			Expect(expectedEgress.networkSetRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.privateNetworkRules {
			Expect(expectedEgress.privateNetworkRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.egress.publicNetworkRules {
			Expect(expectedEgress.publicNetworkRules).To(HaveKeyWithValue(key, val))
		}

		Expect(rec.ingress.size).To(Equal(expectedIngress.size))
		Expect(rec.ingress.egressToDomainRules).To(HaveLen(0))
		Expect(rec.ingress.egressToServiceRules).To(HaveLen(0))
		for key, val := range rec.ingress.namespaceRules {
			Expect(expectedIngress.namespaceRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.networkSetRules {
			Expect(expectedIngress.networkSetRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.privateNetworkRules {
			Expect(expectedIngress.privateNetworkRules).To(HaveKeyWithValue(key, val))
		}
		for key, val := range rec.ingress.publicNetworkRules {
			Expect(expectedIngress.publicNetworkRules).To(HaveKeyWithValue(key, val))
		}
	},
	Entry("build-egress-to-domains",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Domains: []string{"www.my-domain1.com", "my-domain2.com"},
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.EgressToDomainScope),
					},
				},
			},
		},
		engineRules{
			egressToDomainRules: map[engineRuleKey]*types.FlowLogData{
				{
					name:      "",
					namespace: "",
					protocol:  numorstring.ProtocolFromInt(6),
					port:      numorstring.Port{MinPort: 80, MaxPort: 80},
				}: {
					Action:    v3.Allow,
					Domains:   []string{"www.my-domain1.com", "my-domain2.com"},
					Name:      "",
					Namespace: "",
					Protocol:  numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			publicNetworkRules: map[engineRuleKey]*types.FlowLogData{},
			size:               1,
		},
		engineRules{},
	),
	Entry("build-egress-to-service",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Services: &v3.ServiceMatch{
						Name: "external-service",
					},
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "external-service",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.EgressToServiceScope),
					},
				},
			},
		},
		engineRules{
			egressToServiceRules: map[engineRuleKey]*types.FlowLogData{
				{
					name:     "external-service",
					protocol: numorstring.ProtocolFromInt(6),
				}: {
					Action:   v3.Allow,
					Name:     "external-service",
					Protocol: numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("build-egress-to-namespace-allow",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "pod-2-*",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
					},
				},
			},
		},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace2",
					protocol:  numorstring.ProtocolFromInt(6),
				}: {
					Action:    v3.Allow,
					Namespace: "namespace2",
					Protocol:  numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("build-egress-to-namespace-pass",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Pass,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace1'",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "pod-2-*",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace1",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
					},
				},
			},
		},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace1",
					protocol:  numorstring.ProtocolFromInt(6),
				}: {
					Action:    v3.Pass,
					Namespace: "namespace1",
					Protocol:  numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("build-egress-to-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "networkset-1",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					name:      "networkset-1",
					namespace: "namespace2",
					protocol:  numorstring.ProtocolFromInt(6),
				}: {
					Action:    v3.Allow,
					Name:      "networkset-1",
					Namespace: "namespace2",
					Protocol:  numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("build-egress-to-global-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "global()",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "global-networkset-1",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					global:   true,
					name:     "global-networkset-1",
					protocol: numorstring.ProtocolFromInt(6),
				}: {
					Action:   v3.Allow,
					Global:   true,
					Name:     "global-networkset-1",
					Protocol: numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("build-egress-to-private-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
		},
		engineRules{
			privateNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: numorstring.ProtocolFromInt(6),
				}: {
					Action:   v3.Allow,
					Protocol: numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("build-egress-to-public-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), true, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.EgressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
		},
		engineRules{
			publicNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: numorstring.ProtocolFromInt(6),
				}: {
					Action:   v3.Allow,
					Protocol: numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
		engineRules{},
	),
	Entry("build-ingress-from-namespace",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.IngressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "pod-2-*",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
					},
				},
			},
		},
		engineRules{},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace2",
					protocol:  numorstring.ProtocolFromInt(6),
				}: {
					Action:    v3.Allow,
					Namespace: "namespace2",
					Protocol:  numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("build-ingress-from-intra-namespace",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.IngressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace1'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "pod-2-*",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace1",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
					},
				},
			},
		},
		engineRules{},
		engineRules{
			namespaceRules: map[engineRuleKey]*types.FlowLogData{
				{
					namespace: "namespace1",
					protocol:  numorstring.ProtocolFromInt(6),
				}: {
					Action:    v3.Allow,
					Namespace: "namespace1",
					Protocol:  numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("build-ingress-from-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.IngressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					Selector:          fmt.Sprintf("projectcalico.org/name == 'networkset-1' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "networkset-1",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		},
		engineRules{},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					name:      "networkset-1",
					namespace: "namespace2",
					protocol:  numorstring.ProtocolFromInt(6),
				}: {
					Action:    v3.Allow,
					Name:      "networkset-1",
					Namespace: "namespace2",
					Protocol:  numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("build-ingress-from-global-networkset",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.IngressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source: v3.EntityRule{
					NamespaceSelector: "global()",
					Selector:          fmt.Sprintf("projectcalico.org/name == 'global-networkset-1' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "global-networkset-1",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace1",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		},
		engineRules{},
		engineRules{
			networkSetRules: map[engineRuleKey]*types.FlowLogData{
				{
					global:   true,
					name:     "global-networkset-1",
					protocol: numorstring.ProtocolFromInt(6),
				}: {
					Action:   v3.Allow,
					Global:   true,
					Name:     "global-networkset-1",
					Protocol: numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("build-ingress-from-private-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.IngressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
		},
		engineRules{},
		engineRules{
			privateNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: numorstring.ProtocolFromInt(6),
				}: {
					Action:   v3.Allow,
					Protocol: numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
	Entry("build-ingress-from-public-network",
		newRecommendation("", "namespace1", time.Duration(0), time.Duration(0), false, "svc.cluster.local", &v3.StagedNetworkPolicy{}, mrc),
		calres.IngressTraffic,
		[]v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: protocolFromInt(uint8(6)),
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
		},
		engineRules{},
		engineRules{
			publicNetworkRules: map[engineRuleKey]*types.FlowLogData{
				{
					protocol: numorstring.ProtocolFromInt(6),
				}: {
					Action:   v3.Allow,
					Protocol: numorstring.ProtocolFromInt(6),
					Ports: []numorstring.Port{
						{MinPort: 80, MaxPort: 80},
					},
					Timestamp: "2022-11-30T09:01:38Z",
				},
			},
			size: 1,
		},
	),
)

func protocolFromInt(i uint8) *numorstring.Protocol {
	p := numorstring.ProtocolFromInt(i)
	return &p
}

var _ = Describe("processFlow", func() {
	const serviceNameSuffix = "svc.cluster.local"

	var (
		rec *recommendation

		flowData []api.Flow

		name          = "test_name"
		namespace     = "namespace1"
		interval      = time.Duration(150 * time.Second)
		stabilization = time.Duration(10 * time.Minute)

		clock = mrc
	)

	BeforeEach(func() {
		rec = newRecommendation(
			name,
			namespace,
			interval,
			stabilization,
			false,
			serviceNameSuffix,
			&v3.StagedNetworkPolicy{},
			clock,
		)

		err := testutils.LoadData(testDataFile, &flowData)
		Expect(err).To(BeNil())
	})

	It("Test valid recommendation rule generation", func() {
		for _, data := range flowData {
			rec.processFlow(&data)
		}

		Expect(len(rec.egress.namespaceRules)).To(Equal(2))
		Expect(rec.egress.namespaceRules[engineRuleKey{namespace: "namespace1", protocol: protocolTCP}]).
			To(Equal(&types.FlowLogData{Action: v3.Allow, Namespace: "namespace1", Protocol: protocolTCP, Ports: ports1, Timestamp: "2022-11-30T09:01:38Z"}))
		Expect(rec.egress.namespaceRules[engineRuleKey{namespace: "namespace2", protocol: protocolTCP}]).
			To(Equal(&types.FlowLogData{Action: v3.Allow, Namespace: "namespace2", Protocol: protocolTCP, Ports: ports2, Timestamp: "2022-11-30T09:01:38Z"}))

		Expect(len(rec.ingress.namespaceRules)).To(Equal(2))
		Expect(rec.ingress.namespaceRules[engineRuleKey{namespace: "namespace1", protocol: protocolTCP}]).
			To(Equal(&types.FlowLogData{Action: v3.Allow, Namespace: "namespace1", Protocol: protocolTCP, Ports: ports1, Timestamp: "2022-11-30T09:01:38Z"}))
		Expect(rec.ingress.namespaceRules[engineRuleKey{namespace: "namespace2", protocol: protocolTCP}]).
			To(Equal(&types.FlowLogData{Action: v3.Allow, Namespace: "namespace2", Protocol: protocolTCP, Ports: ports1, Timestamp: "2022-11-30T09:01:38Z"}))
	})

	It("Test flow with ActionFlagDeny", func() {
		flow := &api.Flow{
			ActionFlag: api.ActionFlagDeny,
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))
	})

	It("Test flow with ActionFlagEndOfTierDeny", func() {
		flow := &api.Flow{
			ActionFlag: api.ActionFlagEndOfTierDeny,
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))
	})

	It("Test 'src' reported flow that matches", func() {
		namespace := "namespace1"
		flow := &api.Flow{
			ActionFlag: api.ActionFlagAllow,
			Reporter:   api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.FlowLogEndpointTypeWEP,
				Namespace: namespace,
			},
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))
	})

	It("Test 'src' reported flow that is not WEP", func() {
		namespace := "namespace1"
		flow := &api.Flow{
			ActionFlag: api.ActionFlagAllow,
			Reporter:   api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.FlowLogEndpointTypeHEP,
				Namespace: namespace,
			},
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))
	})

	It("Test 'src' reported flow where the source flow is not equal to the rec recommendation namespace", func() {
		namespace := "not-the-recommendation-namespace"
		flow := &api.Flow{
			ActionFlag: api.ActionFlagAllow,
			Reporter:   api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.FlowLogEndpointTypeWEP,
				Namespace: namespace,
			},
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))
	})

	It("Test 'dst' reported flow that matches", func() {
		namespace := "namespace1"
		flow := &api.Flow{
			ActionFlag: api.ActionFlagAllow,
			Reporter:   api.ReporterTypeDestination,
			Destination: api.FlowEndpointData{
				Type:      api.FlowLogEndpointTypeWEP,
				Namespace: namespace,
			},
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))
	})

	It("Test 'dst' reported flow that is not WEP", func() {
		namespace := "namespace1"
		flow := &api.Flow{
			ActionFlag: api.ActionFlagAllow,
			Reporter:   api.ReporterTypeDestination,
			Destination: api.FlowEndpointData{
				Type:      api.FlowLogEndpointTypeHEP,
				Namespace: namespace,
			},
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))
	})

	It("Test 'dst' reported flow where the source flow is not equal to the rec recommendation namespace", func() {
		namespace := "not-the-recommendation-namespace"
		flow := &api.Flow{
			ActionFlag: api.ActionFlagAllow,
			Reporter:   api.ReporterTypeDestination,
			Destination: api.FlowEndpointData{
				Type:      api.FlowLogEndpointTypeWEP,
				Namespace: namespace,
			},
		}

		rec.processFlow(flow)
		Expect(rec.egress.size).To(Equal(0))
		Expect(rec.ingress.size).To(Equal(0))

	})
})

var _ = Describe("update", func() {
	const (
		serviceNameSuffix = "svc.cluster.local"
		tier              = "test_tier"
	)

	var (
		flowsEgress, flowsIngress []*api.Flow
		snp                       *v3.StagedNetworkPolicy
		rec                       *recommendation
	)

	BeforeEach(func() {
		data := []api.Flow{}
		err := testutils.LoadData("./testdata/flows_egress.json", &data)
		Expect(err).To(BeNil())

		for i := range data {
			flowsEgress = append(flowsEgress, &data[i])
		}

		data = []api.Flow{}
		err = testutils.LoadData("./testdata/flows_ingress.json", &data)
		Expect(err).To(BeNil())

		for i := range data {
			flowsIngress = append(flowsIngress, &data[i])
		}
		owner := metav1.OwnerReference{
			APIVersion:         "projectcalico.org/v3",
			Kind:               "PolicyRecommendationScope",
			Name:               "default",
			UID:                "orikr-9df4d-0k43m",
			Controller:         getPtrBool(true),
			BlockOwnerDeletion: getPtrBool(false),
		}
		snp = calres.NewStagedNetworkPolicy(
			utils.GenerateRecommendationName(tier, "name1", func() string { return "xv5fb" }),
			"namespace1",
			tier,
			owner.UID,
		)
		// rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, mrc)
	})

	It("should inject egress-to-domain into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)
		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Domains: []string{"www.new-domain.io"},
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.EgressToDomainScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
					Labels: uniquelabels.Make(map[string]string{
						"projectcalico.org/namespace": "namespace1",
						"projectcalico.org/name":      "pod-1-1",
					}),
				},
				Destination: api.FlowEndpointData{
					Type:    api.FlowLogEndpointTypeNetwork,
					Name:    api.FlowLogNetworkPublic,
					Domains: "www.new-domain.io",
					Port:    &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-domain into existing rules", func() {
		// Add existing rules to the recommendation.
		snp.Spec.Egress = append(snp.Spec.Egress, enginedata.EgressToDomainRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Domains: []string{"tigera.io"},
					Ports: []numorstring.Port{
						{
							MinPort: 1,
							MaxPort: 99,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Thu, 30 Nov 2022 12:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.EgressToDomainScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Domains: []string{"www.new-domain.io"},
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.EgressToDomainScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Domains: []string{"calico.org"},
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.EgressToDomainScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Domains: []string{"kubernetes.io"},
					Ports: []numorstring.Port{
						{
							MinPort: 5,
							MaxPort: 59,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 13:04:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.EgressToDomainScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
					Labels: uniquelabels.Make(map[string]string{
						"projectcalico.org/namespace": "namespace1",
						"projectcalico.org/name":      "pod-1-1",
					}),
				},
				Destination: api.FlowEndpointData{
					Type:    api.FlowLogEndpointTypeNetwork,
					Name:    api.FlowLogNetworkPublic,
					Domains: "www.new-domain.io",
					Port:    &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(4))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("egress-to-domain diffs: %s", cmp.Diff(snp.Spec.Egress, expectedRules))
		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-namespace into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-2-1",
					Namespace: "namespace2",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-namespace into existing rules", func() {
		snp.Spec.Egress = append(snp.Spec.Egress, enginedata.EgressNamespaceRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Pass,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace1'",
					Ports: []numorstring.Port{
						{
							MinPort: 5,
							MaxPort: 59,
						},
						{
							MinPort: 22,
							MaxPort: 22,
						},
						{
							MinPort: 44,
							MaxPort: 56,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Thu, 30 Nov 2022 06:04:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace1",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'new-namespace'",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "new-namespace",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Pass,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace1'",
					Ports: []numorstring.Port{
						{
							MinPort: 5,
							MaxPort: 59,
						},
						{
							MinPort: 22,
							MaxPort: 22,
						},
						{
							MinPort: 44,
							MaxPort: 56,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:04:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace1",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:05:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace3'",
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:05:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace3",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-new",
					Namespace: "new-namespace",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(5))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Egress))

		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-networkset into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'netset-2' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'new-netset-namespace'",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "netset-2",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "new-netset-namespace",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeNetworkSet,
					Name:      "netset-2",
					Namespace: "new-netset-namespace",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-networkset into existing rules", func() {
		snp.Spec.Egress = append(snp.Spec.Egress, enginedata.EgressNetworkSetRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'netset-3' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'namespace3'",
					Ports: []numorstring.Port{
						{
							MinPort: 1,
							MaxPort: 99,
						},
						{
							MinPort: 3,
							MaxPort: 3,
						},
						{
							MinPort: 24,
							MaxPort: 35,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "netset-3",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace3",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'new-netset' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'new-netset-namespace'",
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "new-netset",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "new-netset-namespace",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'global-netset-2' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "global()",
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "global-netset-2",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'netset-2' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "netset-2",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeNetworkSet,
					Name:      "new-netset",
					Namespace: "new-netset-namespace",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(4))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Egress))

		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-private into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type: api.FlowLogEndpointTypeNetwork,
					Name: api.FlowLogNetworkPrivate,
					Port: &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-private into existing rules", func() {
		snp.Spec.Egress = append(snp.Spec.Egress, enginedata.EgressPrivateNetworkRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
					Ports: []numorstring.Port{
						{
							MinPort: 1,
							MaxPort: 99,
						},
						{
							MinPort: 3,
							MaxPort: 3,
						},
						{
							MinPort: 24,
							MaxPort: 35,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type: api.FlowLogEndpointTypeNetwork,
					Name: api.FlowLogNetworkPrivate,
					Port: &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(2))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Egress))

		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-public into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type: api.FlowLogEndpointTypeNetwork,
					Name: api.FlowLogNetworkPublic,
					Port: &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	It("should inject egress-to-public into existing rules", func() {
		snp.Spec.Egress = append(snp.Spec.Egress, enginedata.EgressPublicNetworkRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:      v3.Allow,
				Protocol:    &protocolICMP,
				Source:      v3.EntityRule{},
				Destination: v3.EntityRule{},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},

			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 5,
							MaxPort: 59,
						},
						{
							MinPort: 22,
							MaxPort: 22,
						},
						{
							MinPort: 44,
							MaxPort: 56,
						},
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Namespace: "namespace1",
				},
				Destination: api.FlowEndpointData{
					Type: api.FlowLogEndpointTypeNetwork,
					Name: api.FlowLogNetworkPublic,
					Port: &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Egress)).To(Equal(3))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Egress))

		Expect(snp.Spec.Egress).To(Equal(expectedRules))
	})

	// Ingress rules
	It("should inject ingress-from-namespace into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'new-namespace'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "new-namespace",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "new-pod",
					Namespace: "new-namespace",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})

	It("should inject ingress-from-namespace into existing rules", func() {
		snp.Spec.Ingress = append(snp.Spec.Ingress, enginedata.IngressNamespaceRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 5,
							MaxPort: 59,
						},
						{
							MinPort: 22,
							MaxPort: 22,
						},
						{
							MinPort: 44,
							MaxPort: 56,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Thu, 30 Nov 2022 06:04:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'new-namespace'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "new-namespace",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 1,
							MaxPort: 99,
						},
						{
							MinPort: 3,
							MaxPort: 3,
						},
						{
							MinPort: 24,
							MaxPort: 35,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:04:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace3'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:05:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace3",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source: v3.EntityRule{
					NamespaceSelector: "projectcalico.org/name == 'namespace4'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:05:05 PST",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace4",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NamespaceScope),
						fmt.Sprintf("%s/warnings", calres.PolicyRecKeyName):    "NonServicePortsAndProtocol",
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "new-pod",
					Namespace: "new-namespace",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(5))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Ingress))

		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})

	It("should inject ingress-from-networkset into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'new-netset' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'new-netset-namespace'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "new-netset",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "new-netset-namespace",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeNetworkSet,
					Name:      "new-netset",
					Namespace: "new-netset-namespace",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})

	It("should inject ingress-from-networkset into existing rules", func() {
		snp.Spec.Ingress = append(snp.Spec.Ingress, enginedata.IngressNetworkSetRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'netset-3' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'namespace3'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 1,
							MaxPort: 99,
						},
						{
							MinPort: 3,
							MaxPort: 3,
						},
						{
							MinPort: 24,
							MaxPort: 35,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "netset-3",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace3",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'new-netset' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'new-netset-namespace'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "new-netset",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "new-netset-namespace",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'global-netset-2' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "global()",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "global-netset-2",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source: v3.EntityRule{
					Selector:          fmt.Sprintf("projectcalico.org/name == 'netset-2' && projectcalico.org/kind == '%s'", string(calres.NetworkSetScope)),
					NamespaceSelector: "projectcalico.org/name == 'namespace2'",
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/name", calres.PolicyRecKeyName):        "netset-2",
						fmt.Sprintf("%s/namespace", calres.PolicyRecKeyName):   "namespace2",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.NetworkSetScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeNetworkSet,
					Name:      "new-netset",
					Namespace: "new-netset-namespace",
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(4))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Ingress))

		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})

	It("should inject ingress-from-private into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type: api.EndpointTypeNet,
					Name: api.FlowLogNetworkPrivate,
					IPs:  []net.IP{*net.ParseIP("10.10.10.10")},
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})

	It("should inject ingress-from-private into existing rules", func() {
		snp.Spec.Ingress = append(snp.Spec.Ingress, enginedata.IngressPrivateNetworkRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source: v3.EntityRule{
					Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source: v3.EntityRule{
					Nets: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
				},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 88,
							MaxPort: 89,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PrivateNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type: api.EndpointTypeNet,
					Name: api.FlowLogNetworkPrivate,
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(2))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Ingress))

		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})

	It("should inject ingress-from-public into empty rules", func() {
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type: api.EndpointTypeNet,
					Name: api.FlowLogNetworkPublic,
					IPs:  []net.IP{*net.ParseIP("8.8.8.8")},
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(1))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})

	It("should inject ingress-from-public into existing rules", func() {
		snp.Spec.Ingress = append(snp.Spec.Ingress, enginedata.IngressPublicNetworkRulesData...)
		rec = newRecommendation("name1", "namespace1", time.Duration(0), time.Duration(0), true, serviceNameSuffix, snp, mrc)

		expectedRules := []v3.Rule{
			{
				Action:      v3.Allow,
				Protocol:    &protocolICMP,
				Source:      v3.EntityRule{},
				Destination: v3.EntityRule{},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolTCP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 5,
							MaxPort: 59,
						},
						{
							MinPort: 22,
							MaxPort: 22,
						},
						{
							MinPort: 44,
							MaxPort: 56,
						},
						{
							MinPort: 80,
							MaxPort: 80,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "2022-11-30T09:01:38Z",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
			{
				Action:   v3.Allow,
				Protocol: &protocolUDP,
				Source:   v3.EntityRule{},
				Destination: v3.EntityRule{
					Ports: []numorstring.Port{
						{
							MinPort: 8080,
							MaxPort: 8081,
						},
					},
				},
				Metadata: &v3.RuleMetadata{
					Annotations: map[string]string{
						fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName): "Wed, 29 Nov 2022 14:30:05 PST",
						fmt.Sprintf("%s/scope", calres.PolicyRecKeyName):       string(calres.PublicNetworkScope),
					},
				},
			},
		}

		flows := []*api.Flow{
			{
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeDestination,
				Proto:      &[]uint8{6}[0],
				Source: api.FlowEndpointData{
					Type: api.EndpointTypeNet,
					Name: api.FlowLogNetworkPublic,
				},
				Destination: api.FlowEndpointData{
					Type:      api.FlowLogEndpointTypeWEP,
					Name:      "pod-1-1",
					Namespace: "namespace1",
					Port:      &[]uint16{80}[0],
				},
			},
		}

		updated := rec.update(flows, snp)
		Expect(updated).To(BeTrue())

		Expect(len(snp.Spec.Ingress)).To(Equal(3))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/status", calres.PolicyRecKeyName), calres.LearningStatus))
		Expect(snp.Annotations).To(HaveKeyWithValue(fmt.Sprintf("%s/lastUpdated", calres.PolicyRecKeyName), "2022-11-30T09:01:38Z"))
		log.Infof("rules: %s", prettyRules(snp.Spec.Ingress))

		Expect(snp.Spec.Ingress).To(Equal(expectedRules))
	})
})

var _ = DescribeTable("lessPorts",
	func(a, b []numorstring.Port, expected int) {
		Expect(lessPorts(a, b)).To(Equal(expected))
	},
	Entry("less-ports-1",
		[]numorstring.Port{{MinPort: 0, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		-1,
	),
	Entry("less-ports-2",
		[]numorstring.Port{{MinPort: 1, MaxPort: 1, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		-1,
	),
	Entry("less-ports-3",
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 3, PortName: "A"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		-1,
	),
	Entry("less-ports-4",
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		0,
	),
	Entry("less-ports-5",
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 5, PortName: "C"}},
		1,
	),
	Entry("less-ports-6",
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "A"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		-1,
	),
	Entry("less-ports-7",
		[]numorstring.Port{{MinPort: 1, MaxPort: 2, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		[]numorstring.Port{{MinPort: 1, MaxPort: 1, PortName: "A"}, {MinPort: 3, MaxPort: 4, PortName: "B"}, {MinPort: 5, MaxPort: 6, PortName: "C"}},
		1,
	),
)

var _ = DescribeTable("lessStringArrays",
	func(a, b []string, expected bool) {
		Expect(lessStringArrays(a, b)).To(Equal(expected))
	},
	Entry("less-string-arrays-1",
		[]string{"apple"},
		[]string{"Apple"},
		false,
	),
	Entry("less-string-arrays-2",
		[]string{"apple", "banana"},
		[]string{"apple", "banana", "cherry"},
		true,
	),
	Entry("less-string-arrays-3",
		[]string{"apple", "banana", "cherry"},
		[]string{"apple", "banana", "cherry"},
		false,
	),
	Entry("less-string-arrays-4",
		[]string{"apple", "banana", "cherry"},
		[]string{"apple", "banana", "apple"},
		false,
	),
	Entry("less-string-arrays-5",
		[]string{"apple", "banana", "cherry"},
		[]string{"banana", "cherry", "date"},
		true,
	),
	Entry("less-string-arrays-6",
		[]string{"grape", "kiwi", "mango"},
		[]string{"grape", "kiwi", "cherry"},
		false,
	),
)

var (
	ports1 = []numorstring.Port{
		{
			MinPort: 443,
			MaxPort: 443,
		},
	}

	ports2 = []numorstring.Port{
		{
			MinPort: 8080,
			MaxPort: 8080,
		},
		{
			MinPort: 5432,
			MaxPort: 5432,
		},
	}
)

// prettyRules logs a pretty version of map[string]string.
func prettyRules(rules []v3.Rule) string {
	value, err := json.MarshalIndent(rules, "", " ")
	Expect(err).NotTo(HaveOccurred())

	return string(value)
}

func getPtrBool(f bool) *bool {
	return &f
}

func getPtrUint8(i uint8) *uint8 {
	return &i
}

func getPtrUint16(i uint16) *uint16 {
	return &i
}
