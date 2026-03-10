// Copyright (c) 2019-2022 Tigera, Inc. All rights reserved.
package policyrec_test

import (
	"fmt"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lma/pkg/api"
)

var (
	port80   = uint16(80)
	port443  = uint16(443)
	port8080 = uint16(8080)
	port5432 = uint16(5432)
	port53   = uint16(53)

	protoTCP   = api.ProtoTCP
	protoTCPNS = numorstring.ProtocolFromString("TCP")
	protoUDP   = api.ProtoUDP
	protoUDPNS = numorstring.ProtocolFromString("UDP")

	// Namespaces
	globalNamespace = ""
	namespace1      = "namespace1"
	namespace2      = "namespace2"
	namespace3      = "namespace3"

	// Profiles
	namespace1DefaultAllowProfile, _ = api.PolicyHitFromFlowLogPolicyString("0|__PROFILE__|__PROFILE__.kns.namespace1|allow|0")
	namespace2DefaultAllowProfile, _ = api.PolicyHitFromFlowLogPolicyString("0|__PROFILE__|__PROFILE__.kns.namespace2|allow|0")
	namespace3DefaultAllowProfile, _ = api.PolicyHitFromFlowLogPolicyString("0|__PROFILE__|__PROFILE__.kns.namespace3|allow|0")

	// Endpoints
	emptyEndpoint = ""
	pod1Aggr      = "pod-1-*"
	pod1          = "pod-1"
	pod2Aggr      = "pod-2-*"
	pod2          = "pod-2"
	pod3Aggr      = "pod-3-*"
	pod3          = "pod-3"
	pod4Rs1Aggr   = "pod-4-rs-1-*"
	pod4Rs2Aggr   = "pod-4-rs-2-*"
	ns1           = "netset-1"
	ns1Aggr       = "netset-1"
	gns1          = "gns-1"
	gns1Aggr      = "gns-1"

	// Labels
	pod1LabelsBlue = uniquelabels.Make(map[string]string{
		"name":      pod1,
		"namespace": namespace1,
		"job-name":  "nagging",
		"color":     "blue",
	})
	pod1LabelsRed = uniquelabels.Make(map[string]string{
		"name":      pod1,
		"namespace": namespace1,
		"job-name":  "badger",
		"color":     "red",
	})
	pod2Labels = uniquelabels.Make(map[string]string{
		"name":              pod2,
		"namespace":         namespace1,
		"pod-template-hash": "abcdef",
	})
	pod3Labels = uniquelabels.Make(map[string]string{
		"pod-name":                 pod3,
		"pod-namespace":            namespace2,
		"controller-revision-hash": "xyz123",
	})
	pod4Rs1Labels = uniquelabels.Make(map[string]string{
		"controller-revision-hash": "rs1",
	})
	pod4Rs2Labels = uniquelabels.Make(map[string]string{
		"controller-revision-hash": "rs2",
	})
	ns1Labels = uniquelabels.Make(map[string]string{
		"name":      ns1,
		"namespace": namespace1,
	})
	gns1Labels = uniquelabels.Make(map[string]string{
		"name": gns1,
	})

	// Flow Endpoints - source
	flowEndpointNamespace1Pod1BlueSource = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod1Aggr,
		Namespace: namespace1,
		Labels:    pod1LabelsBlue,
	}
	flowEndpointNamespace1Pod1RedSource = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod1Aggr,
		Namespace: namespace1,
		Labels:    pod1LabelsRed,
	}
	flowEndpointNamespace1Pod2Source = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod2Aggr,
		Namespace: namespace1,
		Labels:    pod2Labels,
	}
	flowEndpointGlobalNamespaceGlobalNetworkSet1Source = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeNetworkSet,
		Name:      gns1Aggr,
		Namespace: globalNamespace,
		Labels:    gns1Labels,
	}
	flowEndpointNamespace3Pod4Rs1Source = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod4Rs1Aggr,
		Namespace: namespace3,
		Labels:    pod4Rs1Labels,
	}
	flowEndpointNamespace3Pod4Rs2Source = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod4Rs2Aggr,
		Namespace: namespace3,
		Labels:    pod4Rs2Labels,
	}

	// Flow Endpoints - destination (and traffic)
	flowEndpointNamespace1Pod2DestinationTCP443 = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod2Aggr,
		Namespace: namespace1,
		Labels:    pod2Labels,
		Port:      &port443,
	}
	flowEndpointNamespace2Pod3DestinationTCP8080 = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod3Aggr,
		Namespace: namespace2,
		Labels:    pod3Labels,
		Port:      &port8080,
	}
	flowEndpointNamespace2Pod3DestinationTCP5432 = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeWEP,
		Name:      pod3Aggr,
		Namespace: namespace2,
		Labels:    pod3Labels,
		Port:      &port5432,
	}
	flowEndpointNetworkNoNamespaceDestination53 = api.FlowEndpointData{
		Type: api.FlowLogEndpointTypeNetwork,
		Name: api.FlowLogNetworkPrivate,
		Port: &port53,
	}
	flowEndpointNamespace3NetworkSet1DestinationTCP80 = api.FlowEndpointData{
		Type:      api.FlowLogEndpointTypeNetworkSet,
		Name:      ns1Aggr,
		Namespace: namespace1,
		Labels:    ns1Labels,
		Port:      &port80,
	}

	// Flows
	// pod1 has only egress flows.
	// pod2 has both ingress and egress flows.
	// pod3 has only ingress flows.
	// pod4 has only egress flows.

	// pod1-blue -> pod2 allow port 443
	flowPod1BlueToPod2Allow443ReporterSource = api.Flow{
		Reporter:    api.ReporterTypeSource,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1BlueSource,
		Destination: flowEndpointNamespace1Pod2DestinationTCP443,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}
	flowPod1BlueToPod2Allow443ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1BlueSource,
		Destination: flowEndpointNamespace1Pod2DestinationTCP443,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}

	// pod1-blue -> external udp port 53. Only source flow.
	flowPod1BlueToExternalAllow53ReporterSource = api.Flow{
		Reporter:    api.ReporterTypeSource,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1BlueSource,
		Destination: flowEndpointNetworkNoNamespaceDestination53,
		Proto:       &protoUDP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}

	// pod1-red -> pod2 allow port 443
	flowPod1RedToPod2Allow443ReporterSource = api.Flow{
		Reporter:    api.ReporterTypeSource,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1RedSource,
		Destination: flowEndpointNamespace1Pod2DestinationTCP443,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}
	flowPod1RedToPod2Allow443ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1RedSource,
		Destination: flowEndpointNamespace1Pod2DestinationTCP443,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}

	// pod1-red -> pod3 allow port 8080 - cross namespace
	flowPod1RedToPod3Allow8080ReporterSource = api.Flow{
		Reporter:    api.ReporterTypeSource,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1RedSource,
		Destination: flowEndpointNamespace2Pod3DestinationTCP8080,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}
	flowPod1RedToPod3Allow8080ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1RedSource,
		Destination: flowEndpointNamespace2Pod3DestinationTCP8080,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace2DefaultAllowProfile},
	}

	// pod1-blue -> pod3 allow port 5432 - cross namespace
	flowPod1BlueToPod3Allow5432ReporterSource = api.Flow{
		Reporter:    api.ReporterTypeSource,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1BlueSource,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}
	flowPod1BlueToPod3Allow5432ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod1BlueSource,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace2DefaultAllowProfile},
	}

	// pod2 -> pod3 allow port 5432 - cross namespace
	flowPod2ToPod3Allow5432ReporterSource = api.Flow{
		Reporter:    api.ReporterTypeSource,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod2Source,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}
	flowPod2ToPod3Allow5432ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod2Source,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace2DefaultAllowProfile},
	}

	// pod2 -> ns1 allow port 80
	flowPod2ToNs1Allow80ReporterSource = api.Flow{
		Reporter:    api.ReporterTypeSource,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace1Pod2Source,
		Destination: flowEndpointNamespace3NetworkSet1DestinationTCP80,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace1DefaultAllowProfile},
	}

	// gns1 -> pod3 allow port 5432 - global Namespace to namespace
	flowGlobalNetworkSet1ToPod3Allow5432ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointGlobalNamespaceGlobalNetworkSet1Source,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace2DefaultAllowProfile},
	}

	// Ingress only pod4rs1 -> pod3 port 5432
	flowPod4Rs1ToPod3Allow5432ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace3Pod4Rs1Source,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace3DefaultAllowProfile},
	}

	// Ingress only pod4rs1 -> pod3 port 8080
	flowPod4Rs1ToPod3Allow8080ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace3Pod4Rs1Source,
		Destination: flowEndpointNamespace2Pod3DestinationTCP8080,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace3DefaultAllowProfile},
	}

	// Ingress only pod4rs2 -> pod3 port 5432
	flowPod4Rs2ToPod3Allow5432ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace3Pod4Rs2Source,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace3DefaultAllowProfile},
	}

	// Ingress only pod4rs2 -> pod3 port 8080
	flowPod4Rs2ToPod3Allow8080ReporterDestination = api.Flow{
		Reporter:    api.ReporterTypeDestination,
		ActionFlag:  api.ActionFlagAllow,
		Source:      flowEndpointNamespace3Pod4Rs2Source,
		Destination: flowEndpointNamespace2Pod3DestinationTCP5432,
		Proto:       &protoTCP,
		Policies:    []api.PolicyHit{namespace3DefaultAllowProfile},
	}
)

// Expected Policies
var (
	// TODO(doublek): The input flows and output policies are closely related. Need a way to better declare this
	// when writing test data.

	// Egress policy matching pod1-blue in namespace1, to pod2 port 443.
	networkPolicyNamespace1Pod1BlueToPod2 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod1,
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "name == 'pod-1' && namespace == 'namespace1' && color == 'blue'",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						Selector: "name == 'pod-2' && namespace == 'namespace1'",
						Ports:    []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Egress policy matching pod1 (both blue and red labels) in namespace1, to pod2 port 443.
	egressNetworkPolicyNamespace1Pod1ToPod2 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod1,
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "name == 'pod-1' && namespace == 'namespace1'",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						Selector: "name == 'pod-2' && namespace == 'namespace1'",
						Ports:    []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Ingress policy matching pod2 in namespace1, from everywhere to port 443.
	ingressNetworkPolicyNamespace1Pod1ToPod2 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod2,
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "name == 'pod-2' && namespace == 'namespace1'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress},
			Egress:   []v3.Rule{},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						Selector: "name == 'pod-1' && namespace == 'namespace1'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
			},
		},
	}

	// Egress policy matching pod1-blue in namespace1, to pod2 port 443 and udp to external network port 53.
	networkPolicyNamespace1Pod1BlueToPod2AndExternalNet = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod1,
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "name == 'pod-1' && namespace == 'namespace1' && color == 'blue'",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						Selector: "name == 'pod-2' && namespace == 'namespace1'",
						Ports:    []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoUDPNS,
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port53)},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Egress policy matching pod1 in namespace1, to pod2 port 443 and pod3 port 5432 and 8080.
	networkPolicyNamespace1Pod1ToPod2AndPod3 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod1,
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "name == 'pod-1' && namespace == 'namespace1'",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						Selector: "name == 'pod-2' && namespace == 'namespace1'",
						Ports:    []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						Selector:          "pod-name == 'pod-3' && pod-namespace == 'namespace2'",
						NamespaceSelector: "projectcalico.org/name == 'namespace2'",
						Ports: []numorstring.Port{
							numorstring.SinglePort(port5432),
							numorstring.SinglePort(port8080),
						},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Ingress and egress policy matching pod2 in namespace1.
	networkPolicyNamespace1Pod2 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod2,
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "name == 'pod-2' && namespace == 'namespace1'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						Selector: "name == 'pod-1' && namespace == 'namespace1' && color == 'blue'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
			},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						Selector:          "pod-name == 'pod-3' && pod-namespace == 'namespace2'",
						NamespaceSelector: "projectcalico.org/name == 'namespace2'",
						Ports:             []numorstring.Port{numorstring.SinglePort(port5432)},
					},
				},
			},
		},
	}

	// Ingress policy matching pod3 from pod1 and pod2.
	networkPolicyNamespace1Pod3 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod3,
			Namespace: namespace2,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "pod-name == 'pod-3' && pod-namespace == 'namespace2'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress},
			Egress:   []v3.Rule{},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						Selector:          "name == 'pod-1' && namespace == 'namespace1'",
						NamespaceSelector: "projectcalico.org/name == 'namespace1'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{
							numorstring.SinglePort(port8080),
							numorstring.SinglePort(port5432),
						},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						Selector:          "name == 'pod-2' && namespace == 'namespace1'",
						NamespaceSelector: "projectcalico.org/name == 'namespace1'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port5432)},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						Selector:          "name == 'gns-1'",
						NamespaceSelector: "global()",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port5432)},
					},
				},
			},
		},
	}

	// Ingress policy matching pod3 in namespace2, from pod4 to port 5432.
	ingressNetworkPolicyToNamespace2Pod3FromPod4Port5432 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod3,
			Namespace: namespace2,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "pod-name == 'pod-3' && pod-namespace == 'namespace2'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress},
			Egress:   []v3.Rule{},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'namespace3'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port5432)},
					},
				},
			},
		},
	}

	// Ingress policy matching pod3 in namespace2, from pod4 to port 5432.
	ingressNetworkPolicyToNamespace2Pod3FromPod4Port5432And8080 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + pod3,
			Namespace: namespace2,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:     "default",
			Selector: "pod-name == 'pod-3' && pod-namespace == 'namespace2'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress},
			Egress:   []v3.Rule{},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						NamespaceSelector: "projectcalico.org/name == 'namespace3'",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{
							numorstring.SinglePort(port5432),
							numorstring.SinglePort(port8080),
						},
					},
				},
			},
		},
	}

	// Egress policy matching pod1-blue in namespace1, to pod2 port 443.
	namespaceNetworkPolicyNamespace1Pod1BlueToPod2 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace1 + "-policy",
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace1),
			Types:        []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace1),
						Ports:             []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Egress policy matching pod1 (both blue and red labels) in namespace1, to pod2 port 443.
	namespaceEgressNetworkPolicyNamespace1Pod1ToPod2 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace1 + "-policy",
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace1),
			Types:        []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace1),
						Ports:             []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Egress policy matching pod1-blue in namespace1, to pod2 port 443 and udp to external network port 53.
	namespaceNetworkPolicyNamespace1Pod1BlueToPod2AndExternalNet = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace1 + "-policy",
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace1),
			Types:        []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoUDPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: "global()",
						Ports:             []numorstring.Port{numorstring.SinglePort(port53)},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace1),
						Ports:             []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Egress policy matching pod1 in namespace1, to pod2 port 443 and pod3 port 5432 and 8080.
	namespaceNetworkPolicyNamespace1Pod1ToPod2AndPod3 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace1 + "-policy",
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace1),
			Types:        []v3.PolicyType{v3.PolicyTypeEgress},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace1),
						Ports: []numorstring.Port{
							numorstring.SinglePort(443),
						},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace2),
						Ports: []numorstring.Port{
							numorstring.SinglePort(port5432),
							numorstring.SinglePort(port8080)},
					},
				},
			},
			Ingress: []v3.Rule{},
		},
	}

	// Ingress and egress policy matching pod2 in namespace1.
	namespaceNetworkPolicyNamespace1Pod2 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace1 + "-policy",
			Namespace: namespace1,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace1),
			Types:        []v3.PolicyType{v3.PolicyTypeEgress},
			Ingress:      []v3.Rule{},
			Egress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace1),
						Ports:             []numorstring.Port{numorstring.SinglePort(port443)},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Destination: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace2),
						Ports:             []numorstring.Port{numorstring.SinglePort(port5432)},
					},
				},
			},
		},
	}

	// Ingress policy matching pod3 from pod1 and pod2.
	namespaceNetworkPolicyNamespace1Pod3 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace2 + "-policy",
			Namespace: namespace2,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace2),
			Types:        []v3.PolicyType{v3.PolicyTypeIngress},
			Egress:       []v3.Rule{},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace1),
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{
							numorstring.SinglePort(port8080),
							numorstring.SinglePort(port5432),
						},
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						NamespaceSelector: "global()",
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port5432)},
					},
				},
			},
		},
	}

	// Ingress policy matching pod3 in namespace2, from pod4 to port 5432.
	namespaceIngressNetworkPolicyToNamespace2Pod3FromPod4Port5432 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace2 + "-policy",
			Namespace: namespace2,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace2),
			Types:        []v3.PolicyType{v3.PolicyTypeIngress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace3),
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{numorstring.SinglePort(port5432)},
					},
				},
			},
			Egress: []v3.Rule{},
		},
	}

	// Ingress policy matching pod3 in namespace2, from pod4 to port 5432.
	namespaceIngressNetworkPolicyToNamespace2Pod3FromPod4Port5432And8080 = &v3.StagedNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v3.KindStagedNetworkPolicy,
			APIVersion: v3.GroupVersionCurrent,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default." + namespace2 + "-policy",
			Namespace: namespace2,
		},
		Spec: v3.StagedNetworkPolicySpec{
			Tier:         "default",
			StagedAction: v3.StagedActionSet,
			Selector:     fmt.Sprintf("projectcalico.org/namespace == '%s'", namespace2),
			Types:        []v3.PolicyType{v3.PolicyTypeIngress},
			Egress:       []v3.Rule{},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &protoTCPNS,
					Source: v3.EntityRule{
						NamespaceSelector: fmt.Sprintf("projectcalico.org/name == '%s'", namespace3),
					},
					Destination: v3.EntityRule{
						Ports: []numorstring.Port{
							numorstring.SinglePort(port5432),
							numorstring.SinglePort(port8080),
						},
					},
				},
			},
		},
	}
)
