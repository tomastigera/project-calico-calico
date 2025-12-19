package policycalc_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/lma/pkg/api"
	pipcfg "github.com/projectcalico/calico/ui-apis/pkg/pip/config"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/policycalc"
)

var (
	tier1Policy1 = &v3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier1.policy1",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:     "tier1",
			Selector: "color == 'red'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{{Action: v3.Allow}},
			Egress:   []v3.Rule{{Action: v3.Allow}},
		},
	}

	tier1Policy2 = &v3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier1.policy1",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:     "tier1",
			Selector: "color == 'blue'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{{Action: v3.Deny}},
			Egress:   []v3.Rule{{Action: v3.Deny}},
		},
	}

	tier2Policy1 = &v3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tier2.policy1",
			Namespace: "ns1",
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     "tier2",
			Selector: "color == 'purple'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{{Action: v3.Deny}},
			Egress:   []v3.Rule{{Action: v3.Pass}},
		},
	}

	// Matches all in namespace ns1, ingress and egress with no rules, will cause end of tier drop if
	// no other policies.
	tier3Policy1 = &v3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tier3.policy1",
			Namespace: "ns1",
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     "tier3",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Selector: "all()",
		},
	}

	// Matches all in namespace ns1, ingress allow all.
	tier3Policy2 = &v3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tier3.policy2",
			Namespace: "ns1",
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     "tier3",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress},
			Selector: "all()",
			Ingress:  []v3.Rule{{Action: v3.Allow}},
		},
	}

	// Matches all in namespace ns1, egress allow all.
	tier3Policy3 = &v3.NetworkPolicy{
		TypeMeta: resources.TypeCalicoNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tier3.policy3",
			Namespace: "ns1",
		},
		Spec: v3.NetworkPolicySpec{
			Tier:     "tier3",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Selector: "all()",
			Egress:   []v3.Rule{{Action: v3.Allow}},
		},
	}

	tier3Policy4 = &v3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier3.policy4",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:     "tier3",
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress:  []v3.Rule{{Action: v3.Pass}},
			Egress:   []v3.Rule{{Action: v3.Pass}},
		},
	}

	serviceAccountNameSource = "sa-source"
	namedPortSourceName      = "source-port"
	namedPortSourcePort      = uint16(10)
	namedPortProtocol        = "TCP"
	namedPortProtocolNumber  = api.ProtoTCP
	namedPortDestinationName = "destination-port"
	namedPortDestinationPort = uint16(11)

	tier3PolicyMatchCached = &v3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier3.policymatchcached",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:     "tier3",
			Selector: "cached == 'true'",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{{
				Action: v3.Allow,
				Source: v3.EntityRule{
					Selector: "source == 'true'",
					ServiceAccounts: &v3.ServiceAccountMatch{
						Names: []string{serviceAccountNameSource},
					},
					Ports: []numorstring.Port{numorstring.NamedPort(namedPortSourceName)},
				},
				Destination: v3.EntityRule{
					Selector: "destination == 'true'",
					Ports:    []numorstring.Port{numorstring.NamedPort(namedPortDestinationName)},
				},
			}},
			Egress: []v3.Rule{{
				Action: v3.Allow,
				Source: v3.EntityRule{
					Selector: "source == 'true'",
					ServiceAccounts: &v3.ServiceAccountMatch{
						Names: []string{serviceAccountNameSource},
					},
					Ports: []numorstring.Port{numorstring.NamedPort(namedPortSourceName)},
				},
				Destination: v3.EntityRule{
					Selector: "destination == 'true'",
					Ports:    []numorstring.Port{numorstring.NamedPort(namedPortDestinationName)},
				},
			}},
		},
	}
	tier3PolicyMatchCachedDenyAll = &v3.GlobalNetworkPolicy{
		TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name: "tier3.policymatchcached.denyall",
		},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:     "tier3",
			Selector: "all()",
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{{
				Action: v3.Deny,
			}},
			Egress: []v3.Rule{{
				Action: v3.Deny,
			}},
		},
	}

	ns1 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns1",
			Labels: map[string]string{
				"name": "ns1",
			},
		},
	}

	ns2 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns2",
			Labels: map[string]string{
				"name": "ns2",
			},
		},
	}

	cfgDontCalcActionBefore = &pipcfg.Config{
		CalculateOriginalAction: false,
	}

	cfgCalcActionBefore = &pipcfg.Config{
		CalculateOriginalAction: true,
	}
)

var _ = Describe("Policy calculator tests - tier/policy/rule/profile enumeration", func() {
	var ep *policycalc.EndpointCache

	BeforeEach(func() {
		ep = policycalc.NewEndpointCache()
	})

	It("handles: no policy -> single policy that drops all in namespace ns1", func() {
		By("Having no policy before")
		rdBefore := &policycalc.ResourceData{
			Tiers:      policycalc.Tiers{},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}

		By("Having a single drop all in namespace ns1 policy")
		rdAfter := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{{{
				CalicoV3Policy: tier3Policy1,
				ResourceID:     resources.GetResourceID(tier3Policy1),
			}}},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(tier3Policy1), policycalc.Impact{Modified: true})

		By("Creating the policy calculators which calculates before and after")
		pc := policycalc.NewPolicyCalculator(cfgCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Checking a flow not in namespace ns1 is unaffected")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after := pc.CalculateSource(f)
		Expect(modified).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))

		By("Checking a flow with source in namespace ns1 is recalculated")
		f = &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{},
			ActionFlag:  api.ActionFlagDeny,
		}

		modified, before, after = pc.CalculateSource(f)
		Expect(modified).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagEndOfTierDeny))

		By("Checking a flow from networkset in namespace1 to a dest not in namespace ns1 is unaffected")
		f = &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeNs,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after = pc.CalculateSource(f)
		Expect(modified).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))

		By("Checking a flow from source not in namespace ns1 to a networkset in namespace ns1 is unaffected")
		f = &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeNs,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after = pc.CalculateSource(f)
		Expect(modified).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))

		By("Checking a flow with destination in namespace ns1 is recalculated")
		f = &api.Flow{
			Reporter: api.ReporterTypeDestination,
			Source:   api.FlowEndpointData{},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagDeny,
		}

		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(modified).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagEndOfTierDeny))
	})

	It("handles: single policy selecting ns1 with no rules -> next policy ingress allows all for ns1", func() {
		By("Having a single drop all in namespace ns1 policy")
		rdBefore := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{{{
				CalicoV3Policy: tier3Policy1,
				ResourceID:     resources.GetResourceID(tier3Policy1),
			}}},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}

		By("Adding an allow all ingress rule after the no-rule policy")
		rdAfter := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{{{
				CalicoV3Policy: tier3Policy1,
				ResourceID:     resources.GetResourceID(tier3Policy1),
			}, {
				CalicoV3Policy: tier3Policy2,
				ResourceID:     resources.GetResourceID(tier3Policy2),
			}}},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(tier3Policy2), policycalc.Impact{Modified: true})

		By("Creating the policy calculators which calculates before and after")
		pc := policycalc.NewPolicyCalculator(cfgCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Checking a flow with source in ns1 is unaffected")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after := pc.CalculateSource(f)
		Expect(modified).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))

		f.Reporter = api.ReporterTypeDestination
		_, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))

		By("Checking a flow with dest in namespace ns1 is recalculated")
		f = &api.Flow{
			Reporter: api.ReporterTypeDestination,
			Source:   api.FlowEndpointData{},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(modified).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagEndOfTierDeny))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
	})

	It("handles: single policy selecting ns1 with no rules -> next policy egress allows all for ns1", func() {
		By("Having a single drop all in namespace ns1 policy")
		rdBefore := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{{{
				CalicoV3Policy: tier3Policy1,
				ResourceID:     resources.GetResourceID(tier3Policy1),
			}}},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}

		By("Adding an allow all egress rule after the no-rule policy")
		rdAfter := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{{{
				CalicoV3Policy: tier3Policy1,
				ResourceID:     resources.GetResourceID(tier3Policy1),
			}, {
				CalicoV3Policy: tier3Policy3,
				ResourceID:     resources.GetResourceID(tier3Policy3),
			}}},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(tier3Policy3), policycalc.Impact{Modified: true})

		By("Creating the policy calculators which calculates before and after")
		pc := policycalc.NewPolicyCalculator(cfgCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Checking a flow with dest in ns1 is unaffected")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after := pc.CalculateSource(f)
		Expect(modified).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))

		f.Reporter = api.ReporterTypeDestination
		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(modified).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))

		By("Checking a flow with source in namespace ns1 is recalculated")
		f = &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{},
			ActionFlag:  api.ActionFlagAllow,
		}

		modified, before, after = pc.CalculateSource(f)
		Expect(modified).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagEndOfTierDeny))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
	})

	It("handles: multiple tiers", func() {
		By("Having no resources before")
		rdBefore := &policycalc.ResourceData{
			Tiers:      policycalc.Tiers{},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}

		By("Adding a bunch of policies across multiple tiers")
		rdAfter := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{
				{
					{CalicoV3Policy: tier1Policy1, ResourceID: resources.GetResourceID(tier1Policy1)},
					{CalicoV3Policy: tier1Policy2, ResourceID: resources.GetResourceID(tier1Policy2)},
				},
				{{CalicoV3Policy: tier2Policy1, ResourceID: resources.GetResourceID(tier2Policy1)}},
				{{CalicoV3Policy: tier3Policy4, ResourceID: resources.GetResourceID(tier3Policy4)}},
			},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(tier1Policy1), policycalc.Impact{Modified: true})
		impacted.Add(resources.GetResourceID(tier1Policy2), policycalc.Impact{Modified: true})
		impacted.Add(resources.GetResourceID(tier2Policy1), policycalc.Impact{Modified: true})
		impacted.Add(resources.GetResourceID(tier3Policy4), policycalc.Impact{Modified: true})

		By("Creating the policy calculators which calculates after and leaves before action unchanged")
		pc := policycalc.NewPolicyCalculator(cfgDontCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Checking a red->red flow is allowed")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Make(map[string]string{"color": "red"}),
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Make(map[string]string{"color": "red"}),
			},
			ActionFlag: api.ActionFlagDeny,
		}

		modified, before, after := pc.CalculateSource(f)
		Expect(before.Action).To(Equal(api.ActionFlagDeny))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(modified).To(BeTrue())

		f.Reporter = api.ReporterTypeDestination
		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(before.Action).To(Equal(api.ActionFlagDeny))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(modified).To(BeTrue())

		By("Checking a red->blue flow is denied")
		f = &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Make(map[string]string{"color": "red"}),
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Make(map[string]string{"color": "blue"}),
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after = pc.CalculateSource(f)
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(before.Policies).To(HaveLen(1))
		Expect(after.Policies).To(HaveLen(1))
		Expect(before.Policies[0].Name()).To(Equal("kns.ns2"))
		Expect(after.Policies[0].Name()).To(Equal("tier1.policy1"))
		Expect(modified).To(BeTrue())

		f.Reporter = api.ReporterTypeDestination
		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagDeny))
		Expect(modified).To(BeTrue())

		By("Checking a blue->red flow is denied")
		f = &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Make(map[string]string{"color": "blue"}),
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Make(map[string]string{"color": "red"}),
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after = pc.CalculateSource(f)
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagDeny))
		Expect(modified).To(BeTrue())

		f.Reporter = api.ReporterTypeDestination
		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagDeny)
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlag(0)))
		Expect(modified).To(BeTrue())

		By("Checking a net->purple flow is denied")
		f = &api.Flow{
			Reporter: api.ReporterTypeDestination,
			Source:   api.FlowEndpointData{},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Labels:    uniquelabels.Make(map[string]string{"color": "purple"}),
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after = pc.CalculateDest(f, policycalc.ActionFlagsAllowAndDeny, policycalc.ActionFlagsAllowAndDeny)
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Action).To(Equal(api.ActionFlagDeny))
		Expect(modified).To(BeTrue())

		By("Checking a purple->net flow is denied")
		f = &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns2",
				Labels:    uniquelabels.Make(map[string]string{"color": "purple"}),
			},
			Destination: api.FlowEndpointData{},
			ActionFlag:  api.ActionFlagDeny,
		}

		modified, before, after = pc.CalculateSource(f)
		Expect(before.Action).To(Equal(api.ActionFlagDeny))
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(modified).To(BeTrue())
	})

	It("handles: pod source and destination info filled in from cache", func() {
		By("Having a policy that denies all")
		rdBefore := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{{{
				CalicoV3Policy: tier3PolicyMatchCachedDenyAll,
				ResourceID:     resources.GetResourceID(tier3PolicyMatchCachedDenyAll),
			}}},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}

		By("Adding a policy that matches on ingress and egress cached data before the deny")
		rdAfter := &policycalc.ResourceData{
			Tiers: policycalc.Tiers{{{
				CalicoV3Policy: tier3PolicyMatchCached,
				ResourceID:     resources.GetResourceID(tier3PolicyMatchCached),
			}, {
				CalicoV3Policy: tier3PolicyMatchCachedDenyAll,
				ResourceID:     resources.GetResourceID(tier3PolicyMatchCachedDenyAll),
			}}},
			Namespaces: []*corev1.Namespace{ns1, ns2},
		}
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(tier3PolicyMatchCached), policycalc.Impact{Modified: true})

		By("Updating the endpoint cache with the source and dest endpoints in")
		ep.OnUpdates([]syncer.Update{
			{
				Type: syncer.UpdateTypeDeleted,
			},
			{
				Type: syncer.UpdateTypeSet,
				Resource: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:         "pod1-abcde",
						Namespace:    "ns1",
						GenerateName: "pod1-",
						Labels: map[string]string{
							"cached":      "true",
							"source":      "true",
							"destination": "false",
						},
					},
					Spec: corev1.PodSpec{
						ServiceAccountName: serviceAccountNameSource,
						Containers: []corev1.Container{{
							Ports: []corev1.ContainerPort{{
								Name:          namedPortSourceName,
								ContainerPort: int32(namedPortSourcePort),
								Protocol:      corev1.Protocol(namedPortProtocol),
							}},
						}},
					},
				},
			},
			{
				Type: syncer.UpdateTypeSet,
				Resource: &v3.HostEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name: "hostendpoint",
						Labels: map[string]string{
							"cached":      "true",
							"source":      "false",
							"destination": "true",
						},
					},
					Spec: v3.HostEndpointSpec{
						Ports: []v3.EndpointPort{{
							Name:     namedPortDestinationName,
							Protocol: numorstring.ProtocolFromString(namedPortProtocol),
							Port:     namedPortDestinationPort,
						}},
					},
				},
			},
		})

		By("Creating the policy calculators which only calculates after")
		pc := policycalc.NewPolicyCalculator(cfgDontCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Creating a flow with all of the cached data missing and running through the policy calculator")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Namespace: "ns1",
				Name:      "pod1-*",
				Port:      &namedPortSourcePort,
			},
			Destination: api.FlowEndpointData{
				Type: api.EndpointTypeHep,
				Name: "hostendpoint",
				Port: &namedPortDestinationPort,
			},
			Proto:      &namedPortProtocolNumber,
			ActionFlag: api.ActionFlagDeny,
		}
		modified, before, after := pc.CalculateSource(f)
		Expect(modified).To(BeTrue())

		By("Checking before flow is unchanged")
		Expect(before.Action).To(Equal(api.ActionFlagDeny))
		Expect(before.Include).To(BeTrue())

		By("Checking after flow source is allow and included")
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Include).To(BeTrue())

		By("Checking after flow destination is also allow and included - this has been added by policycalc")
		_, before, after = pc.CalculateDest(f, api.ActionFlagDeny|policycalc.ActionFlagFlowLogRemovedUncertainty, api.ActionFlagAllow)
		Expect(before.Include).To(BeFalse())
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Include).To(BeTrue())
	})

	It("Compares policy hits between measured (dirty) and calculated [ignores staged, order and duplicates]", func() {
		By("Checking staged policies ignored in dirty set")
		Expect(policycalc.PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.staged:policy|allow", 1),
				mustCreatePolicyHit("2|tier|ns1/tier.policy|allow", 1),
				mustCreatePolicyHit("3|tier|ns1/tier.staged:policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
			}),
		).To(BeTrue())

		By("Checking duplicate policies ignored in dirty set")
		Expect(policycalc.PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.staged:policy|allow", 1),
				mustCreatePolicyHit("2|tier|ns1/tier.policy|allow", 1),
				mustCreatePolicyHit("3|tier|ns1/tier.policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
			}),
		).To(BeTrue())

		By("Checking staged policies ignored in calculated set")
		Expect(policycalc.PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("2|tier|ns1/tier.policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.staged:policy|allow", 1),
				mustCreatePolicyHit("2|tier|ns1/tier.policy|allow", 1),
			}),
		).To(BeTrue())

		By("Checking policy name not matching")
		Expect(policycalc.PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.staged:policy|allow", 1),
				mustCreatePolicyHit("3|tier|ns1/tier.policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier2|ns1/tier2.staged:policy|allow", 1),
				mustCreatePolicyHit("2|tier2|ns1/tier2.policy|allow", 1),
			}),
		).To(BeFalse())

		By("Checking action not matching")
		Expect(policycalc.PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|deny", 1),
			}),
		).To(BeFalse())

		By("Checking conflicting actions in dirty set")
		Expect(policycalc.PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
				mustCreatePolicyHit("1|tier|ns1/tier.policy|deny", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("3|tier|ns1/tier.policy|deny", 1),
			}),
		).To(BeFalse())
	})

	It("Compares policy hits for before and after [ignores staged]", func() {
		By("Checking staged policies ignored in before set")
		Expect(policycalc.PolicyHitsEqualIgnoringStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.staged:policy|allow", 1),
				mustCreatePolicyHit("2|tier|ns1/tier.policy|allow", 1),
				mustCreatePolicyHit("3|tier|ns1/tier.staged:policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
			}),
		).To(BeTrue())

		By("Checking staged policies ignored in after set")
		Expect(policycalc.PolicyHitsEqualIgnoringStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier2|ns1/tier2.staged:policy|allow", 1),
				mustCreatePolicyHit("2|tier|ns1/tier.policy|allow", 1),
			}),
		).To(BeTrue())

		By("Checking policies have to be in the same order")
		Expect(policycalc.PolicyHitsEqualIgnoringStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
				mustCreatePolicyHit("2|tier|ns2/tier.policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns2/tier.staged:policy|allow", 1),
				mustCreatePolicyHit("2|tier|ns1/tier.policy|allow", 1),
			}),
		).To(BeFalse())

		By("Checking policy actions have to be the same")
		Expect(policycalc.PolicyHitsEqualIgnoringStaged(
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|allow", 1),
			},
			[]api.PolicyHit{
				mustCreatePolicyHit("1|tier|ns1/tier.policy|deny", 1),
			}),
		).To(BeFalse())
	})
})

func mustCreatePolicyHit(policyStr string, count int) api.PolicyHit {
	policyHit, err := api.PolicyHitFromFlowLogPolicyString(policyStr, int64(count))
	Expect(err).ShouldNot(HaveOccurred())

	return policyHit
}
