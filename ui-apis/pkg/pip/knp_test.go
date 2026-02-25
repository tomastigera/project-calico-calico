package pip

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/lma/pkg/api"
	pipcfg "github.com/projectcalico/calico/ui-apis/pkg/pip/config"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/policycalc"
)

var (
	defaultTier = &v3.Tier{
		TypeMeta: resources.TypeCalicoTiers,
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	knpDefaultDenyIngress = &networkingv1.NetworkPolicy{
		TypeMeta: resources.TypeK8sNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-ingress",
			Namespace: "ns1",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	knpAllowAllIngress = &networkingv1.NetworkPolicy{
		TypeMeta: resources.TypeK8sNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allows-all-ingress",
			Namespace: "ns1",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{},
				}},
			}},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	knpDefaultDenyEgress = &networkingv1.NetworkPolicy{
		TypeMeta: resources.TypeK8sNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-egress",
			Namespace: "ns1",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	}

	knpAllowAllEgress = &networkingv1.NetworkPolicy{
		TypeMeta: resources.TypeK8sNetworkPolicies,
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allows-all-egress",
			Namespace: "ns1",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{},
				}},
			}},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
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

	cfgCalcActionBefore = &pipcfg.Config{
		CalculateOriginalAction: true,
	}
)

var _ = Describe("Kubernetes Network Policy PIP tests", func() {
	var ep *policycalc.EndpointCache

	BeforeEach(func() {
		ep = policycalc.NewEndpointCache()
	})

	It("handles kubernetes network policy default deny then adding default allow", func() {
		xc := xrefcache.NewXrefCache(&config.Config{}, func() {})
		xc.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("Adding the default tier and namespace ns1")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(defaultTier),
			Resource:   defaultTier,
		}, {
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(ns1),
			Resource:   ns1,
		}})

		By("Having a single drop all ingress in namespace ns1 policy")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(knpDefaultDenyIngress),
			Resource:   knpDefaultDenyIngress,
		}})
		rdBefore := resourceDataFromXrefCache(xc)

		By("Adding an allow all ingress rule")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(knpAllowAllIngress),
			Resource:   knpAllowAllIngress,
		}})
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(knpAllowAllIngress), policycalc.Impact{Modified: true})
		rdAfter := resourceDataFromXrefCache(xc)

		By("Creating the policy calculators which calculates before and after")
		pc := policycalc.NewPolicyCalculator(cfgCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Checking a flow with dest in ns1 is unaffected")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Name:      "wep1-*",
				Namespace: "ns1",
				Labels: uniquelabels.Make(map[string]string{
					"any": "value",
				}),
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Name:      "wep2-*",
				Namespace: "ns1",
				Labels: uniquelabels.Make(map[string]string{
					"any": "value",
				}),
			},
			ActionFlag: api.ActionFlagAllow,
		}

		processed, before, after := pc.CalculateSource(f)
		Expect(processed).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(before.Include).To(BeTrue())
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Include).To(BeTrue())

		f.Reporter = api.ReporterTypeDestination
		processed, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(processed).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagEndOfTierDeny))
		Expect(before.Include).To(BeTrue())
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Include).To(BeTrue())

		processed, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagDeny)
		Expect(processed).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagEndOfTierDeny))
		Expect(before.Include).To(BeTrue())
		Expect(after.Include).To(BeFalse())
	})

	It("handles kubernetes network policy default allow all ingress with default deny then deleting default allow", func() {
		xc := xrefcache.NewXrefCache(&config.Config{}, func() {})
		xc.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("Adding the default tier and namespace ns1")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(defaultTier),
			Resource:   defaultTier,
		}, {
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(ns1),
			Resource:   ns1,
		}})

		By("Installing a default allow all ingress and a default deny policy in namespace ns1")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(knpDefaultDenyIngress),
			Resource:   knpDefaultDenyIngress,
		}, {
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(knpAllowAllIngress),
			Resource:   knpAllowAllIngress,
		}})
		rdBefore := resourceDataFromXrefCache(xc)

		By("Deleting the default allow all ingress rule")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeDeleted,
			ResourceID: resources.GetResourceID(knpAllowAllIngress),
		}})
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(knpAllowAllIngress), policycalc.Impact{Modified: true})
		rdAfter := resourceDataFromXrefCache(xc)

		By("Creating the policy calculators which calculates before and after")
		pc := policycalc.NewPolicyCalculator(cfgCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Checking a flow with dest in ns1 is unaffected")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Name:      "wep1-*",
				Namespace: "ns1",
				Labels: uniquelabels.Make(map[string]string{
					"any": "value",
				}),
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Name:      "wep2-*",
				Namespace: "ns1",
				Labels: uniquelabels.Make(map[string]string{
					"any": "value",
				}),
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after := pc.CalculateSource(f)
		Expect(modified).To(BeFalse())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(before.Include).To(BeTrue())
		Expect(after.Action).To(Equal(api.ActionFlagAllow))
		Expect(after.Include).To(BeTrue())

		f.Reporter = api.ReporterTypeDestination
		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagAllow)
		Expect(modified).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(before.Include).To(BeTrue())
		Expect(after.Action).To(Equal(api.ActionFlagEndOfTierDeny))
		Expect(after.Include).To(BeTrue())
	})

	It("handles kubernetes network policy default allow all egress with default deny then deleting default allow", func() {
		xc := xrefcache.NewXrefCache(&config.Config{}, func() {})
		xc.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("Adding the default tier and namespace ns1")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(defaultTier),
			Resource:   defaultTier,
		}, {
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(ns1),
			Resource:   ns1,
		}})

		By("Installing a default allow all egress and a default deny policy in namespace ns1")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(knpDefaultDenyEgress),
			Resource:   knpDefaultDenyEgress,
		}, {
			Type:       syncer.UpdateTypeSet,
			ResourceID: resources.GetResourceID(knpAllowAllEgress),
			Resource:   knpAllowAllEgress,
		}})
		rdBefore := resourceDataFromXrefCache(xc)

		By("Deleting the default allow all egress rule")
		xc.OnUpdates([]syncer.Update{{
			Type:       syncer.UpdateTypeDeleted,
			ResourceID: resources.GetResourceID(knpAllowAllEgress),
		}})
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(knpAllowAllEgress), policycalc.Impact{Modified: true})
		rdAfter := resourceDataFromXrefCache(xc)

		By("Creating the policy calculators which calculates before and after")
		pc := policycalc.NewPolicyCalculator(cfgCalcActionBefore, ep, rdBefore, rdAfter, impacted)

		By("Checking a flow with src in ns1 goes allow->deny")
		f := &api.Flow{
			Reporter: api.ReporterTypeSource,
			Source: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Name:      "wep1-*",
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			Destination: api.FlowEndpointData{
				Type:      api.EndpointTypeWep,
				Name:      "wep2-*",
				Namespace: "ns1",
				Labels:    uniquelabels.Empty,
			},
			ActionFlag: api.ActionFlagAllow,
		}

		modified, before, after := pc.CalculateSource(f)
		Expect(modified).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(before.Include).To(BeTrue())
		Expect(after.Action).To(Equal(api.ActionFlagEndOfTierDeny))
		Expect(after.Include).To(BeTrue())

		f.Reporter = api.ReporterTypeDestination
		modified, before, after = pc.CalculateDest(f, api.ActionFlagAllow, api.ActionFlagDeny)
		Expect(modified).To(BeTrue())
		Expect(before.Action).To(Equal(api.ActionFlagAllow))
		Expect(before.Include).To(BeTrue())
		Expect(after.Action).To(BeEquivalentTo(0))
		Expect(after.Include).To(BeFalse())
	})
})
