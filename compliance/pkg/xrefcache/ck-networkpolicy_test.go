// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package xrefcache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	. "github.com/projectcalico/calico/compliance/internal/testutils"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var _ = Describe("Basic CRUD of network policies with no other resources present", func() {
	var tester *XrefCacheTester

	BeforeEach(func() {
		tester = NewXrefCacheTester()
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())
	})

	It("should handle basic CRUD of GlobalNetworkPolicy and determine non-xref state", func() {
		By("applying a GlobalNetworkPolicy, ingress no rules")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np := tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a GlobalNetworkPolicy, egress no rules")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			nil,
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("applying a GlobalNetworkPolicy, ingress, one allow source rule with internet CIDR")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Source, Public),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryInternetExposedIngress))

		By("applying a GlobalNetworkPolicy, ingress, one allow destination rule with internet CIDR")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Destination, Public),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings - dest CIDR not relevant for ingress rule")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		By("applying a GlobalNetworkPolicy, ingress, one allow source rule with private CIDR")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Source, Private),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a GlobalNetworkPolicy, ingress and egress no rules")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{},
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryProtectedEgress))

		By("applying a GlobalNetworkPolicy, egress, one allow destination rule with internet CIDR")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Destination, Public),
			},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress | xrefcache.CacheEntryInternetExposedEgress))

		By("applying a GlobalNetworkPolicy, egress, one allow source rule with internet CIDR")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Source, Public),
			},
			&Order1,
		)

		By("checking the cache settings - source CIDR not relevant for egress rule")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryInternetExposedEgress |
				xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("applying a GlobalNetworkPolicy, egress, one allow destination rule with private CIDR")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Destination, Private),
			},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("deleting the first network policy")
		tester.DeleteGlobalNetworkPolicy(TierDefault, Name1)

		By("checking the cache settings")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).To(BeNil())
	})

	It("should handle basic CRUD of Calico NetworkPolicy and determine non-xref state", func() {
		By("applying a NetworkPolicy, ingress no rules")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np := tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a NetworkPolicy, egress no rules")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			nil,
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("applying a NetworkPolicy, ingress, one allow source rule with internet CIDR")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Source, Public),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryInternetExposedIngress,
		))

		By("applying a NetworkPolicy, ingress, one allow source rule with private CIDR")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Source, Private),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a NetworkPolicy, ingress, one allow source rule with selector")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, Select1, NoNamespaceSelector),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a NetworkPolicy, ingress, one allow source rule with namespace selector")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, NoSelector, Select1),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		By("applying a NetworkPolicy, ingress, one allow destination rule with internet CIDR")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Destination, Public),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings - dest CIDR not relevant for ingress rule")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		By("applying a NetworkPolicy, ingress, one allow destination rule with selector")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Destination, Select1, NoNamespaceSelector),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings - dest selector not relevant for ingress rule")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		By("applying a NetworkPolicy, ingress and egress no rules")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{},
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryProtectedEgress))

		By("applying a NetworkPolicy, egress, one allow destination rule with internet CIDR")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Destination, Public),
			},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress | xrefcache.CacheEntryInternetExposedEgress))

		By("applying a NetworkPolicy, egress, one allow destination rule with private CIDR")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Destination, Private),
			},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("applying a NetworkPolicy, egress, one allow destination rule with selector")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Destination, Select1, NoNamespaceSelector),
			},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("applying a NetworkPolicy, egress, one allow destination rule with namespace selector")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Destination, NoSelector, Select1),
			},
			&Order1,
		)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("applying a NetworkPolicy, egress, one allow source rule with internet CIDR")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleNets(Allow, Source, Public),
			},
			&Order1,
		)

		By("checking the cache settings - source CIDR not relevant for egress rule")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryInternetExposedEgress |
				xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("applying a NetworkPolicy, egress, one allow source rule with selector")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, Select1, NoNamespaceSelector),
			},
			&Order1,
		)

		By("checking the cache settings - source selector not relevant for egress rule")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryInternetExposedEgress |
				xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("deleting the first network policy")
		tester.DeleteNetworkPolicy(TierDefault, Name1, Namespace1)

		By("checking the cache settings")
		np = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)
		Expect(np).To(BeNil())
	})

	It("should handle basic CRUD of Calico K8sNetworkPolicy and determine non-xref state", func() {
		By("applying a K8sNetworkPolicy, ingress no rules")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{},
			nil,
		)

		By("checking the cache settings")
		np := tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a K8sNetworkPolicy, egress no rules")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			nil,
			[]networkingv1.NetworkPolicyEgressRule{},
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("applying a K8sNetworkPolicy, ingress, one allow source rule with internet CIDR")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{
				K8sIngressRuleNets(Allow, Source, Public),
			},
			nil,
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryInternetExposedIngress,
		))

		By("applying a K8sNetworkPolicy, ingress, one allow source rule with private CIDR")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{
				K8sIngressRuleNets(Allow, Source, Private),
			},
			nil,
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a K8sNetworkPolicy, ingress, one allow source rule with selector")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{
				K8sIngressRuleSelectors(Allow, Source, Select1, NoNamespaceSelector),
			},
			nil,
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress))

		By("applying a K8sNetworkPolicy, ingress, one allow source rule with namespace selector")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{
				K8sIngressRuleSelectors(Allow, Source, NoSelector, Select1),
			},
			nil,
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		By("applying a K8sNetworkPolicy, ingress and egress no rules")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{},
			[]networkingv1.NetworkPolicyEgressRule{},
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryProtectedEgress))

		By("applying a K8sNetworkPolicy, egress, one allow destination rule with internet CIDR")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			nil,
			[]networkingv1.NetworkPolicyEgressRule{
				K8sEgressRuleNets(Allow, Destination, Public),
			},
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress | xrefcache.CacheEntryInternetExposedEgress))

		By("applying a K8sNetworkPolicy, egress, one allow destination rule with private CIDR")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			nil,
			[]networkingv1.NetworkPolicyEgressRule{
				K8sEgressRuleNets(Allow, Destination, Private),
			},
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("applying a K8sNetworkPolicy, egress, one allow destination rule with selector")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			nil,
			[]networkingv1.NetworkPolicyEgressRule{
				K8sEgressRuleSelectors(Allow, Destination, Select1, NoNamespaceSelector),
			},
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(xrefcache.CacheEntryProtectedEgress))

		By("applying a K8sNetworkPolicy, egress, one allow destination rule with namespace selector")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			nil,
			[]networkingv1.NetworkPolicyEgressRule{
				K8sEgressRuleSelectors(Allow, Destination, NoSelector, Select1),
			},
		)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).ToNot(BeNil())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("deleting the first network policy")
		tester.DeleteK8sNetworkPolicy(Name1, Namespace1)

		By("checking the cache settings")
		np = tester.GetK8sNetworkPolicy(Name1, Namespace1)
		Expect(np).To(BeNil())
	})

	It("should track endpoints correctly", func() {
		By("applying pod1 label1")
		tester.SetPod(Name1, Namespace1, Label1, IP1, NoServiceAccount, NoPodOptions)
		pod := tester.GetPod(Name1, Namespace1)

		By("applying hep1 label2")
		tester.SetHostEndpoint(Name2, Label2, IP2)
		hep := tester.GetHostEndpoint(Name2)

		By("applying a GlobalNetworkPolicy matching select all()")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{},
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the pod and hep are linked in the policy")
		gnp := tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(gnp.SelectedHostEndpoints.Len()).To(Equal(1))
		Expect(gnp.SelectedPods.Len()).To(Equal(1))
		Expect(len(gnp.ScheduledNodes)).To(Equal(1))
		Expect(gnp.SelectedHostEndpoints.Contains(resources.GetResourceID(hep))).To(BeTrue())
		Expect(gnp.SelectedPods.Contains(resources.GetResourceID(pod))).To(BeTrue())
		thePod := pod.GetPrimary().(*corev1.Pod)
		scheduledNodes, ok := gnp.ScheduledNodes[thePod.Spec.NodeName]
		Expect(ok).To(BeTrue())
		Expect(scheduledNodes.Contains(resources.GetResourceID(pod))).To(BeTrue())

		By("updating GlobalNetworkPolicy to match Label1")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, Select1,
			[]apiv3.Rule{},
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the pod is linked in the policy and the hep is now unlinked")
		gnp = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(gnp.SelectedHostEndpoints.Len()).To(Equal(0))
		Expect(gnp.SelectedPods.Len()).To(Equal(1))
		Expect(gnp.SelectedPods.Contains(resources.GetResourceID(pod))).To(BeTrue())

		By("updating GlobalNetworkPolicy to match Label2")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, Select2,
			[]apiv3.Rule{},
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the hep is linked in the policy and the pod is now unlinked")
		gnp = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(gnp.SelectedHostEndpoints.Len()).To(Equal(1))
		Expect(gnp.SelectedPods.Len()).To(Equal(0))
		Expect(gnp.SelectedHostEndpoints.Contains(resources.GetResourceID(hep))).To(BeTrue())

		By("updating GlobalNetworkPolicy to match Label3")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, Select3,
			[]apiv3.Rule{},
			[]apiv3.Rule{},
			&Order1,
		)

		By("checking the policy has no linked endpoints")
		gnp = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(gnp.SelectedHostEndpoints.Len()).To(Equal(0))
		Expect(gnp.SelectedPods.Len()).To(Equal(0))
		Expect(len(gnp.ScheduledNodes)).To(Equal(0))
	})
})

var _ = Describe("Basic CRUD of network policies with no other resources present - policy ordering", func() {
	var tester *XrefCacheTester
	var tier1, tier2, tierDefault *xrefcache.CacheEntryTier
	var gnp1Tier1, np1Tier1, np1Default, knp1Default, gnp1Default, gnp1Tier2, np1Tier2 *xrefcache.CacheEntryNetworkPolicy

	BeforeEach(func() {
		tester = NewXrefCacheTester()
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("applying tier 2 order 10")
		tester.SetTier(Name2, Order10)
		tier2 = tester.GetTier(Name2)

		By("applying a GlobalNetworkPolicy order 10 in tier1")
		tester.SetGlobalNetworkPolicy(Tier1, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order10,
		)
		gnp1Tier1 = tester.GetGlobalNetworkPolicy(Tier1, Name1)

		By("applying a Calico NetworkPolicy order 1 in tier2")
		tester.SetNetworkPolicy(Tier2, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)
		np1Tier2 = tester.GetNetworkPolicy(Tier2, Name1, Namespace1)

		By("applying a Calico NetworkPolicy order 1 in default tier")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)
		np1Default = tester.GetNetworkPolicy(TierDefault, Name1, Namespace1)

		By("applying a k8s NetworkPolicy in default tier")
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{},
			nil,
		)
		knp1Default = tester.GetK8sNetworkPolicy(Name1, Namespace1)

		By("applying a GlobalNetworkPolicy order 10000 in default tier")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order10000,
		)
		gnp1Default = tester.GetGlobalNetworkPolicy(TierDefault, Name1)

		By("applying a GlobalNetworkPolicy order 10 in tier2")
		tester.SetGlobalNetworkPolicy(Tier2, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order10,
		)
		gnp1Tier2 = tester.GetGlobalNetworkPolicy(Tier2, Name1)

		By("applying a Calico NetworkPolicy order 1 in tier1")
		tester.SetNetworkPolicy(Tier1, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)
		np1Tier1 = tester.GetNetworkPolicy(Tier1, Name1, Namespace1)

		By("applying tier 1 order 1")
		tester.SetTier(Name1, Order1)
		tier1 = tester.GetTier(Name1)

		By("applying default tier infinite order")
		tester.SetDefaultTier()
		tierDefault = tester.GetDefaultTier()
	})

	It("should handle ordering of tiers and policies when querying GetOrderedTiers", func() {
		By("calling GetOrderedTiers and checking tier order")
		tiers := tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[0].Tier).To(Equal(tier1))
		Expect(tiers[1].Tier).To(Equal(tier2))
		Expect(tiers[2].Tier).To(Equal(tierDefault))

		By("checking sorted policies in each tier")
		Expect(tiers[0].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier1, gnp1Tier1}))
		Expect(tiers[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier2, gnp1Tier2}))
		Expect(tiers[2].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Default, knp1Default, gnp1Default}))
	})

	It("should handle querying GetOrderedTiers reordering tiers and then requerying", func() {
		By("calling GetOrderedTiers and checking tier order")
		tiers := tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[0].Tier).To(Equal(tier1))
		Expect(tiers[1].Tier).To(Equal(tier2))
		Expect(tiers[2].Tier).To(Equal(tierDefault))

		By("reordering tier1 and tier2")
		tester.SetTier(Name1, Order10000)

		By("calling GetOrderedTiers and checking tier order and sorted policies in the tiers")
		tiers = tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[0].Tier).To(Equal(tier2))
		Expect(tiers[1].Tier).To(Equal(tier1))
		Expect(tiers[2].Tier).To(Equal(tierDefault))
		Expect(tiers[0].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier2, gnp1Tier2}))
		Expect(tiers[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier1, gnp1Tier1}))
		Expect(tiers[2].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Default, knp1Default, gnp1Default}))
	})

	It("should handle querying GetOrderedPolicies reordering policies and then requerying", func() {
		By("calling GetOrderedTiers to perform initial ordering")
		tester.GetOrderedTiersAndPolicies()

		By("reordering default tier policies")
		tester.SetNetworkPolicy(TierDefault, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order10,
		)
		tester.SetK8sNetworkPolicy(Name1, Namespace1, SelectAll,
			[]networkingv1.NetworkPolicyIngressRule{},
			nil,
		)
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)

		By("Getting ordered tiers and policies and checking default policies are re-ordered")
		tiers := tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[2].Tier).To(Equal(tierDefault))
		Expect(tiers[2].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{gnp1Default, np1Default, knp1Default}))
	})

	It("should handle ordering of tiers and policies when querying GetOrderedTiers", func() {
		By("calling GetOrderedTiers and checking tier order")
		tiers := tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[0].Tier).To(Equal(tier1))
		Expect(tiers[1].Tier).To(Equal(tier2))
		Expect(tiers[2].Tier).To(Equal(tierDefault))

		By("reordering tier1 and tier2, calling GetOrderedTiers again and checking tier order")
		tester.SetTier(Name1, Order10000)

		By("reordering gnp1Tier1 and np1Tier1")
		tester.SetGlobalNetworkPolicy(Tier1, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)
		tester.SetNetworkPolicy(Tier1, Name1, Namespace1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order10,
		)

		By("calling GetOrderedTiers and checking tier order")
		tiers = tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[0].Tier).To(Equal(tier2))
		Expect(tiers[1].Tier).To(Equal(tier1))
		Expect(tiers[2].Tier).To(Equal(tierDefault))

		By("checking sorted policies in each tier")
		Expect(tiers[0].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier2, gnp1Tier2}))
		Expect(tiers[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{gnp1Tier1, np1Tier1}))
		Expect(tiers[2].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Default, knp1Default, gnp1Default}))
	})

	It("should handle reordering of policies when deleting a policy", func() {
		By("calling GetOrderedTiers to perform initial ordering")
		tiers := tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[0].Tier).To(Equal(tier1))
		Expect(tiers[1].Tier).To(Equal(tier2))
		Expect(tiers[2].Tier).To(Equal(tierDefault))

		By("checking sorted policies in each tier")
		Expect(tiers[0].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier1, gnp1Tier1}))
		Expect(tiers[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier2, gnp1Tier2}))
		Expect(tiers[2].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Default, knp1Default, gnp1Default}))

		By("deleting a policy in each tier")
		tester.DeleteNetworkPolicy(Tier1, Name1, Namespace1)
		tester.DeleteGlobalNetworkPolicy(Tier2, Name1)
		tester.DeleteK8sNetworkPolicy(Name1, Namespace1)

		By("calling GetOrderedTiers to perform reordering")
		tiers = tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))

		By("checking sorted policies in each tier")
		Expect(tiers[0].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{gnp1Tier1}))
		Expect(tiers[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Tier2}))
		Expect(tiers[2].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Default, gnp1Default}))
	})

	It("should handle reordering of tiers when deleting a tier", func() {
		By("checking tier order")
		tiers := tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(3))
		Expect(tiers[0].Tier).To(Equal(tier1))
		Expect(tiers[1].Tier).To(Equal(tier2))
		Expect(tiers[2].Tier).To(Equal(tierDefault))

		By("deleting tier2")
		tester.DeleteTier(Tier2)

		By("checking tier order")
		tiers = tester.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(2))
		Expect(tiers[0].Tier).To(Equal(tier1))
		Expect(tiers[1].Tier).To(Equal(tierDefault))
	})

	It("should filter policies and tiers based on endpoint applied policies", func() {
		By("creating a pod and hack the applied policies to contain some in tier1 and default tier")
		res := tester.SetPod(Name1, Namespace1, NoLabels, IP1, Name1, 0)
		ep := tester.Get(resources.GetResourceID(res)).(*xrefcache.CacheEntryEndpoint)
		ep.AppliedPolicies = set.New[apiv3.ResourceID]()
		ep.AppliedPolicies.Add(resources.GetResourceID(gnp1Tier1))
		ep.AppliedPolicies.Add(resources.GetResourceID(knp1Default))
		ep.AppliedPolicies.Add(resources.GetResourceID(np1Default))

		By("checking tier order")
		tiers := ep.GetOrderedTiersAndPolicies()
		Expect(tiers).To(HaveLen(2))
		Expect(tiers[0].Tier).To(Equal(tier1))
		Expect(tiers[1].Tier).To(Equal(tierDefault))

		By("checking sorted policies in each tier")
		Expect(tiers[0].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{gnp1Tier1}))
		Expect(tiers[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{np1Default, knp1Default}))
	})
})
