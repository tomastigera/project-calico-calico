// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package xrefcache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	. "github.com/projectcalico/calico/compliance/internal/testutils"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
)

// The network policy rule selector pseudo resources are managed internally through the NetworkPolicyRuleSelectorManager.
// This component handles the creation and deletion of the rule selector pseudo resources. To test this code, easiest
// thing is to create a bunch of real policies with rule selectors and validate the management of the rule selector
// pseudo resources and their augmented linkage data.
//
// We can do these tests with the GlobalNetworkPolicy resource only since we test the correct decomposition of the
// different network policy resource types into the v3/v1 components separately.

var _ = Describe("Basic CRUD of network policies rule selector pseudo resource types", func() {
	var tester *XrefCacheTester

	BeforeEach(func() {
		tester = NewXrefCacheTester()
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())
	})

	It("should handle basic CRUD of a single rule selector pseudo resource", func() {
		By("applying a GlobalNetworkPolicy with no rules")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)

		By("checking the rule selector cache has no entries")
		ids := tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(0))

		By("applying a GlobalNetworkPolicy, ingress, one allow  source rule with all() selector")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, SelectAll, NoNamespaceSelector),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(1))
		Expect(ids).To(ConsistOf([]string{"all()"}))
		entry := tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		np := tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(1))

		By("applying a second GlobalNetworkPolicy, ingress, one allow source rule with all() selector")
		tester.SetGlobalNetworkPolicy(TierDefault, Name2, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, SelectAll, NoNamespaceSelector),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(1))
		Expect(ids).To(ConsistOf([]string{"all()"}))
		entry = tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(2))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(1))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(1))

		By("deleting the first network policy")
		tester.DeleteGlobalNetworkPolicy(TierDefault, Name1)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(1))
		Expect(ids).To(ConsistOf([]string{"all()"}))
		entry = tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(1))

		By("deleting the second network policy")
		tester.DeleteGlobalNetworkPolicy(TierDefault, Name2)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(0))
	})

	It("should handle basic CRUD of multiple rule selector pseudo resources", func() {
		By("applying a GlobalNetworkPolicy with no rules")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{},
			nil,
			&Order1,
		)

		By("checking the rule selector cache has no entries")
		ids := tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(0))

		By("applying a GlobalNetworkPolicy, ingress two allow source, one allow dest")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, SelectAll, NoNamespaceSelector),
				CalicoRuleSelectors(Allow, Destination, Select1, Select2),
				CalicoRuleSelectors(Allow, Source, Select2, Select3),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings - the dest rule won't count")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(2))
		entry := tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		entry = tester.GetGNPRuleSelectorCacheEntry(Select2, Select3)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		np := tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(2))

		By("applying a second GlobalNetworkPolicy, ingress, two allow source, one overlaps with first GNP")
		tester.SetGlobalNetworkPolicy(TierDefault, Name2, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, Select1, Select2),
				CalicoRuleSelectors(Allow, Source, Select2, Select3),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(3))
		entry = tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		entry = tester.GetGNPRuleSelectorCacheEntry(Select1, Select2)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		entry = tester.GetGNPRuleSelectorCacheEntry(Select2, Select3)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(2))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(2))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(2))

		By("Updating the second GlobalNetworkPolicy, to change overlapping entries (and include unhandle deny)")
		tester.SetGlobalNetworkPolicy(TierDefault, Name2, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, SelectAll, NoNamespaceSelector),
				CalicoRuleSelectors(Allow, Source, Select1, Select2),
				CalicoRuleSelectors(Deny, Source, Select2, Select3),
			},
			nil,
			&Order1,
		)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(3))
		entry = tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(2))
		entry = tester.GetGNPRuleSelectorCacheEntry(Select1, Select2)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		entry = tester.GetGNPRuleSelectorCacheEntry(Select2, Select3)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(2))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(2))

		By("deleting the second network policy")
		tester.DeleteGlobalNetworkPolicy(TierDefault, Name2)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(2))
		entry = tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		entry = tester.GetGNPRuleSelectorCacheEntry(Select2, Select3)
		Expect(entry).ToNot(BeNil())
		Expect(entry.Policies.Len()).To(Equal(1))
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors).To(HaveLen(2))

		By("deleting the first network policy")
		tester.DeleteGlobalNetworkPolicy(TierDefault, Name1)

		By("checking the cache settings")
		ids = tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(0))
	})

	It("should handle Netset-RuleSelector-Policy linkages and config calculation", func() {
		By("applying gnp1, with an ingress allow all() rule")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, SelectAll, NoNamespaceSelector),
			},
			nil,
			&Order1,
		)

		By("applying gnp2, with an ingress allow select2 rule")
		tester.SetGlobalNetworkPolicy(TierDefault, Name2, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, Select2, NoNamespaceSelector),
			},
			nil,
			&Order1,
		)

		By("creating ns1 with label1 and internet exposed")
		tester.SetGlobalNetworkSet(Name1, Label1, Public)

		By("creating ns2 with label2 and all addresses private")
		tester.SetGlobalNetworkSet(Name2, Label2, Private)

		By("checking all() rule matches ns1/ns2/gnp1 and effective config is 'internet exposed'")
		r := tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(r).ToNot(BeNil())
		Expect(r.Policies.Len()).To(Equal(1))
		Expect(r.NetworkSets.Len()).To(Equal(2))
		Expect(r.NetworkSetFlags & xrefcache.CacheEntryInternetExposed).ToNot(BeZero())

		By("checking gnp1 has inherited the settings from the all() rule (internet exposed ingress)")
		np := tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).ToNot(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryProtectedIngress).ToNot(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryProtectedEgress).To(BeZero())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryInternetExposedIngress | xrefcache.CacheEntryProtectedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		By("updating gnp1, to have only an egress allow all() rule")
		tester.SetGlobalNetworkPolicy(TierDefault, Name1, SelectAll,
			nil,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Destination, SelectAll, NoNamespaceSelector),
			},
			&Order1,
		)

		By("checking gnp1 has inherited the settings from the all() rule (internet exposed egress)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).ToNot(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryProtectedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryProtectedEgress).ToNot(BeZero())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryInternetExposedEgress | xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("checking select2 rule matches ns2/gnp2 and effective config is 'internet not exposed'")
		r = tester.GetGNPRuleSelectorCacheEntry(Select2, NoNamespaceSelector)
		Expect(r).ToNot(BeNil())
		Expect(r.Policies.Len()).To(Equal(1))
		Expect(r.NetworkSets.Len()).To(Equal(1))
		Expect(r.NetworkSetFlags & xrefcache.CacheEntryInternetExposed).To(BeZero())

		By("checking gnp2 has inherited the settings from the select2 rule (internet not exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryProtectedIngress).ToNot(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryProtectedEgress).To(BeZero())
		Expect(np.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		By("updating gnp2 to have an ingress allow *select1* rule")
		tester.SetGlobalNetworkPolicy(TierDefault, Name2, SelectAll,
			[]apiv3.Rule{
				CalicoRuleSelectors(Allow, Source, Select1, NoNamespaceSelector),
			},
			nil,
			&Order1,
		)

		By("checking cache xref and to ensure select2 rule no longer exists")
		r = tester.GetGNPRuleSelectorCacheEntry(Select2, NoNamespaceSelector)
		Expect(r).To(BeNil())

		By("checking select1 rule matches ns1/gnp2 and effective config is 'internet exposed'")
		r = tester.GetGNPRuleSelectorCacheEntry(Select1, NoNamespaceSelector)
		Expect(r).ToNot(BeNil())
		Expect(r.Policies.Len()).To(Equal(1))
		Expect(r.NetworkSets.Len()).To(Equal(1))
		Expect(r.NetworkSetFlags & xrefcache.CacheEntryInternetExposed).ToNot(BeZero())

		By("checking gnp2 has inherited the settings from the select1 rule (internet exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).ToNot(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())

		By("deleting ns1")
		tester.DeleteGlobalNetworkSet(Name1)

		By("checking select1 has no nets and all has 1 net")
		r = tester.GetGNPRuleSelectorCacheEntry(Select1, NoNamespaceSelector)
		Expect(r).ToNot(BeNil())
		Expect(r.NetworkSets.Len()).To(Equal(0))
		r = tester.GetGNPRuleSelectorCacheEntry(SelectAll, NoNamespaceSelector)
		Expect(r).ToNot(BeNil())
		Expect(r.NetworkSets.Len()).To(Equal(1))
		ns := tester.GetGlobalNetworkSet(Name2)
		Expect(ns).ToNot(BeNil())
		Expect(ns.PolicyRuleSelectors.Len()).To(Equal(1))

		By("checking gnp1 has inherited the settings from ns2 (internet not exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())

		By("checking gnp2 has inherited the settings from no networksets (i.e. internet not exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())

		By("updating ns2 to have public and private addresses")
		tester.SetGlobalNetworkSet(Name2, Label2, Private|Public)

		By("checking gnp1 has inherited the settings from ns2 (internet is exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).ToNot(BeZero())

		By("checking gnp2 has inherited the settings from no networksets (i.e. internet not exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())

		By("setting ns2 labels to have Label1 and Label2")
		tester.SetGlobalNetworkSet(Name2, Label1|Label2, Private|Public)

		By("checking gnp1 has inherited the settings from ns2 (internet is exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).ToNot(BeZero())

		By("checking gnp2 has inherited the settings from ns2 (internet is exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).ToNot(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())

		By("deleting ns2")
		tester.DeleteGlobalNetworkSet(Name2)

		By("checking gnp1 and gnp2 no longer inherit the settings from ns2")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name1)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())

		By("checking gnp2 has inherited the settings from ns2 (internet is exposed)")
		np = tester.GetGlobalNetworkPolicy(TierDefault, Name2)
		Expect(np).ToNot(BeNil())
		Expect(np.AllowRuleSelectors.Len()).To(Equal(1))
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedIngress).To(BeZero())
		Expect(np.Flags & xrefcache.CacheEntryInternetExposedEgress).To(BeZero())

		By("deleting gnp1 and gnp2")
		tester.DeleteGlobalNetworkPolicy(TierDefault, Name1)
		tester.DeleteGlobalNetworkPolicy(TierDefault, Name2)

		By("checking the rule selector cache has no entries")
		ids := tester.GetCachedRuleSelectors()
		Expect(ids).To(HaveLen(0))
	})
})
