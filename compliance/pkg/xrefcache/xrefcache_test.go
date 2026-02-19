// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	networkingv1 "k8s.io/api/networking/v1"

	. "github.com/projectcalico/calico/compliance/internal/testutils"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

var _ = Describe("xref cache", func() {
	// Ensure  the client resource list is in-sync with the resource helper.
	It("should support in-sync and complete with no injected configuration", func() {
		cache := xrefcache.NewXrefCache(config.MustLoadConfig(), func() {
			log.Info("Healthy notification from xref cache")
		})
		cache.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		cache.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeComplete,
		})
	})
})

type callbacks struct {
	deletes int
	sets    int
	updated map[apiv3.ResourceID]*xrefcache.CacheEntryEndpoint
}

func (c *callbacks) onUpdate(update syncer.Update) {
	if update.Type&xrefcache.EventResourceDeleted != 0 {
		delete(c.updated, update.ResourceID)
		c.deletes++
	} else {
		c.updated[update.ResourceID] = update.Resource.(*xrefcache.CacheEntryEndpoint)
		c.sets++
	}
}

var _ = Describe("xref cache in-scope callbacks", func() {
	var cb *callbacks
	var tester *XrefCacheTester
	var nsID1 apiv3.ResourceID
	var saName1 string
	var saName2 string
	var podID1 apiv3.ResourceID
	var podID2 apiv3.ResourceID
	var podID3 apiv3.ResourceID
	var podID4 apiv3.ResourceID

	BeforeEach(func() {
		tester = NewXrefCacheTester()
		cb = &callbacks{
			updated: make(map[apiv3.ResourceID]*xrefcache.CacheEntryEndpoint),
		}
		ns := tester.SetNamespace(Namespace1, Label1)
		nsID1 = resources.GetResourceID(ns)
		tester.SetNamespace(Namespace2, Label2)
		sa := tester.SetServiceAccount(Name1, Namespace1, Label1)
		saName1 = sa.GetObjectMeta().GetName()
		sa = tester.SetServiceAccount(Name2, Namespace1, Label2)
		saName2 = sa.GetObjectMeta().GetName()
		tester.SetServiceAccount(Name1, Namespace2, Label1)
		tester.SetServiceAccount(Name2, Namespace2, Label2)
		pod := tester.SetPod(Name1, Namespace1, Label1, IP1, Name2, NoPodOptions)
		podID1 = resources.GetResourceID(pod)
		pod = tester.SetPod(Name2, Namespace1, Label2, IP1, Name1, NoPodOptions)
		podID2 = resources.GetResourceID(pod)
		pod = tester.SetPod(Name2, Namespace2, Label1, IP1, Name2, NoPodOptions)
		podID3 = resources.GetResourceID(pod)
		pod = tester.SetPod(Name1, Namespace2, Label2, IP1, Name1, NoPodOptions)
		podID4 = resources.GetResourceID(pod)
		for _, k := range xrefcache.KindsEndpoint {
			tester.RegisterOnUpdateHandler(k, xrefcache.EventInScope, cb.onUpdate)
		}
	})

	It("should flag in-scope endpoints with no endpoint selector", func() {
		_ = tester.RegisterInScopeEndpoints(nil)
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(4))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID2))
		Expect(cb.updated).To(HaveKey(podID3))
		Expect(cb.updated).To(HaveKey(podID4))
	})

	It("should flag in-scope endpoints matching endpoint selector", func() {
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{
			Selector: tester.GetSelector(Select1),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(2))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID3))
	})

	It("should flag in-scope endpoints matching endpoint selector and namespace name", func() {
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{
			Selector: tester.GetSelector(Select1),
			Namespaces: &apiv3.NamesAndLabelsMatch{
				Names: []string{nsID1.Name},
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(1))
		Expect(cb.updated).To(HaveKey(podID1))
	})

	It("should flag in-scope endpoints matching endpoint selector and namespace selector", func() {
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{
			Selector: tester.GetSelector(Select1),
			Namespaces: &apiv3.NamesAndLabelsMatch{
				Selector: tester.GetSelector(Select2),
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(1))
		Expect(cb.updated).To(HaveKey(podID3))

		tester.SetNamespace(Namespace1, Label2)
		Expect(cb.updated).To(HaveLen(2))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID3))
	})

	It("should flag in-scope endpoints matching endpoint selector and service account name", func() {
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{
			Selector: tester.GetSelector(Select2),
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Names: []string{saName1},
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(2))
		Expect(cb.updated).To(HaveKey(podID2))
		Expect(cb.updated).To(HaveKey(podID4))
	})

	It("should flag in-scope endpoints by service account selector", func() {
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Selector: tester.GetSelector(Select2),
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(2))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID3))

		tester.SetServiceAccount(Name1, Namespace1, Label2)
		Expect(cb.updated).To(HaveLen(3))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID2))
		Expect(cb.updated).To(HaveKey(podID3))

		tester.SetServiceAccount(Name1, Namespace2, Label2)
		Expect(cb.updated).To(HaveLen(4))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID2))
		Expect(cb.updated).To(HaveKey(podID3))
		Expect(cb.updated).To(HaveKey(podID4))
	})

	It("should flag in-scope endpoints matching endpoint selector and service account selector", func() {
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{
			Selector: tester.GetSelector(Select1),
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Selector: tester.GetSelector(Select2),
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(2))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID3))
	})

	It("should flag in-scope endpoints multiple service account names", func() {
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{
			ServiceAccounts: &apiv3.NamesAndLabelsMatch{
				Names: []string{saName1, saName2},
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cb.updated).To(HaveLen(0))
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		Expect(cb.updated).To(HaveLen(4))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.updated).To(HaveKey(podID2))
		Expect(cb.updated).To(HaveKey(podID3))
		Expect(cb.updated).To(HaveKey(podID4))
	})
})

var _ = Describe("xref cache multiple update transactions", func() {
	It("should handle an update transaction containing create and delete of the same resource when in-sync", func() {
		tester := NewXrefCacheTester()
		By("Setting in-sync")
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		cb := &callbacks{
			updated: make(map[apiv3.ResourceID]*xrefcache.CacheEntryEndpoint),
		}

		By("Registering all endpoints as in-scope and registering for inscope events")
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{})
		Expect(err).NotTo(HaveOccurred())
		for _, k := range xrefcache.KindsEndpoint {
			tester.RegisterOnUpdateHandler(k, xrefcache.EventInScope, cb.onUpdate)
		}

		By("Setting tester to accumlate updates and creating a pod and service account")
		tester.AccumlateUpdates = true
		tester.SetNamespace(Namespace1, Label1)
		tester.SetPod(Name1, Namespace1, Label1, IP1, Name2, NoPodOptions)

		By("Setting tester to no longer accumlate updates and deleting the pod")
		tester.AccumlateUpdates = false
		tester.DeletePod(Name1, Namespace1)

		By("Checking both updates")
		Expect(cb.updated).To(HaveLen(0))
		Expect(cb.sets).To(Equal(1))
		Expect(cb.deletes).To(Equal(1))
	})

	It("should handle an update transaction containing create, delete, recreate of the same resource when in-sync", func() {
		tester := NewXrefCacheTester()
		By("Setting in-sync")
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})
		cb := &callbacks{
			updated: make(map[apiv3.ResourceID]*xrefcache.CacheEntryEndpoint),
		}

		By("Registering all endpoints as in-scope and registering for inscope events")
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{})
		Expect(err).NotTo(HaveOccurred())
		for _, k := range xrefcache.KindsEndpoint {
			tester.RegisterOnUpdateHandler(k, xrefcache.EventInScope, cb.onUpdate)
		}

		By("Setting tester to accumlate updates and creating a pod and service account")
		tester.AccumlateUpdates = true
		tester.SetNamespace(Namespace1, Label1)
		tester.SetPod(Name1, Namespace1, Label1, IP1, Name2, NoPodOptions)

		By("Deleting the pod")
		tester.DeletePod(Name1, Namespace1)

		By("Setting tester to no longer accumlate updates and recreating the pod")
		tester.AccumlateUpdates = false
		pod := tester.SetPod(Name1, Namespace1, Label1, IP1, Name2, NoPodOptions)
		podID1 := resources.GetResourceID(pod)

		By("Checking for all three updates and newly created pod")
		Expect(cb.updated).To(HaveLen(1))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.sets).To(Equal(2))
		Expect(cb.deletes).To(Equal(1))
	})

	It("should handle an update transaction containing create and delete of the same resource before being in-sync", func() {
		tester := NewXrefCacheTester()
		cb := &callbacks{
			updated: make(map[apiv3.ResourceID]*xrefcache.CacheEntryEndpoint),
		}

		By("Registering all endpoints as in-scope and registering for inscope events")
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{})
		Expect(err).NotTo(HaveOccurred())
		for _, k := range xrefcache.KindsEndpoint {
			tester.RegisterOnUpdateHandler(k, xrefcache.EventInScope, cb.onUpdate)
		}

		By("Setting tester to accumlate updates and creating a pod and service account")
		tester.AccumlateUpdates = true
		tester.SetNamespace(Namespace1, Label1)
		tester.SetPod(Name1, Namespace1, Label1, IP1, Name2, NoPodOptions)

		By("Setting tester to no longer accumlate updates and deleting the pod")
		tester.AccumlateUpdates = false
		tester.DeletePod(Name1, Namespace1)

		By("Setting in-sync")
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})

		By("Checking for no updates")
		Expect(cb.updated).To(HaveLen(0))
		Expect(cb.sets).To(Equal(0))
		Expect(cb.deletes).To(Equal(0))
	})

	It("should handle an update transaction containing create, delete, recreate of the same resource before being in-sync", func() {
		tester := NewXrefCacheTester()
		cb := &callbacks{
			updated: make(map[apiv3.ResourceID]*xrefcache.CacheEntryEndpoint),
		}

		By("Registering all endpoints as in-scope and registering for inscope events")
		err := tester.RegisterInScopeEndpoints(&apiv3.EndpointsSelection{})
		Expect(err).NotTo(HaveOccurred())
		for _, k := range xrefcache.KindsEndpoint {
			tester.RegisterOnUpdateHandler(k, xrefcache.EventInScope, cb.onUpdate)
		}

		By("Setting tester to accumlate updates and creating a pod and service account")
		tester.AccumlateUpdates = true
		tester.SetNamespace(Namespace1, Label1)
		tester.SetPod(Name1, Namespace1, Label1, IP1, Name2, NoPodOptions)

		By("Deleting the pod")
		tester.DeletePod(Name1, Namespace1)

		By("Setting tester to no longer accumlate updates and recreating the pod")
		tester.AccumlateUpdates = false
		pod := tester.SetPod(Name1, Namespace1, Label1, IP1, Name2, NoPodOptions)
		podID1 := resources.GetResourceID(pod)

		By("Checking for no updates")
		Expect(cb.updated).To(HaveLen(0))
		Expect(cb.sets).To(Equal(0))
		Expect(cb.deletes).To(Equal(0))

		By("Setting in-sync")
		tester.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})

		By("Checking for just a single update for the newly created pod")
		Expect(cb.updated).To(HaveLen(1))
		Expect(cb.updated).To(HaveKey(podID1))
		Expect(cb.deletes).To(Equal(0))
		Expect(cb.sets).To(Equal(1))
	})

	It("should handle AAPIS versions of each calico resource type", func() {
		tester := NewXrefCacheTester()

		By("Creating, storing and then deleting a calico tier")
		var tier *apiv3.Tier
		tester.SetTier(Name1, Order1)
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoTiers)).To(HaveLen(1))
		_ = tester.EachCacheEntry(resources.TypeCalicoTiers, func(ce xrefcache.CacheEntry) error {
			tier = ce.GetCalicoV3().(*apiv3.Tier)
			tester.OnUpdates([]syncer.Update{
				{Type: syncer.UpdateTypeDeleted, ResourceID: resources.GetResourceID(ce.GetCalicoV3())},
			})
			return nil
		})
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoTiers)).To(HaveLen(0))

		By("Creating a AAPIS tier (from the original calico tier) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(tier),
				Resource:   &apiv3.Tier{TypeMeta: tier.TypeMeta, ObjectMeta: tier.ObjectMeta, Spec: tier.Spec},
			},
		})
		res := tester.Get(resources.GetResourceID(tier))
		Expect(res).ToNot(BeNil())
		Expect(res.GetCalicoV3()).To(Equal(tier))

		By("Creating, storing and then deleting a calico global network set")
		var gns *apiv3.GlobalNetworkSet
		tester.SetGlobalNetworkSet(Name1, Label1, Public|Private)
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoGlobalNetworkSets)).To(HaveLen(1))
		_ = tester.EachCacheEntry(resources.TypeCalicoGlobalNetworkSets, func(ce xrefcache.CacheEntry) error {
			gns = ce.GetCalicoV3().(*apiv3.GlobalNetworkSet)
			tester.OnUpdates([]syncer.Update{
				{Type: syncer.UpdateTypeDeleted, ResourceID: resources.GetResourceID(ce.GetCalicoV3())},
			})
			return nil
		})
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoGlobalNetworkSets)).To(HaveLen(0))

		By("Creating a AAPIS gns (from the original calico gns) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(gns),
				Resource:   &apiv3.GlobalNetworkSet{TypeMeta: gns.TypeMeta, ObjectMeta: gns.ObjectMeta, Spec: gns.Spec},
			},
		})
		res = tester.Get(resources.GetResourceID(gns))
		Expect(res).ToNot(BeNil())
		Expect(res.GetCalicoV3()).To(Equal(gns))

		By("Creating, storing and then deleting a calico namespaced network set")
		var netset *apiv3.NetworkSet
		tester.SetNetworkSet(Name1, Namespace1, Label1, Public|Private)
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoNetworkSets)).To(HaveLen(1))
		_ = tester.EachCacheEntry(resources.TypeCalicoNetworkSets, func(ce xrefcache.CacheEntry) error {
			netset = ce.GetCalicoV3().(*apiv3.NetworkSet)
			tester.OnUpdates([]syncer.Update{
				{Type: syncer.UpdateTypeDeleted, ResourceID: resources.GetResourceID(ce.GetCalicoV3())},
			})
			return nil
		})
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoNetworkSets)).To(HaveLen(0))

		By("Creating a AAPIS netset (from the original calico netset) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(netset),
				Resource:   &apiv3.NetworkSet{TypeMeta: netset.TypeMeta, ObjectMeta: netset.ObjectMeta, Spec: netset.Spec},
			},
		})
		res = tester.Get(resources.GetResourceID(netset))
		Expect(res).ToNot(BeNil())
		Expect(res.GetCalicoV3()).To(Equal(netset))

		By("Creating, storing and then deleting a calico global network policy")
		var gnp *apiv3.GlobalNetworkPolicy
		tester.SetGlobalNetworkPolicy(Name1, Name1, Select1, []apiv3.Rule{}, nil, &Order1)
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoGlobalNetworkPolicies)).To(HaveLen(1))
		_ = tester.EachCacheEntry(resources.TypeCalicoGlobalNetworkPolicies, func(ce xrefcache.CacheEntry) error {
			gnp = ce.GetCalicoV3().(*apiv3.GlobalNetworkPolicy)
			tester.OnUpdates([]syncer.Update{
				{Type: syncer.UpdateTypeDeleted, ResourceID: resources.GetResourceID(ce.GetCalicoV3())},
			})
			return nil
		})
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoGlobalNetworkPolicies)).To(HaveLen(0))

		By("Creating a AAPIS gnp (from the original calico gnp) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(gnp),
				Resource:   &apiv3.GlobalNetworkPolicy{TypeMeta: gnp.TypeMeta, ObjectMeta: gnp.ObjectMeta, Spec: gnp.Spec},
			},
		})
		res = tester.Get(resources.GetResourceID(gnp))
		Expect(res).ToNot(BeNil())
		Expect(res.GetCalicoV3()).To(Equal(gnp))

		By("Creating, storing and then deleting a calico network policy")
		var np *apiv3.NetworkPolicy
		tester.SetNetworkPolicy(Name1, Name1, Namespace1, Select1, nil, []apiv3.Rule{}, &Order10)
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoNetworkPolicies)).To(HaveLen(1))
		_ = tester.EachCacheEntry(resources.TypeCalicoNetworkPolicies, func(ce xrefcache.CacheEntry) error {
			np = ce.GetCalicoV3().(*apiv3.NetworkPolicy)
			tester.OnUpdates([]syncer.Update{
				{Type: syncer.UpdateTypeDeleted, ResourceID: resources.GetResourceID(ce.GetCalicoV3())},
			})
			return nil
		})
		Expect(tester.XrefCache.GetCachedResourceIDs(resources.TypeCalicoNetworkPolicies)).To(HaveLen(0))

		By("Creating a AAPIS np (from the original calico np) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(np),
				Resource:   &apiv3.NetworkPolicy{TypeMeta: np.TypeMeta, ObjectMeta: np.ObjectMeta, Spec: np.Spec},
			},
		})
		res = tester.Get(resources.GetResourceID(np))
		Expect(res).ToNot(BeNil())
		Expect(res.GetCalicoV3()).To(Equal(np))

		By("Creating, storing and then deleting a staged calico network policy")
		snp := tester.SetStagedNetworkPolicy(Name1, Name1, Namespace1, Select1, nil, []apiv3.Rule{}, &Order10, apiv3.StagedActionSet).(*apiv3.StagedNetworkPolicy)
		ids := tester.GetCachedResourceIDs(resources.TypeCalicoStagedNetworkPolicies)
		Expect(ids).To(HaveLen(1))

		// Get the entry from the cache - the staged policy is converted to the equivalent v3 type.
		var ok bool
		res = tester.Get(ids[0])
		Expect(res).ToNot(BeNil())
		snp2, ok := res.GetPrimary().(*apiv3.StagedNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(snp2).To(Equal(snp))

		// Delete and re-check cache
		tester.DeleteStagedNetworkPolicy(Name1, Name1, Namespace1)
		ids = tester.GetCachedResourceIDs(resources.TypeCalicoStagedNetworkPolicies)
		Expect(ids).To(HaveLen(0))

		By("Creating a AAPIS staged np (from the original calico staged np) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(snp),
				Resource:   &apiv3.StagedNetworkPolicy{TypeMeta: snp.TypeMeta, ObjectMeta: snp.ObjectMeta, Spec: snp.Spec},
			},
		})
		res = tester.Get(resources.GetResourceID(snp))
		Expect(res).ToNot(BeNil())
		snp2, ok = res.GetPrimary().(*apiv3.StagedNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(snp2).To(Equal(snp))

		By("Creating, storing and then deleting a staged calico global network policy")
		sgnp := tester.SetStagedGlobalNetworkPolicy(Name1, Name1, Select1, nil, []apiv3.Rule{}, &Order10, apiv3.StagedActionSet).(*apiv3.StagedGlobalNetworkPolicy)
		ids = tester.GetCachedResourceIDs(resources.TypeCalicoStagedGlobalNetworkPolicies)
		Expect(ids).To(HaveLen(1))

		// Get the entry from the cache - the staged policy is converted to the equivalent v3 type.
		res = tester.Get(ids[0])
		Expect(res).ToNot(BeNil())
		sgnp2, ok := res.GetPrimary().(*apiv3.StagedGlobalNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(sgnp2).To(Equal(sgnp))

		// Delete and re-check cache
		tester.DeleteStagedGlobalNetworkPolicy(Name1, Name1)
		ids = tester.GetCachedResourceIDs(resources.TypeCalicoStagedGlobalNetworkPolicies)
		Expect(ids).To(HaveLen(0))

		By("Creating a AAPIS staged np (from the original calico staged np) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(sgnp),
				Resource:   &apiv3.StagedGlobalNetworkPolicy{TypeMeta: sgnp.TypeMeta, ObjectMeta: sgnp.ObjectMeta, Spec: sgnp.Spec},
			},
		})
		res = tester.Get(resources.GetResourceID(sgnp))
		Expect(res).ToNot(BeNil())
		sgnp2, ok = res.GetPrimary().(*apiv3.StagedGlobalNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(sgnp2).To(Equal(sgnp))

		By("Creating, storing and then deleting a staged kubernetes network policy")
		sknp := tester.SetStagedKubernetesNetworkPolicy(Name1, Namespace1, Select1, []networkingv1.NetworkPolicyIngressRule{}, nil, apiv3.StagedActionSet).(*apiv3.StagedKubernetesNetworkPolicy)
		ids = tester.GetCachedResourceIDs(resources.TypeCalicoStagedKubernetesNetworkPolicies)
		Expect(ids).To(HaveLen(1))

		// Get the entry from the cache - the staged policy is converted to the equivalent v3 type.
		res = tester.Get(ids[0])
		Expect(res).ToNot(BeNil())
		sknp2, ok := res.GetPrimary().(*apiv3.StagedKubernetesNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(sknp2).To(Equal(sknp))

		// Delete and re-check cache
		tester.DeleteStagedKubernetesNetworkPolicy(Name1, Namespace1)
		ids = tester.GetCachedResourceIDs(resources.TypeCalicoStagedKubernetesNetworkPolicies)
		Expect(ids).To(HaveLen(0))

		By("Creating a AAPIS staged np (from the original calico staged np) and checking the cached result matches")
		tester.OnUpdates([]syncer.Update{
			{
				Type:       syncer.UpdateTypeSet,
				ResourceID: resources.GetResourceID(sknp),
				Resource:   &apiv3.StagedKubernetesNetworkPolicy{TypeMeta: sknp.TypeMeta, ObjectMeta: sknp.ObjectMeta, Spec: sknp.Spec},
			},
		})
		res = tester.Get(resources.GetResourceID(sknp))
		Expect(res).ToNot(BeNil())
		sknp2, ok = res.GetPrimary().(*apiv3.StagedKubernetesNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(sknp2).To(Equal(sknp))
	})

	It("should handle policy ordering of staged policy sets and deletion from staged policy deletes", func() {
		tester := NewXrefCacheTester()

		By("Creating v3 policy types")
		tester.SetTier(Name1, Order1)
		tester.SetDefaultTier()

		gnp := tester.SetGlobalNetworkPolicy(Name1, Name1, Select1, []apiv3.Rule{}, nil, &Order1).(*apiv3.GlobalNetworkPolicy)
		np := tester.SetNetworkPolicy(Name1, Name1, Namespace1, Select1, nil, []apiv3.Rule{}, &Order10).(*apiv3.NetworkPolicy)
		knp := tester.SetK8sNetworkPolicy(Name1, Namespace1, Select1, []networkingv1.NetworkPolicyIngressRule{}, nil).(*networkingv1.NetworkPolicy)

		res := tester.Get(resources.GetResourceID(gnp))
		Expect(res).ToNot(BeNil())
		cegnp, ok := res.(*xrefcache.CacheEntryNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(cegnp.GetCalicoV3()).To(Equal(gnp))
		Expect(cegnp.IsStaged()).To(BeFalse())

		res = tester.Get(resources.GetResourceID(np))
		Expect(res).ToNot(BeNil())
		cenp, ok := res.(*xrefcache.CacheEntryNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(cenp.GetCalicoV3()).To(Equal(np))
		Expect(cenp.IsStaged()).To(BeFalse())

		res = tester.Get(resources.GetResourceID(knp))
		Expect(res).ToNot(BeNil())
		ceknp, ok := res.(*xrefcache.CacheEntryNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(ceknp.GetPrimary()).To(Equal(knp))
		Expect(ceknp.IsStaged()).To(BeFalse())

		By("Creating staged policy sets")
		sgnp := tester.SetStagedGlobalNetworkPolicy(Name1, Name1, Select1, []apiv3.Rule{}, nil, &Order1, "")
		snp := tester.SetStagedNetworkPolicy(Name1, Name1, Namespace1, Select1, nil, []apiv3.Rule{}, &Order10, apiv3.StagedActionSet)
		sknp := tester.SetStagedKubernetesNetworkPolicy(Name1, Namespace1, Select1, []networkingv1.NetworkPolicyIngressRule{}, nil, "")

		res = tester.Get(resources.GetResourceID(sgnp))
		Expect(res).ToNot(BeNil())
		cesgnp, ok := res.(*xrefcache.CacheEntryNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(cesgnp.IsStaged()).To(BeTrue())

		res = tester.Get(resources.GetResourceID(snp))
		Expect(res).ToNot(BeNil())
		cesnp, ok := res.(*xrefcache.CacheEntryNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(cesnp.IsStaged()).To(BeTrue())

		res = tester.Get(resources.GetResourceID(sknp))
		Expect(res).ToNot(BeNil())
		cesknp, ok := res.(*xrefcache.CacheEntryNetworkPolicy)
		Expect(ok).To(BeTrue())
		Expect(cesknp.IsStaged()).To(BeTrue())

		By("Checking staged policies come immediately before the v3 policy")
		ordered := tester.GetOrderedTiersAndPolicies()
		Expect(ordered).To(HaveLen(2))
		Expect(ordered[0].Tier.GetObjectMeta().GetName()).To(Equal("tier-1"))
		Expect(ordered[0].OrderedPolicies).To(HaveLen(4))

		// Check fields individually to give better error messages.
		exp := []*xrefcache.CacheEntryNetworkPolicy{cegnp, cesgnp, cenp, cesnp}
		for i, op := range ordered[0].OrderedPolicies {
			Expect(op.GetObjectMeta().GetName()).To(Equal(exp[i].GetObjectMeta().GetName()), "name mismatch at index %d", i)
			Expect(op.GetObjectMeta().GetNamespace()).To(Equal(exp[i].GetObjectMeta().GetNamespace()), "namespace mismatch at index %d", i)
			Expect(op.GetObjectKind().GroupVersionKind().Kind).To(Equal(exp[i].GetObjectKind().GroupVersionKind().Kind), "kind mismatch at index %d", i)
			Expect(op.IsStaged()).To(Equal(exp[i].IsStaged()), "staged mismatch at index %d", i)
			Expect(op).To(Equal(exp[i]), "mismatch at index %d", i)
		}
		// Make sure the full slices are equal to catch anything we missed.
		Expect(ordered[0].OrderedPolicies).To(Equal(exp))

		Expect(ordered[1].Tier.GetObjectMeta().GetName()).To(Equal("default"))
		Expect(ordered[1].OrderedPolicies).To(HaveLen(2))
		Expect(ordered[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{ceknp, cesknp}))

		By("Creating staged policy deletes")
		tester.SetStagedGlobalNetworkPolicy(Name1, Name1, Select1, []apiv3.Rule{}, nil, &Order1, apiv3.StagedActionDelete)
		tester.SetStagedNetworkPolicy(Name1, Name1, Namespace1, Select1, nil, []apiv3.Rule{}, &Order10, apiv3.StagedActionDelete)
		tester.SetStagedKubernetesNetworkPolicy(Name1, Namespace1, Select1, []networkingv1.NetworkPolicyIngressRule{}, nil, apiv3.StagedActionDelete)

		res = tester.Get(resources.GetResourceID(sgnp))
		Expect(res).To(BeNil())

		res = tester.Get(resources.GetResourceID(snp))
		Expect(res).To(BeNil())

		res = tester.Get(resources.GetResourceID(sknp))
		Expect(res).To(BeNil())

		By("Checking staged policies are no longer in ordered tiers")
		ordered = tester.GetOrderedTiersAndPolicies()
		Expect(ordered).To(HaveLen(2))
		Expect(ordered[0].Tier.GetObjectMeta().GetName()).To(Equal("tier-1"))
		Expect(ordered[0].OrderedPolicies).To(HaveLen(2))
		Expect(ordered[0].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{cegnp, cenp}))

		Expect(ordered[1].Tier.GetObjectMeta().GetName()).To(Equal("default"))
		Expect(ordered[1].OrderedPolicies).To(HaveLen(1))
		Expect(ordered[1].OrderedPolicies).To(Equal([]*xrefcache.CacheEntryNetworkPolicy{ceknp}))
	})
})
