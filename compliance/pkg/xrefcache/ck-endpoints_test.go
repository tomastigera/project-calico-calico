// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package xrefcache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/compliance/internal/testutils"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

var _ = Describe("Pods cache verification", func() {
	var tester *testutils.XrefCacheTester

	BeforeEach(func() {
		tester = testutils.NewXrefCacheTester()
	})

	It("should handle basic CRUD of a pod with no other resources", func() {
		By("sending in-sync")
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("applying a pod")
		tester.SetPod(testutils.Name1, testutils.Namespace1, testutils.NoLabels, testutils.IP1, testutils.NoServiceAccount, testutils.NoPodOptions)

		By("checking the cache settings")
		ep := tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Flags).To(BeZero())
		Expect(ep.AppliedPolicies.Len()).To(BeZero())
		Expect(ep.GetFlowLogAggregationName()).To(Equal(ep.GetObjectMeta().GetName()))

		By("applying another pod in a different namespace")
		tester.SetPod(testutils.Name1, testutils.Namespace2, testutils.NoLabels, testutils.IP2, testutils.NoServiceAccount, testutils.NoPodOptions)

		By("checking the cache settings")
		ep = tester.GetPod(testutils.Name1, testutils.Namespace2)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Flags).To(BeZero())
		Expect(ep.AppliedPolicies.Len()).To(BeZero())
		Expect(ep.GetFlowLogAggregationName()).To(Equal(ep.GetObjectMeta().GetName()))

		By("deleting the first pod")
		tester.DeletePod(testutils.Name1, testutils.Namespace1)

		By("checking the cache settings")
		ep = tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).To(BeNil())

		By("deleting the second pod")
		tester.DeletePod(testutils.Name1, testutils.Namespace2)

		By("checking the cache settings")
		ep = tester.GetPod(testutils.Name1, testutils.Namespace2)
		Expect(ep).To(BeNil())
	})

	It("should handle a pod with Envoy enabled", func() {
		By("applying a pod")
		tester.SetPod(testutils.Name1, testutils.Namespace1, testutils.NoLabels, testutils.IP1, testutils.NoServiceAccount, testutils.PodOptEnvoyEnabled)

		By("sending in-sync")
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("checking the cache settings")
		ep := tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Flags).To(Equal(xrefcache.CacheEntryEnvoyEnabled))
		Expect(ep.AppliedPolicies.Len()).To(BeZero())
		Expect(ep.GetFlowLogAggregationName()).To(Equal(ep.GetObjectMeta().GetName()))

		By("deleting the first pod")
		tester.DeletePod(testutils.Name1, testutils.Namespace1)

		By("checking the cache settings")
		ep = tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).To(BeNil())
	})

	It("should handle a pod with generate name", func() {
		By("sending in-sync")
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("applying a pod")
		tester.SetPod(testutils.Name1, testutils.Namespace1, testutils.NoLabels, testutils.IP1, testutils.NoServiceAccount, testutils.PodOptSetGenerateName)

		By("checking the cache settings")
		ep := tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Flags).To(BeZero())
		Expect(ep.AppliedPolicies.Len()).To(BeZero())
		Expect(ep.GetFlowLogAggregationName()).To(Equal("pod-*"))

		By("deleting the first pod")
		tester.DeletePod(testutils.Name1, testutils.Namespace1)

		By("checking the cache settings")
		ep = tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).To(BeNil())
	})

	It("should handle basic CRUD of a host endpoint", func() {
		By("sending in-sync")
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("applying a host endpoint")
		tester.SetHostEndpoint(testutils.Name1, testutils.NoLabels, testutils.IP1)

		By("checking the cache settings")
		ep := tester.GetHostEndpoint(testutils.Name1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Flags).To(BeZero())
		Expect(ep.AppliedPolicies.Len()).To(BeZero())
		// SetHostEndpoint always sets node to node1.
		Expect(ep.GetFlowLogAggregationName()).To(Equal("node1"))

		By("applying a different host endpoint")
		tester.SetHostEndpoint(testutils.Name2, testutils.NoLabels, testutils.IP2)

		By("checking the cache settings")
		ep = tester.GetHostEndpoint(testutils.Name2)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Flags).To(BeZero())
		Expect(ep.AppliedPolicies.Len()).To(BeZero())
		// SetHostEndpoint always sets node to node1.
		Expect(ep.GetFlowLogAggregationName()).To(Equal("node1"))

		By("deleting the first host endpoint")
		tester.DeleteHostEndpoint(testutils.Name1)

		By("checking the cache settings")
		ep = tester.GetHostEndpoint(testutils.Name1)
		Expect(ep).To(BeNil())

		By("deleting the second host endpoint")
		tester.DeleteHostEndpoint(testutils.Name2)

		By("checking the cache settings")
		ep = tester.GetHostEndpoint(testutils.Name2)
		Expect(ep).To(BeNil())
	})

	It("should track the set of applied policies and overall settings", func() {
		By("applying np1 select1 with an ingress allow select1 rule")
		tester.SetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Select1,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Source, testutils.Select1, testutils.NoNamespaceSelector),
			},
			nil,
			&testutils.Order1,
		)

		By("applying np2 select2 with an ingress allow select2 rule")
		tester.SetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name2, testutils.Select2,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Source, testutils.Select2, testutils.NoNamespaceSelector),
			},
			nil,
			&testutils.Order1,
		)

		By("applying np1 select1 with an egress allow select1 rule")
		tester.SetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1, testutils.Select1,
			nil,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Destination, testutils.Select1, testutils.NoNamespaceSelector),
			},
			&testutils.Order1,
		)

		By("creating ns1 with label3 and internet exposed")
		tester.SetGlobalNetworkSet(testutils.Name1, testutils.Label1, testutils.Public)

		By("creating ns2 with label2 and all addresses private")
		tester.SetGlobalNetworkSet(testutils.Name2, testutils.Label2, testutils.Private)

		By("creating a pod1 with label 1")
		tester.SetPod(testutils.Name1, testutils.Namespace1, testutils.Label1, testutils.IP1, testutils.NoServiceAccount, testutils.NoPodOptions)

		By("checking pod1 xref with two policies in the cache")
		pod := tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(pod).NotTo(BeNil())
		Expect(pod.AppliedPolicies.Len()).To(Equal(2))
		gnp1 := tester.GetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name1)
		Expect(gnp1).NotTo(BeNil())
		Expect(gnp1.SelectedPods.Len()).To(Equal(1))
		gnp2 := tester.GetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name2)
		Expect(gnp2).NotTo(BeNil())
		Expect(gnp2.SelectedPods.Len()).To(Equal(0))
		np1 := tester.GetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1)
		Expect(np1).NotTo(BeNil())
		Expect(np1.SelectedPods.Len()).To(Equal(1))

		By("checking cross-ref calculated flags are not yet set")
		Expect(gnp1.Flags).To(BeZero())
		Expect(np1.Flags).To(BeZero())

		By("sending in-sync")
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("checking cross-ref calculated flags")
		Expect(gnp1.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))
		Expect(np1.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress, // no egress internet because NP won't match a global NS
		))

		By("checking the pod settings have inherited the expected policy configuration from gnp1 and np1")
		Expect(pod.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress | xrefcache.CacheEntryProtectedEgress,
		))

		By("updating np1 to include a namespace selector")
		tester.SetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1, testutils.Select1,
			nil,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Destination, testutils.Select1, testutils.Select1),
			},
			&testutils.Order1,
		)

		By("checking the np1 flags have been updated")
		np1 = tester.GetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1)
		Expect(np1).NotTo(BeNil())
		Expect(np1.SelectedPods.Len()).To(Equal(1))
		Expect(np1.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress | xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("checking the pod settings have inherited the expected policy configuration from gnp1 and np1")
		pod = tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(pod).NotTo(BeNil())
		Expect(pod.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress | xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))
	})

	It("should track the set of applied policies and overall settings (with namespaced networkset)", func() {
		By("applying np1 select1 with an ingress allow select1 rule")
		tester.SetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Select1,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Source, testutils.Select1, testutils.NoNamespaceSelector),
			},
			nil,
			&testutils.Order1,
		)

		By("applying np2 select2 with an ingress allow select2 rule")
		tester.SetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name2, testutils.Select2,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Source, testutils.Select2, testutils.NoNamespaceSelector),
			},
			nil,
			&testutils.Order1,
		)

		By("applying np1 select1 with an egress allow select1 rule")
		tester.SetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1, testutils.Select1,
			nil,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Destination, testutils.Select1, testutils.NoNamespaceSelector),
			},
			&testutils.Order1,
		)

		By("creating ns1 with label1 and internet exposed")
		tester.SetNetworkSet(testutils.Name1, testutils.Namespace1, testutils.Label1, testutils.Public)

		By("creating ns2 with label2 and all addresses private")
		tester.SetNetworkSet(testutils.Name2, testutils.Namespace1, testutils.Label2, testutils.Private)

		By("creating a pod1 with label 1")
		tester.SetPod(testutils.Name1, testutils.Namespace1, testutils.Label1, testutils.IP1, testutils.NoServiceAccount, testutils.NoPodOptions)

		By("checking pod1 xref with two policies in the cache")
		pod := tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(pod).NotTo(BeNil())
		Expect(pod.AppliedPolicies.Len()).To(Equal(2))
		gnp1 := tester.GetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name1)
		Expect(gnp1).NotTo(BeNil())
		Expect(gnp1.SelectedPods.Len()).To(Equal(1))
		gnp2 := tester.GetGlobalNetworkPolicy(testutils.TierDefault, testutils.Name2)
		Expect(gnp2).NotTo(BeNil())
		Expect(gnp2.SelectedPods.Len()).To(Equal(0))
		np1 := tester.GetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1)
		Expect(np1).NotTo(BeNil())
		Expect(np1.SelectedPods.Len()).To(Equal(1))

		By("checking cross-ref calculated flags are not yet set")
		Expect(gnp1.Flags).To(BeZero())
		Expect(np1.Flags).To(BeZero())

		By("sending in-sync")
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		Expect(gnp1.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress,
		))

		Expect(np1.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryInternetExposedEgress,
		))

		By("checking the pod settings have inherited the expected policy configuration from gnp1 and np1")
		Expect(pod.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress | xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryInternetExposedEgress,
		))

		By("updating np1 to include a namespace selector")
		tester.SetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1, testutils.Select1,
			nil,
			[]apiv3.Rule{
				testutils.CalicoRuleSelectors(testutils.Allow, testutils.Destination, testutils.Select1, testutils.Select1),
			},
			&testutils.Order1,
		)

		By("checking the np1 flags have been updated")
		np1 = tester.GetNetworkPolicy(testutils.TierDefault, testutils.Name1, testutils.Namespace1)
		Expect(np1).NotTo(BeNil())
		Expect(np1.SelectedPods.Len()).To(Equal(1))
		Expect(np1.Flags).To(Equal(
			xrefcache.CacheEntryProtectedEgress | xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))

		By("checking the pod settings have inherited the expected policy configuration from gnp1 and np1")
		pod = tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(pod).NotTo(BeNil())
		Expect(pod.Flags).To(Equal(
			xrefcache.CacheEntryProtectedIngress | xrefcache.CacheEntryProtectedEgress |
				xrefcache.CacheEntryInternetExposedIngress |
				xrefcache.CacheEntryOtherNamespaceExposedIngress | xrefcache.CacheEntryOtherNamespaceExposedEgress,
		))
	})

	It("should handle tracking matching services", func() {
		By("sending in-sync")
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())

		By("applying pod1 IP1")
		tester.SetPod(testutils.Name1, testutils.Namespace1, testutils.NoLabels, testutils.IP1, testutils.NoServiceAccount, testutils.NoPodOptions)

		By("applying pod2 IP2")
		tester.SetPod(testutils.Name2, testutils.Namespace1, testutils.NoLabels, testutils.IP2, testutils.NoServiceAccount, testutils.NoPodOptions)

		By("applying pod3 with no IP")
		pod3 := tester.SetPod(testutils.Name2, testutils.Namespace2, testutils.NoLabels, 0, testutils.NoServiceAccount, testutils.NoPodOptions)
		pod3Id := resources.GetResourceID(pod3)

		By("applying service1 with IP1 IP2 IP3")
		svcEps1 := tester.SetEndpoints(testutils.Name1, testutils.Namespace1, testutils.IP1|testutils.IP2|testutils.IP3)
		svcEpsID1 := resources.GetResourceID(svcEps1)
		svc1 := apiv3.ResourceID{
			TypeMeta:  resources.TypeK8sServices,
			Name:      svcEpsID1.Name,
			Namespace: svcEpsID1.Namespace,
		}

		By("applying service2 with IP1 IP3 and pod3Id ref")
		svcEps2 := tester.SetEndpoints(testutils.Name2, testutils.Namespace1, testutils.IP1|testutils.IP3, pod3Id)
		svcEpsID2 := resources.GetResourceID(svcEps2)
		svc2 := apiv3.ResourceID{
			TypeMeta:  resources.TypeK8sServices,
			Name:      svcEpsID2.Name,
			Namespace: svcEpsID2.Namespace,
		}

		By("checking that pod1 refs service1 and service2")
		ep := tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(2))
		Expect(ep.Services.Contains(svc1)).To(BeTrue())
		Expect(ep.Services.Contains(svc2)).To(BeTrue())

		By("checking that pod2 refs service1")
		ep = tester.GetPod(testutils.Name2, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(1))
		Expect(ep.Services.Contains(svc1)).To(BeTrue())

		By("checking that pod3 refs service2")
		ep = tester.GetPod(testutils.Name2, testutils.Namespace2)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(1))
		Expect(ep.Services.Contains(svc2)).To(BeTrue())

		By("updating service2 with IP2 IP3 and removing pod3")
		tester.SetEndpoints(testutils.Name2, testutils.Namespace1, testutils.IP2|testutils.IP3)

		By("checking that pod1 no longer refs service2")
		ep = tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(1))
		Expect(ep.Services.Contains(svc1)).To(BeTrue())
		Expect(ep.Services.Contains(svc2)).To(BeFalse())

		By("checking that pod2 refs service1 and service2")
		ep = tester.GetPod(testutils.Name2, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(2))
		Expect(ep.Services.Contains(svc1)).To(BeTrue())
		Expect(ep.Services.Contains(svc2)).To(BeTrue())

		By("checking that pod3 no longer refs service2")
		ep = tester.GetPod(testutils.Name2, testutils.Namespace2)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(0))

		By("deleting and re-adding pod2 and checking services are the same")
		tester.DeletePod(testutils.Name2, testutils.Namespace1)
		Expect(tester.GetPod(testutils.Name2, testutils.Namespace1)).To(BeNil())
		tester.SetPod(testutils.Name2, testutils.Namespace1, testutils.NoLabels, testutils.IP2, testutils.NoServiceAccount, testutils.NoPodOptions)
		ep = tester.GetPod(testutils.Name2, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(2))
		Expect(ep.Services.Contains(svc1)).To(BeTrue())
		Expect(ep.Services.Contains(svc2)).To(BeTrue())

		By("updating service1 with IP3")
		tester.SetEndpoints(testutils.Name1, testutils.Namespace1, testutils.IP3)

		By("checking that pod2 no longer refs service1")
		ep = tester.GetPod(testutils.Name2, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(1))
		Expect(ep.Services.Contains(svc1)).To(BeFalse())
		Expect(ep.Services.Contains(svc2)).To(BeTrue())

		By("updating pod2 with IP3")
		tester.SetPod(testutils.Name2, testutils.Namespace1, testutils.NoLabels, testutils.IP3, testutils.NoServiceAccount, testutils.NoPodOptions)

		By("checking that pod2 no refs service1 and service2")
		ep = tester.GetPod(testutils.Name2, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(2))
		Expect(ep.Services.Contains(svc1)).To(BeTrue())
		Expect(ep.Services.Contains(svc2)).To(BeTrue())

		By("deleting service2")
		tester.DeleteEndpoints(testutils.Name2, testutils.Namespace1)
		Expect(tester.GetEndpoints(testutils.Name2, testutils.Namespace1)).To(BeNil())

		By("checking that pod2 no refs service2")
		ep = tester.GetPod(testutils.Name2, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(Equal(1))
		Expect(ep.Services.Contains(svc1)).To(BeTrue())
		Expect(ep.Services.Contains(svc2)).To(BeFalse())

		By("deleting service1")
		tester.DeleteEndpoints(testutils.Name1, testutils.Namespace1)
		Expect(tester.GetEndpoints(testutils.Name1, testutils.Namespace1)).To(BeNil())

		By("checking both pods reference no services")
		ep = tester.GetPod(testutils.Name1, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(BeZero())
		ep = tester.GetPod(testutils.Name2, testutils.Namespace1)
		Expect(ep).NotTo(BeNil())
		Expect(ep.Services.Len()).To(BeZero())
	})
})
