// Copyright (c) 2026 Tigera, Inc. All rights reserved.
package client

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/cache"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/labelhandler"
)

var _ = Describe("getPolicySelector", func() {
	var cq *cachedQuery

	BeforeEach(func() {
		policiesCache := cache.NewPoliciesCache()

		gnpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(apiv3.KindGlobalNetworkPolicy),
		)
		npConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewNetworkPolicyUpdateProcessor(apiv3.KindNetworkPolicy),
		)
		knpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewNetworkPolicyUpdateProcessor(model.KindKubernetesNetworkPolicy),
		)
		sgnpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewStagedGlobalNetworkPolicyUpdateProcessor(),
		)
		snpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewStagedNetworkPolicyUpdateProcessor(),
		)
		sk8snpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewStagedKubernetesNetworkPolicyUpdateProcessor(),
		)
		anpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(model.KindKubernetesAdminNetworkPolicy),
		)
		banpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(model.KindKubernetesBaselineAdminNetworkPolicy),
		)
		tierConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewTierUpdateProcessor(),
		)

		dispatcherTypes := []dispatcherv1v3.Resource{
			{Kind: apiv3.KindGlobalNetworkPolicy, Converter: gnpConverter},
			{Kind: model.KindKubernetesAdminNetworkPolicy, Converter: anpConverter},
			{Kind: model.KindKubernetesBaselineAdminNetworkPolicy, Converter: banpConverter},
			{Kind: model.KindKubernetesNetworkPolicy, Converter: knpConverter},
			{Kind: apiv3.KindNetworkPolicy, Converter: npConverter},
			{Kind: apiv3.KindStagedGlobalNetworkPolicy, Converter: sgnpConverter},
			{Kind: apiv3.KindStagedNetworkPolicy, Converter: snpConverter},
			{Kind: apiv3.KindStagedKubernetesNetworkPolicy, Converter: sk8snpConverter},
			{Kind: apiv3.KindTier, Converter: tierConverter},
		}

		dispatcher := dispatcherv1v3.New(dispatcherTypes)
		policiesCache.RegisterWithDispatcher(dispatcher)

		// Tier required for policies to be stored correctly.
		tierUpdate := api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{
					Name: "default",
					Kind: apiv3.KindTier,
				},
				Value: &apiv3.Tier{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindTier,
						APIVersion: "projectcalico.org/v3",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
					Spec: apiv3.TierSpec{
						Order: ptr.To(100.0),
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		}

		// KubernetesNetworkPolicy - stored as *apiv3.NetworkPolicy with Kind "NetworkPolicy"
		// (matching what the syncer produces via K8sNetworkPolicyToCalico).
		knpUpdate := api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{
					Name:      "k8s-np-test",
					Namespace: "default",
					Kind:      model.KindKubernetesNetworkPolicy,
				},
				Value: &apiv3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindNetworkPolicy,
						APIVersion: "projectcalico.org/v3",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "k8s-np-test",
						Namespace: "default",
						UID:       "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
					},
					Spec: apiv3.NetworkPolicySpec{
						Tier:     "default",
						Order:    ptr.To(1000.0),
						Selector: "app == 'test'",
						Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
						Ingress: []apiv3.Rule{
							{
								Action: apiv3.Allow,
								Source: apiv3.EntityRule{
									Selector: "role == 'frontend'",
								},
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		}

		// Regular Calico NetworkPolicy for comparison.
		npUpdate := api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{
					Name:      "default.calico-np-test",
					Namespace: "default",
					Kind:      apiv3.KindNetworkPolicy,
				},
				Value: &apiv3.NetworkPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       apiv3.KindNetworkPolicy,
						APIVersion: "projectcalico.org/v3",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default.calico-np-test",
						Namespace: "default",
						UID:       "11111111-2222-3333-4444-555555555555",
					},
					Spec: apiv3.NetworkPolicySpec{
						Tier:     "default",
						Selector: "all()",
						Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
						Ingress: []apiv3.Rule{
							{
								Action: apiv3.Allow,
								Source: apiv3.EntityRule{
									Selector: "app == 'backend'",
								},
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		}

		lh := labelhandler.NewLabelHandler()
		policiesCache.RegisterWithLabelHandler(lh)

		dispatcher.OnUpdates([]api.Update{tierUpdate, knpUpdate, npUpdate})

		cq = &cachedQuery{
			policies:        policiesCache,
			gnpConverter:    gnpConverter,
			npConverter:     npConverter,
			knpConverter:    knpConverter,
			sgnpConverter:   sgnpConverter,
			snpConverter:    snpConverter,
			sk8snpConverter: sk8snpConverter,
			anpConverter:    anpConverter,
			banpConverter:   banpConverter,
		}
	})

	It("should return the selector for a KubernetesNetworkPolicy", func() {
		key := model.ResourceKey{
			Name:      "k8s-np-test",
			Namespace: "default",
			Kind:      model.KindKubernetesNetworkPolicy,
		}
		selector, err := cq.getPolicySelector(key, "", 0, "", false)
		Expect(err).ShouldNot(HaveOccurred())
		// The selector should include the namespace qualifier added by the converter.
		Expect(selector).To(ContainSubstring("app == 'test'"))
		Expect(selector).To(ContainSubstring("projectcalico.org/namespace == 'default'"))
	})

	It("should return the ingress rule selector for a KubernetesNetworkPolicy", func() {
		key := model.ResourceKey{
			Name:      "k8s-np-test",
			Namespace: "default",
			Kind:      model.KindKubernetesNetworkPolicy,
		}
		selector, err := cq.getPolicySelector(key, "ingress", 0, "source", false)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(selector).To(ContainSubstring("role == 'frontend'"))
	})

	It("should return the selector for a Calico NetworkPolicy", func() {
		key := model.ResourceKey{
			Name:      "default.calico-np-test",
			Namespace: "default",
			Kind:      apiv3.KindNetworkPolicy,
		}
		selector, err := cq.getPolicySelector(key, "", 0, "", false)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(selector).To(ContainSubstring("all()"))
	})
})
