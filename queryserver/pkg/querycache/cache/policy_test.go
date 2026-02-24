// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package cache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/cache"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
)

var _ = Describe("Querycache policy tests", func() {
	Context("validate IsKubernetesType()", func() {
		var policiesCache cache.PoliciesCache
		BeforeEach(func() {
			policiesCache = populateCache()
		})

		It("should return true for admin network policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "test",
				Namespace: "",
				Kind:      model.KindKubernetesAdminNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for baseline admin network policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "test",
				Namespace: "",
				Kind:      model.KindKubernetesBaselineAdminNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for kubernetes network policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "test",
				Namespace: "default",
				Kind:      model.KindKubernetesNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for staged kubernetes network policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "test.1",
				Namespace: "default",
				Kind:      v3.KindStagedKubernetesNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return false for calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      v3.KindNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})

		It("should return false for staged calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      v3.KindStagedNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})

		It("should return false for global calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      v3.KindGlobalNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})

		It("should return false for staged global calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      v3.KindStagedGlobalNetworkPolicy,
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})
	})
})

func populateCache() cache.PoliciesCache {
	policiesCache := cache.NewPoliciesCache()
	gnpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
		updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(v3.KindGlobalNetworkPolicy),
	)
	anpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
		updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(model.KindKubernetesAdminNetworkPolicy),
	)
	banpConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
		updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(model.KindKubernetesBaselineAdminNetworkPolicy),
	)
	npConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
		updateprocessors.NewNetworkPolicyUpdateProcessor(v3.KindNetworkPolicy),
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
	tierConverter := dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
		updateprocessors.NewTierUpdateProcessor(),
	)

	dispatcherTypes := []dispatcherv1v3.Resource{
		{
			// We need to convert the GNP for use with the policy sorter, and to get the
			// correct selectors for the labelhandler.
			Kind:      v3.KindGlobalNetworkPolicy,
			Converter: gnpConverter,
		},
		{
			Kind:      model.KindKubernetesAdminNetworkPolicy,
			Converter: anpConverter,
		},
		{
			Kind:      model.KindKubernetesBaselineAdminNetworkPolicy,
			Converter: banpConverter,
		},
		{
			// Convert the KubernetesNetworkPolicy to NP.
			Kind:      model.KindKubernetesNetworkPolicy,
			Converter: knpConverter,
		},
		{
			// We need to convert the NP for use with the policy sorter, and to get the
			// correct selectors for the labelhandler.
			Kind:      v3.KindNetworkPolicy,
			Converter: npConverter,
		},
		{
			// Convert the SGNP to GNP
			Kind:      v3.KindStagedGlobalNetworkPolicy,
			Converter: sgnpConverter,
		},
		{
			// Convert the SNP to NP
			Kind:      v3.KindStagedNetworkPolicy,
			Converter: snpConverter,
		},
		{
			// Convert the SK8SNP to NP
			Kind:      v3.KindStagedKubernetesNetworkPolicy,
			Converter: sk8snpConverter,
		},
		{
			Kind:      v3.KindTier,
			Converter: tierConverter,
		},
	}

	dispatcher := dispatcherv1v3.New(dispatcherTypes)
	policiesCache.RegisterWithDispatcher(dispatcher)

	newKANPUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "test",
				Namespace: "",
				Kind:      model.KindKubernetesAdminNetworkPolicy,
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
					UID:  "e398dea3-328b-48ca-b152-1efcafaccc24",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Tier: "adminnetworkpolicy",
					Egress: []v3.Rule{
						{
							Action: v3.Allow,
						},
					},
					Selector: "projectcalico.org/orchestrator == 'k8s'",
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	newKANPUpdate2 := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "test.1",
				Namespace: "",
				Kind:      model.KindKubernetesAdminNetworkPolicy,
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
					UID:  "e398dea3-328b-48ca-b152-1efcafaccc24",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Tier: "adminnetworkpolicy",
					Egress: []v3.Rule{
						{
							Action: v3.Allow,
						},
					},
					Selector: "projectcalico.org/orchestrator == 'k8s'",
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	newKBANPUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "test",
				Namespace: "",
				Kind:      model.KindKubernetesBaselineAdminNetworkPolicy,
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "test",
					UID:  "e398dea3-328b-48ca-b152-1efcafaccc24",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Tier: "baselineadminnetworkpolicy",
					Egress: []v3.Rule{
						{
							Action: v3.Allow,
						},
					},
					Selector: "projectcalico.org/orchestrator == 'k8s'",
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	newKBANPUpdate2 := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "test.1",
				Namespace: "",
				Kind:      model.KindKubernetesBaselineAdminNetworkPolicy,
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "test.1",
					UID:  "e398dea3-328b-48ca-b152-1efcafaccc24",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Tier: "baselineadminnetworkpolicy",
					Egress: []v3.Rule{
						{
							Action: v3.Allow,
						},
					},
					Selector: "projectcalico.org/orchestrator == 'k8s'",
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	newKNPUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "test",
				Namespace: "default",
				Kind:      "KubernetesNetworkPolicy",
			},
			Value: &v3.NetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					UID:       "62cb2a82-77ff-44ed-8aab-fabab0a3b521",
				},
				Spec: v3.NetworkPolicySpec{
					Tier:  "",
					Types: []v3.PolicyType{"Ingress"},
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	newKNPUpdate2 := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "test.1",
				Namespace: "default",
				Kind:      "KubernetesNetworkPolicy",
			},
			Value: &v3.NetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "knp.default.test",
					Namespace: "default",
					UID:       "62cb2a82-77ff-44ed-8aab-fabab0a3b521",
				},
				Spec: v3.NetworkPolicySpec{
					Tier:  "",
					Types: []v3.PolicyType{"Ingress"},
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	stagedKNPUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "test.1",
				Namespace: "default",
				Kind:      "StagedKubernetesNetworkPolicy",
			},
			Value: &v3.StagedKubernetesNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "StagedKubernetesNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v3.StagedKubernetesNetworkPolicySpec{},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	newCalicoUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			},
			Value: &v3.NetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "default.test",
					Namespace: "default",
					UID:       "cd4f30f4-a06c-44b9-a4a9-72b41dbf4658",
				},
				Spec: v3.NetworkPolicySpec{
					Tier:     "default",
					Selector: "all()",
					Types:    []v3.PolicyType{"Ingress"},
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	stagedCalicoUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      "StagedNetworkPolicy",
			},
			Value: &v3.StagedNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "default.test",
					Namespace: "default",
					UID:       "00ffcda7-1506-43da-a8f5-138cb46df515",
				},
				Spec: v3.StagedNetworkPolicySpec{
					Tier:     "default",
					Selector: "all()",
					Types:    []v3.PolicyType{"Ingress"},
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	newGlobalCalicoUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      "GlobalNetworkPolicy",
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "default.test",
					Namespace: "default",
					UID:       "cd4f30f4-a06c-44b9-a4a9-72b41dbf4658",
				},
				Spec: v3.GlobalNetworkPolicySpec{
					Tier:     "default",
					Selector: "all()",
					Types:    []v3.PolicyType{"Ingress"},
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	stagedGlobalCalicoUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      "StagedGlobalNetworkPolicy",
			},
			Value: &v3.StagedGlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "StagedGlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "default.test",
					Namespace: "default",
					UID:       "afbb0565-7bc7-43f9-9dda-1126212eac41",
				},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					Tier:     "default",
					Selector: "all()",
					Types:    []v3.PolicyType{"Ingress"},
				},
			},
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	updates := []api.Update{
		newKANPUpdate,
		newKANPUpdate2,
		newKBANPUpdate,
		newKBANPUpdate2,
		newKNPUpdate,
		newKNPUpdate2,
		stagedKNPUpdate,
		newCalicoUpdate,
		stagedCalicoUpdate,
		newGlobalCalicoUpdate,
		stagedGlobalCalicoUpdate,
	}

	dispatcher.OnUpdates(updates)

	return policiesCache
}
