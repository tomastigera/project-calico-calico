// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package cache_test

import (
	. "github.com/onsi/ginkgo"
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
				Name:      "kanp.adminnetworkpolicy.test",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for admin network policy with '.' in the name", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "kanp.adminnetworkpolicy.test.1",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for baseline admin network policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "kbanp.baselineadminnetworkpolicy.test",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for baseline admin network policy with '.' in the name", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "kbanp.baselineadminnetworkpolicy.test.1",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for kubernetes network policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "knp.default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for kubernetes network policy with '.' in the name", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "knp.default.test.1",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return true for staged kubernetes network policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "staged:knp.default.test.1",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeTrue())
		})

		It("should return false for calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})

		It("should return false for staged calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "staged:default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})

		It("should return false for global calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "default.test",
				Namespace: "default",
				Kind:      "GlobalNetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})

		It("should return false for staged global calico policy", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "staged:default.test",
				Namespace: "default",
				Kind:      "GlobalNetworkPolicy",
			})

			isKubPolicy, err := policyData.IsKubernetesType()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(isKubPolicy).To(BeFalse())
		})

		It("should return err for unknown policy structure", func() {
			policyData := policiesCache.GetPolicy(model.ResourceKey{
				Name:      "abc.default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			})

			_, err := policyData.IsKubernetesType()
			Expect(err).Should(HaveOccurred())
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
			Converter: npConverter,
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

	//
	newKANPUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "kanp.adminnetworkpolicy.test",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "kanp.adminnetworkpolicy.test",
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
				Name:      "kanp.adminnetworkpolicy.test.1",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "kanp.adminnetworkpolicy.test",
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
				Name:      "kbanp.baselineadminnetworkpolicy.test",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "kbanp.baselineadminnetworkpolicy.test",
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
				Name:      "kbanp.baselineadminnetworkpolicy.test.1",
				Namespace: "",
				Kind:      "GlobalNetworkPolicy",
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name: "kbanp.baselineadminnetworkpolicy.test",
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
				Name:      "knp.default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
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

	newKNPUpdate2 := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "knp.default.test.1",
				Namespace: "default",
				Kind:      "NetworkPolicy",
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
				Name:      "staged:knp.default.test.1",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			},
			Value: &v3.NetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "knp.default.test",
					Namespace: "default",
				},
				Spec: v3.NetworkPolicySpec{
					Tier:  "",
					Types: []v3.PolicyType{"Ingress"},
				},
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
				Name:      "staged:default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			},
			Value: &v3.NetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "staged:default.test",
					Namespace: "default",
					UID:       "00ffcda7-1506-43da-a8f5-138cb46df515",
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
				Name:      "staged:default.test",
				Namespace: "default",
				Kind:      "GlobalNetworkPolicy",
			},
			Value: &v3.GlobalNetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "GlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "staged:default.test",
					Namespace: "default",
					UID:       "afbb0565-7bc7-43f9-9dda-1126212eac41",
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

	newRandomUpdate := api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{
				Name:      "abc.default.test",
				Namespace: "default",
				Kind:      "NetworkPolicy",
			},
			Value: &v3.NetworkPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "NetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: v1.ObjectMeta{
					Name:      "abc.default.test",
					Namespace: "default",
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
		newRandomUpdate,
	}

	dispatcher.OnUpdates(updates)

	return policiesCache
}
