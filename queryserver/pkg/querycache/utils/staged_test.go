package utils

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("StagedToEnforcedConversion", func() {
	Context("StagedNetworkPolicy conversion", func() {
		It("should preserve UID when converting to NetworkPolicy", func() {
			// Create a test UID
			testUID := types.UID("test-uid-12345")

			// Create a StagedNetworkPolicy with UID
			stagedPolicy := &v3.StagedNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "default",
					UID:       testUID,
				},
				Spec: v3.StagedNetworkPolicySpec{
					Order:        nil,
					Tier:         "default",
					StagedAction: v3.StagedActionSet,
					Selector:     "all()",
				},
			}

			// Create Update objects
			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind:      v3.KindStagedNetworkPolicy,
						Name:      "test-policy",
						Namespace: "default",
					},
					Value: stagedPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name:      "test-policy",
						Namespace: "default",
					},
				},
			}

			// Perform conversion
			StagedToEnforcedConversion(uv1, uv3)

			// Verify the conversion
			Expect(uv3.Key.(model.ResourceKey).Kind).To(Equal(v3.KindNetworkPolicy))
			Expect(uv3.Key.(model.ResourceKey).Name).To(Equal("staged:test-policy"))

			// Verify the UID is preserved
			convertedPolicy, ok := uv3.Value.(*v3.NetworkPolicy)
			Expect(ok).To(BeTrue())
			Expect(convertedPolicy.UID).To(Equal(testUID))
		})

		It("should set the correct name prefix", func() {
			stagedPolicy := &v3.StagedNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-policy",
					Namespace: "kube-system",
					UID:       types.UID("uid-abc"),
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionSet,
					Selector:     "role == 'frontend'",
				},
			}

			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind:      v3.KindStagedNetworkPolicy,
						Name:      "my-policy",
						Namespace: "kube-system",
					},
					Value: stagedPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "my-policy",
					},
				},
			}

			StagedToEnforcedConversion(uv1, uv3)

			convertedPolicy := uv3.Value.(*v3.NetworkPolicy)
			Expect(convertedPolicy.Name).To(Equal("staged:my-policy"))
		})
	})

	Context("StagedKubernetesNetworkPolicy conversion", func() {
		It("should preserve UID when converting to NetworkPolicy", func() {
			testUID := types.UID("k8s-policy-uid-67890")

			stagedK8sPolicy := &v3.StagedKubernetesNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedKubernetesNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "k8s-test-policy",
					Namespace: "default",
					UID:       testUID,
				},
				Spec: v3.StagedKubernetesNetworkPolicySpec{
					StagedAction: v3.StagedActionSet,
				},
			}

			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind:      v3.KindStagedKubernetesNetworkPolicy,
						Name:      "k8s-test-policy",
						Namespace: "default",
					},
					Value: stagedK8sPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "k8s-test-policy",
					},
				},
			}

			// Perform conversion
			StagedToEnforcedConversion(uv1, uv3)

			// Verify the conversion
			Expect(uv3.Key.(model.ResourceKey).Kind).To(Equal(v3.KindNetworkPolicy))

			// Verify the UID is preserved
			convertedPolicy, ok := uv3.Value.(*v3.NetworkPolicy)
			Expect(ok).To(BeTrue())
			Expect(convertedPolicy.UID).To(Equal(testUID))
		})

		It("should set the correct name prefix with K8s marker", func() {
			stagedK8sPolicy := &v3.StagedKubernetesNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedKubernetesNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "my-k8s-policy",
					Namespace: "production",
					UID:       types.UID("uid-k8s-123"),
				},
				Spec: v3.StagedKubernetesNetworkPolicySpec{
					StagedAction: v3.StagedActionSet,
				},
			}

			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind:      v3.KindStagedKubernetesNetworkPolicy,
						Name:      "my-k8s-policy",
						Namespace: "production",
					},
					Value: stagedK8sPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "my-k8s-policy",
					},
				},
			}

			StagedToEnforcedConversion(uv1, uv3)

			convertedPolicy := uv3.Value.(*v3.NetworkPolicy)
			Expect(convertedPolicy.Name).To(Equal("staged:knp.default.my-k8s-policy"))
		})
	})

	Context("StagedGlobalNetworkPolicy conversion", func() {
		It("should preserve UID when converting to GlobalNetworkPolicy", func() {
			testUID := types.UID("global-policy-uid-54321")

			stagedGlobalPolicy := &v3.StagedGlobalNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedGlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "global-test-policy",
					UID:  testUID,
				},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					Order:        nil,
					Tier:         "default",
					StagedAction: v3.StagedActionSet,
					Selector:     "all()",
				},
			}

			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind: v3.KindStagedGlobalNetworkPolicy,
						Name: "global-test-policy",
					},
					Value: stagedGlobalPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "global-test-policy",
					},
				},
			}

			// Perform conversion
			StagedToEnforcedConversion(uv1, uv3)

			// Verify the conversion
			Expect(uv3.Key.(model.ResourceKey).Kind).To(Equal(v3.KindGlobalNetworkPolicy))
			Expect(uv3.Key.(model.ResourceKey).Name).To(Equal("staged:global-test-policy"))

			// Verify the UID is preserved
			convertedPolicy, ok := uv3.Value.(*v3.GlobalNetworkPolicy)
			Expect(ok).To(BeTrue())
			Expect(convertedPolicy.UID).To(Equal(testUID))
		})

		It("should set the correct name prefix", func() {
			stagedGlobalPolicy := &v3.StagedGlobalNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedGlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-global-policy",
					UID:  types.UID("uid-global-xyz"),
				},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					StagedAction: v3.StagedActionSet,
					Selector:     "has(kubernetes.io/hostname)",
				},
			}

			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind: v3.KindStagedGlobalNetworkPolicy,
						Name: "my-global-policy",
					},
					Value: stagedGlobalPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "my-global-policy",
					},
				},
			}

			StagedToEnforcedConversion(uv1, uv3)

			convertedPolicy := uv3.Value.(*v3.GlobalNetworkPolicy)
			Expect(convertedPolicy.Name).To(Equal("staged:my-global-policy"))
		})
	})

	Context("Edge cases", func() {
		It("should handle empty UID", func() {
			stagedPolicy := &v3.StagedNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-uid-policy",
					Namespace: "default",
					// UID is not set (empty)
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionSet,
					Selector:     "all()",
				},
			}

			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind:      v3.KindStagedNetworkPolicy,
						Name:      "no-uid-policy",
						Namespace: "default",
					},
					Value: stagedPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "no-uid-policy",
					},
				},
			}

			// Should not panic
			StagedToEnforcedConversion(uv1, uv3)

			convertedPolicy := uv3.Value.(*v3.NetworkPolicy)
			// Empty UID should remain empty
			Expect(convertedPolicy.UID).To(Equal(types.UID("")))
		})

		It("should handle nil value gracefully", func() {
			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind:      v3.KindStagedNetworkPolicy,
						Name:      "nil-value-policy",
						Namespace: "default",
					},
					Value: nil,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "nil-value-policy",
					},
				},
			}

			// Should not panic when value is nil
			Expect(func() {
				StagedToEnforcedConversion(uv1, uv3)
			}).NotTo(Panic())
		})

		It("should preserve special characters in UID", func() {
			specialUID := types.UID("uid-with-special-chars-!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`")

			stagedGlobalPolicy := &v3.StagedGlobalNetworkPolicy{
				TypeMeta: metav1.TypeMeta{
					Kind:       "StagedGlobalNetworkPolicy",
					APIVersion: "projectcalico.org/v3",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "special-uid-policy",
					UID:  specialUID,
				},
				Spec: v3.StagedGlobalNetworkPolicySpec{
					StagedAction: v3.StagedActionSet,
					Selector:     "all()",
				},
			}

			uv3 := &api.Update{
				KVPair: model.KVPair{
					Key: model.ResourceKey{
						Kind: v3.KindStagedGlobalNetworkPolicy,
						Name: "special-uid-policy",
					},
					Value: stagedGlobalPolicy,
				},
			}

			uv1 := &api.Update{
				KVPair: model.KVPair{
					Key: model.PolicyKey{
						Name: "special-uid-policy",
					},
				},
			}

			StagedToEnforcedConversion(uv1, uv3)

			convertedPolicy := uv3.Value.(*v3.GlobalNetworkPolicy)
			Expect(convertedPolicy.UID).To(Equal(specialUID))
		})
	})
})
