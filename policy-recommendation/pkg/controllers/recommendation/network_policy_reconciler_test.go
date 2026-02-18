// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package recommendation_controller

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	calres "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

var _ = Describe("NetworkPolicyReconciler", func() {
	const (
		// kindRecommendations is the kind of the recommendations resource.
		kindRecommendations = "recommendations"

		// retryInterval is the interval between retries.
		retryInterval = time.Second * 2
	)

	var (
		r *networkPolicyReconciler
	)

	BeforeEach(func() {
		buffer := &bytes.Buffer{}
		// Create a new Logrus logger instance
		logger := log.New()
		// Set the logger's output to the buffer
		logger.SetOutput(buffer)
		// Create a new managed cluster logger entry
		logEntry := logger.WithField("RecommendationScope", "controller")

		ctx := context.TODO()

		mockClientSet := &lmak8s.MockClientSet{}
		mockClientSet.On("ProjectcalicoV3").Return(fakecalico.NewSimpleClientset().ProjectcalicoV3()).Maybe()
		mockClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1()).Maybe()

		_, err := mockClientSet.ProjectcalicoV3().ManagedClusters().Create(ctx, &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: "managed-cluster-2",
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		mockClientSetFactory := &lmak8s.MockClientSetFactory{}
		mockClientSetFactory.On("NewClientSetForApplication", "managed-cluster-1").Return(mockClientSet, nil).Maybe()
		mockClientSetFactory.On("NewClientSetForApplication", "managed-cluster-2").Return(mockClientSet, nil).Maybe()

		// Get the list of recommendations from the datastore with retries.
		listRecommendations := func(ret int) ([]v3.StagedNetworkPolicy, error) {
			var err error
			var snps *v3.StagedNetworkPolicyList
			for i := 0; i < ret; i++ {
				snps, err = mockClientSet.ProjectcalicoV3().StagedNetworkPolicies(v1.NamespaceAll).List(ctx, metav1.ListOptions{
					LabelSelector: fmt.Sprintf("%s=%s", v3.LabelTier, rectypes.PolicyRecommendationTierName),
				})
				if err == nil {
					break
				}
				time.Sleep(retryInterval) // Wait before retrying
			}

			if err != nil {
				return nil, err
			}

			return snps.Items, nil
		}
		// Define the list of items handled by the policy recommendation cache.
		listFunc := func() (map[string]interface{}, error) {
			snps, err := listRecommendations(retries)
			if err != nil {
				return nil, err
			}

			snpMap := make(map[string]interface{})
			for _, snp := range snps {
				snpMap[snp.Namespace] = snp
			}

			return snpMap, nil
		}

		// Create a cache to store recommendations in.
		cacheArgs := rcache.ResourceCacheArgs{
			ListFunc:    listFunc,
			ObjectType:  reflect.TypeOf(v3.StagedNetworkPolicy{}),
			LogTypeDesc: kindRecommendations,
			ReconcilerConfig: rcache.ReconcilerConfig{
				DisableUpdateOnChange: true,
				DisableMissingInCache: true,
			},
		}
		cache := rcache.NewResourceCache(cacheArgs)

		// Create a new instance of the networkPolicyReconciler
		r = &networkPolicyReconciler{
			ctx:       ctx,
			cache:     cache,
			clientSet: mockClientSet,
			clog:      logEntry,
		}
	})

	Describe("Reconcile", func() {
		It("should not return an error if no StagedNetworkPolicy is in the cache", func() {
			// Set up the necessary test data
			key := types.NamespacedName{
				Namespace: "test-namespace",
				Name:      "test-name",
			}

			// Create a NetworkPolicy with the recommendation tier
			_, err := r.clientSet.ProjectcalicoV3().NetworkPolicies(key.Namespace).Create(r.ctx, &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: key.Namespace,
					Name:      key.Name,
				},
				Spec: v3.NetworkPolicySpec{
					Tier: rectypes.PolicyRecommendationTierName,
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Call the Reconcile function
			err = r.Reconcile(key)
			Expect(err).To(BeNil())
		})

		It("should ignore recommendation when a NetworkPolicy is present", func() {
			// Set up the necessary test data
			key := types.NamespacedName{
				Namespace: "test-namespace",
				Name:      "test-name",
			}

			// Create a NetworkPolicy with the recommendation tier
			_, err := r.clientSet.ProjectcalicoV3().NetworkPolicies(key.Namespace).Create(r.ctx, &v3.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: key.Namespace,
					Name:      key.Name,
				},
				Spec: v3.NetworkPolicySpec{
					Tier: rectypes.PolicyRecommendationTierName,
				},
			}, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Add the recommendation to the cache
			snp := v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: key.Namespace,
					Name:      key.Name,
					Labels: map[string]string{
						v3.LabelTier:           rectypes.PolicyRecommendationTierName,
						calres.StagedActionKey: string(v3.StagedActionSet),
					},
				},
				Spec: v3.StagedNetworkPolicySpec{
					Tier:         rectypes.PolicyRecommendationTierName,
					StagedAction: v3.StagedActionSet,
				},
			}
			r.cache.Set(key.Namespace, snp)

			// Call the Reconcile function
			err = r.Reconcile(key)
			Expect(err).To(BeNil())

			// Assert that the recommendation is ignored
			item, ok := r.cache.Get(key.Namespace)
			Expect(ok).To(BeTrue())
			snp = item.(v3.StagedNetworkPolicy)
			Expect(snp.Spec.StagedAction).To(Equal(v3.StagedActionIgnore))
			Expect(snp.Labels[calres.StagedActionKey]).To(Equal(string(v3.StagedActionIgnore)))
		})
	})
})
