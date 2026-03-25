// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
package recommendation_controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	calres "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	recengine "github.com/projectcalico/calico/policy-recommendation/pkg/engine"
	querymocks "github.com/projectcalico/calico/policy-recommendation/pkg/flows/mocks"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

var _ = Describe("RecommendationController", func() {
	const (
		// kindRecommendations is the kind of the recommendations resource.
		kindRecommendations = "recommendations"

		// retryInterval is the interval between retries.
		retryInterval = time.Second * 2
	)

	var (
		controller *recommendationController
		buffer     *bytes.Buffer
	)

	BeforeEach(func() {
		buffer = &bytes.Buffer{}
		// Create a new Logrus logger instance
		logger := log.New()
		// Set the logger's output to the buffer
		logger.SetOutput(buffer)
		// Create a new managed cluster logger entry
		logEntry := logger.WithField("RecommendationScope", "controller")

		ctx := context.TODO()

		mockClientSet := &lmak8s.MockClientSet{}
		mockClientSet.On("ProjectcalicoV3").Return(fakecalico.NewClientset().ProjectcalicoV3()).Maybe()
		mockClientSet.On("CoreV1").Return(fakeK8s.NewClientset().CoreV1()).Maybe()

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
			for range ret {
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
		listFunc := func() (map[string]any, error) {
			snps, err := listRecommendations(retries)
			if err != nil {
				return nil, err
			}

			snpMap := make(map[string]any)
			for _, snp := range snps {
				snpMap[snp.Namespace] = snp
			}

			return snpMap, nil
		}

		// Create a cache to store recommendations in.
		cacheArgs := rcache.ResourceCacheArgs{
			ListFunc:    listFunc,
			ObjectType:  reflect.TypeFor[v3.StagedNetworkPolicy](),
			LogTypeDesc: kindRecommendations,
			ReconcilerConfig: rcache.ReconcilerConfig{
				DisableUpdateOnChange: true,
				DisableMissingInCache: true,
			},
		}
		cache := rcache.NewResourceCache(cacheArgs)

		mockLinseedClient := lsclient.NewMockClient("")

		namespaces := []string{"default"}

		minPollInterval := metav1.Duration{Duration: time.Second * 30}

		mockClock := &MockClock{}

		query := &querymocks.PolicyRecommendationQuery{}
		flows := []*api.Flow{
			{
				Source: api.FlowEndpointData{
					Type:      api.EndpointTypeWep,
					Name:      "test-pod",
					Namespace: "test-namespace",
				},
				Destination: api.FlowEndpointData{
					Type:    api.FlowLogEndpointTypeNetwork,
					Name:    api.FlowLogNetworkPublic,
					Domains: "www.test-domain.com",
					Port:    &[]uint16{80}[0],
				},
				Proto:      &[]uint8{6}[0],
				ActionFlag: api.ActionFlagAllow,
				Reporter:   api.ReporterTypeSource,
			},
		}
		query.On("QueryFlows", mock.Anything).Return(flows, nil)

		engine := recengine.NewRecommendationEngine(
			ctx,
			"managed-cluster-1",
			mockClientSet.ProjectcalicoV3(),
			mockLinseedClient,
			query,
			cache,
			&v3.PolicyRecommendationScope{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default",
				},
				Spec: v3.PolicyRecommendationScopeSpec{
					Interval: &metav1.Duration{
						Duration: time.Second * 2,
					},
				},
			},
			minPollInterval,
			mockClock,
		)

		for _, ns := range namespaces {
			engine.AddNamespace(ns)
		}

		// Create a new instance of the networkPolicyReconciler
		controller = &recommendationController{
			ctx:       ctx,
			cache:     cache,
			clientSet: mockClientSet,
			engine:    engine,
			clog:      logEntry,
		}
	})

	Describe("syncToDatastore", func() {
		Context("when cache item is not found in cache", func() {
			It("should return nil", func() {
				snp := v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "test-namespace",
						Name:      "test-name",
						Labels: map[string]string{
							v3.LabelTier:           rectypes.PolicyRecommendationTierName,
							calres.StagedActionKey: string(v3.StagedActionLearn),
						},
					},
					Spec: v3.StagedNetworkPolicySpec{
						Tier:         rectypes.PolicyRecommendationTierName,
						StagedAction: v3.StagedActionLearn,
					},
				}

				key := snp.Namespace
				err := controller.syncToDatastore(key)
				Expect(err).To(BeNil())
			})
		})

		Context("when store item is not found", func() {
			var (
				name      = "test-name"
				namespace = "test-namespace"
			)

			BeforeEach(func() {
				// Create a new recommendation in the cache
				snp := v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
						Name:      name,
						Labels: map[string]string{
							v3.LabelTier:           rectypes.PolicyRecommendationTierName,
							calres.StagedActionKey: string(v3.StagedActionSet),
						},
						ResourceVersion: "1",
					},
					Spec: v3.StagedNetworkPolicySpec{
						Tier:         rectypes.PolicyRecommendationTierName,
						StagedAction: v3.StagedActionSet,
						Ingress: []v3.Rule{
							{
								Action: "Allow",
								Source: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
						},
						Egress: []v3.Rule{
							{
								Action: "Allow",
								Destination: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
						},
					},
				}

				controller.cache.Set(snp.Namespace, snp)
			})

			It("should create a new tier and a store value from the cache item", func() {
				_, err := controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Get(controller.ctx, namespace, metav1.GetOptions{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not found"))

				err = controller.syncToDatastore(namespace)
				Expect(err).To(BeNil())

				expectedSnp := v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
						Name:      "test-name",
						Labels: map[string]string{
							v3.LabelTier:           rectypes.PolicyRecommendationTierName,
							calres.StagedActionKey: string(v3.StagedActionSet),
						},
					},
					Spec: v3.StagedNetworkPolicySpec{
						Tier:         rectypes.PolicyRecommendationTierName,
						StagedAction: v3.StagedActionSet,
						Ingress: []v3.Rule{
							{
								Action: "Allow",
								Source: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
						},
						Egress: []v3.Rule{
							{
								Action: "Allow",
								Destination: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
						},
					},
				}

				// Check that the tier was created.
				tier, err := controller.clientSet.ProjectcalicoV3().Tiers().Get(controller.ctx, rectypes.PolicyRecommendationTierName, metav1.GetOptions{})
				Expect(err).To(BeNil())
				Expect(tier.Name).To(Equal(rectypes.PolicyRecommendationTierName))

				// Check that the recommendation was updated.
				store, err := controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Get(controller.ctx, name, metav1.GetOptions{})
				Expect(err).To(BeNil())
				Expect(store.Name).To(Equal(expectedSnp.Name))
				Expect(store.Namespace).To(Equal(expectedSnp.Namespace))
				Expect(store.Labels).To(Equal(expectedSnp.Labels))
				Expect(store.Spec).To(Equal(expectedSnp.Spec))
			})
		})

		Context("when store item is found", func() {
			var (
				namespace = "test-namespace"
				name      = "test-name-tfwgs"
			)

			BeforeEach(func() {
				// Create a new recommendation in the store
				_, err := controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Create(controller.ctx, &v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
						Name:      name,
						Labels: map[string]string{
							v3.LabelTier:           rectypes.PolicyRecommendationTierName,
							calres.StagedActionKey: string(v3.StagedActionSet),
						},
					},
					Spec: v3.StagedNetworkPolicySpec{
						Tier:         rectypes.PolicyRecommendationTierName,
						StagedAction: v3.StagedActionSet,
						Ingress: []v3.Rule{
							{
								Action: "Allow",
								Source: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
						},
						Egress: []v3.Rule{
							{
								Action: "Allow",
								Destination: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
						},
					},
				}, metav1.CreateOptions{})
				Expect(err).To(BeNil())
			})

			It("should update the store item with the cache item", func() {
				// Create a new recommendation in the cache
				snp := v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
						Name:      name,
						Labels: map[string]string{
							v3.LabelTier:           rectypes.PolicyRecommendationTierName,
							calres.StagedActionKey: string(v3.StagedActionSet),
						},
						Annotations: map[string]string{
							calres.StatusKey: calres.LearningStatus,
						},
						ResourceVersion: "1",
					},
					Spec: v3.StagedNetworkPolicySpec{
						Tier:         rectypes.PolicyRecommendationTierName,
						StagedAction: v3.StagedActionSet,
						Ingress: []v3.Rule{
							{
								Action: "Allow",
								Source: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
							{
								Action: "Allow",
								Source: v3.EntityRule{
									NamespaceSelector: "test-namespace-3",
								},
							},
						},
						Egress: []v3.Rule{
							{
								Action: "Allow",
								Destination: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
							{
								Action: "Allow",
								Destination: v3.EntityRule{
									NamespaceSelector: "test-namespace-3",
								},
							},
						},
					},
				}
				controller.cache.Set(snp.Namespace, snp)

				item, ok := controller.cache.Get(namespace)
				Expect(ok).To(BeTrue())
				cacheSnp := item.(v3.StagedNetworkPolicy)

				store, err := controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Get(controller.ctx, name, metav1.GetOptions{})
				Expect(err).To(BeNil())
				Expect(*store).NotTo(Equal(cacheSnp))

				err = controller.syncToDatastore(namespace)
				Expect(err).To(BeNil())

				item, ok = controller.cache.Get(namespace)
				Expect(ok).To(BeTrue())
				updatedCacheSnp := item.(v3.StagedNetworkPolicy)

				// Check that the recommendation was updated.
				store, err = controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Get(controller.ctx, name, metav1.GetOptions{})
				Expect(err).To(BeNil())
				Expect(store.Name).To(Equal(updatedCacheSnp.Name))
				Expect(store.Namespace).To(Equal(updatedCacheSnp.Namespace))
				Expect(store.Labels).To(Equal(updatedCacheSnp.Labels))
				Expect(store.Annotations).To(Equal(updatedCacheSnp.Annotations))
				Expect(store.Spec).To(Equal(updatedCacheSnp.Spec))
			})

			It("should replace the store item with the new cache item if they differ in name", func() {
				// Create a new recommendation in the cache
				snp := v3.StagedNetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
						Name:      "test-name-swftg",
						Labels: map[string]string{
							v3.LabelTier:           rectypes.PolicyRecommendationTierName,
							calres.StagedActionKey: string(v3.StagedActionSet),
						},
						Annotations: map[string]string{
							calres.StatusKey: calres.StableStatus,
						},
						ResourceVersion: "1",
					},
					Spec: v3.StagedNetworkPolicySpec{
						Tier:         rectypes.PolicyRecommendationTierName,
						StagedAction: v3.StagedActionSet,
						Ingress: []v3.Rule{
							{
								Action: "Allow",
								Source: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
							{
								Action: "Allow",
								Source: v3.EntityRule{
									NamespaceSelector: "test-namespace-3",
								},
							},
						},
						Egress: []v3.Rule{
							{
								Action: "Allow",
								Destination: v3.EntityRule{
									NamespaceSelector: "test-namespace-2",
								},
							},
							{
								Action: "Allow",
								Destination: v3.EntityRule{
									NamespaceSelector: "test-namespace-3",
								},
							},
						},
					},
				}
				controller.cache.Set(snp.Namespace, snp)

				item, ok := controller.cache.Get(namespace)
				Expect(ok).To(BeTrue())
				cacheSnp := item.(v3.StagedNetworkPolicy)

				store, err := controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Get(controller.ctx, name, metav1.GetOptions{})
				Expect(err).To(BeNil())
				Expect(*store).NotTo(Equal(cacheSnp))
				Expect(store.Name).NotTo(Equal(cacheSnp.Name))

				err = controller.syncToDatastore(namespace)
				Expect(err).To(BeNil())

				item, ok = controller.cache.Get(namespace)
				Expect(ok).To(BeTrue())
				updatedCacheSnp := item.(v3.StagedNetworkPolicy)

				// Check that the recommendation was replaced.
				store, err = controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Get(controller.ctx, updatedCacheSnp.Name, metav1.GetOptions{})
				Expect(err).To(BeNil())
				Expect(store.Name).To(Equal(updatedCacheSnp.Name))
				Expect(store.Namespace).To(Equal(updatedCacheSnp.Namespace))
				Expect(store.Labels).To(Equal(updatedCacheSnp.Labels))
				Expect(store.Spec).To(Equal(updatedCacheSnp.Spec))

				// Check that the old recommendation was deleted.
				_, err = controller.clientSet.ProjectcalicoV3().StagedNetworkPolicies(namespace).Get(controller.ctx, name, metav1.GetOptions{})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not found"))
			})
		})
	})

	Describe("handleErr", func() {
		var (
			key string
		)

		Context("when error is nil", func() {
			It("should forget about the key", func() {
				controller.handleErr(nil, key)
				Expect(controller.cache.GetQueue().NumRequeues(key)).To(Equal(0))
			})
		})

		Context("when error is not nil", func() {
			var (
				err error
			)

			BeforeEach(func() {
				err = errors.New("test-error")
			})

			Context("when number of requeues is less than retries", func() {
				BeforeEach(func() {
					for range retries - 1 {
						controller.cache.GetQueue().AddRateLimited(key)
					}
				})

				It("should re-enqueue the key", func() {
					controller.handleErr(err, key)
					Expect(controller.cache.GetQueue().NumRequeues(key)).To(Equal(retries))
				})
			})

			Context("when number of requeues is equal to retries", func() {
				BeforeEach(func() {
					for range retries {
						controller.cache.GetQueue().AddRateLimited(key)
					}
				})

				It("should forget about the key and report the error", func() {
					controller.handleErr(err, key)
					Expect(controller.cache.GetQueue().NumRequeues(key)).To(Equal(0))
					Expect(buffer.String()).To(ContainSubstring("test-error"))
				})
			})
		})
	})
})
