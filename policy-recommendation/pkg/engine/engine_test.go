// Copyright (c) 2024-2025 Tigera Inc. All rights reserved.

package engine

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	libcselector "github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	calicores "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	querymocks "github.com/projectcalico/calico/policy-recommendation/pkg/flows/mocks"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

type MockClock struct{}

func (MockClock) NowRFC3339() string { return []string{"2022-01-01T00:00:00Z"}[0] }

var _ = Describe("RecommendationEngine", func() {
	const (
		newSelector = `!(projectcalico.org/name starts with 'tigera-') && ` +
			`!(projectcalico.org/name starts with 'calico-') && ` +
			`!(projectcalico.org/name starts with 'kube-') && ` +
			`!(projectcalico.org/name starts with 'openshift-')`

		// kindRecommendations is the kind of the recommendations resource.
		kindRecommendations = "recommendations"

		retryInterval = 100 * time.Millisecond
		retries       = 5
	)

	var (
		stopChan chan struct{}
		engine   *recommendationEngine
		logEntry *log.Entry
	)

	BeforeEach(func() {
		ctx := context.Background()
		logEntry = log.WithField("test", "test")
		mockClock := MockClock{}
		stopChan = make(chan struct{})

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

		parsedSelector, err := libcselector.Parse(`projectcalico.org/name == 'default'`)
		Expect(err).NotTo(HaveOccurred())

		mockClientSet := lmak8s.NewMockClientSet(GinkgoT())
		mockClientSet.On("ProjectcalicoV3").Return(fakecalico.NewSimpleClientset().ProjectcalicoV3())
		mockClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1())

		_, err = mockClientSet.ProjectcalicoV3().StagedNetworkPolicies("test-namespace").Create(ctx, &v3.StagedNetworkPolicy{}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = mockClientSet.ProjectcalicoV3().StagedNetworkPolicies("tigera-namespace").Create(ctx, &v3.StagedNetworkPolicy{}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = mockClientSet.ProjectcalicoV3().StagedNetworkPolicies("openshift-namespace").Create(ctx, &v3.StagedNetworkPolicy{}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Get the list of recommendations from the datastore with retries.
		listRecommendations := func(ret int) ([]v3.StagedNetworkPolicy, error) {
			var err error
			var snps *v3.StagedNetworkPolicyList
			for i := 0; i < ret; i++ {
				snps, err = mockClientSet.ProjectcalicoV3().StagedNetworkPolicies(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
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

		cache.Set("test-namespace", v3.StagedNetworkPolicy{})
		cache.Set("tigera-namespace", v3.StagedNetworkPolicy{})
		cache.Set("openshift-namespace", v3.StagedNetworkPolicy{})

		engine = &recommendationEngine{
			namespaces:         set.FromArray[string]([]string{"test-namespace", "tigera-namespace", "openshift-namespace"}),
			filteredNamespaces: set.FromArray[string]([]string{}),
			cache:              cache,
			scope: &recommendationScope{
				interval:                  1 * time.Minute,
				initialLookback:           1 * time.Hour,
				stabilization:             1 * time.Hour,
				selector:                  parsedSelector,
				passIntraNamespaceTraffic: false,
				uid:                       "rrf2w-2343f-2342f-00000",
				clog:                      logEntry,
			},
			updateChannel: make(chan v3.PolicyRecommendationScope),
			clock:         mockClock,
			query:         query,
			clog:          logEntry,
		}
	})

	AfterEach(func() {
		close(stopChan)
	})

	Context("Run", func() {
		It("should run the engine", func() {
			go engine.Run(stopChan)

			// Simulate an update to the updateChannel
			update := v3.PolicyRecommendationScope{
				ObjectMeta: metav1.ObjectMeta{
					UID: "rrf2w-2343f-2342f-11111",
				},
				Spec: v3.PolicyRecommendationScopeSpec{
					Interval: &metav1.Duration{Duration: 30 * time.Second},
					InitialLookback: &metav1.Duration{
						Duration: 2 * time.Minute,
					},
					StabilizationPeriod: &metav1.Duration{
						Duration: 2 * time.Minute,
					},
					NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
						IntraNamespacePassThroughTraffic: true,
						Selector:                         newSelector,
					},
				},
			}
			engine.updateChannel <- update

			newParsedSelector, err := libcselector.Parse(newSelector)
			Expect(err).NotTo(HaveOccurred())

			// Wait for the engine to process the update
			Eventually(func() bool {
				return engine.scope.interval == 30*time.Second && engine.scope.initialLookback == 2*time.Minute &&
					engine.scope.stabilization == 2*time.Minute && engine.scope.selector.String() == newParsedSelector.String() &&
					engine.scope.passIntraNamespaceTraffic == true && engine.scope.uid == "rrf2w-2343f-2342f-11111"
			}, 2*time.Second, 100*time.Millisecond).Should(BeTrue())

			logEntry.Infof("Filtered namespaces: %s", engine.filteredNamespaces)
			Eventually(func() bool {
				return engine.filteredNamespaces.Contains("test-namespace") && !engine.filteredNamespaces.Contains("openshift-namespace") &&
					!engine.filteredNamespaces.Contains("tiger-namespace")
			}, 2*time.Second, 100*time.Millisecond).Should(BeTrue())

			Eventually(func() bool {
				_, ok1 := engine.cache.Get("test-namespace")
				_, ok2 := engine.cache.Get("tigera-namespace")
				_, ok3 := engine.cache.Get("openshift-namespace")
				return ok1 && !ok2 && !ok3
			}, 2*time.Second, 100*time.Millisecond).Should(BeTrue())

			// Stop the engine
			stopChan <- struct{}{}
		})
	})

	Context("update", func() {
		It("should return false for empty staged network policy", func() {
			result := engine.update(nil)
			Expect(result).To(BeFalse())
		})

		It("should return false for staged network policy with non-learning action", func() {
			snp := &v3.StagedNetworkPolicy{
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionLearn,
				},
			}
			result := engine.update(snp)
			Expect(result).To(BeFalse())
		})

		It("should return false for failed flows logs query", func() {
			snp := &v3.StagedNetworkPolicy{
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionLearn,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "test-namespace",
				},
			}
			mockQuery := &querymocks.PolicyRecommendationQuery{}
			mockQuery.On("QueryFlows", mock.Anything).Return(nil, errors.New("failed to query flows logs"))
			engine.query = mockQuery

			result := engine.update(snp)
			Expect(result).To(BeFalse())
		})

		It("should return true and call rec.update for non-empty flows logs", func() {
			snp := &v3.StagedNetworkPolicy{
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionLearn,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test-policy",
					Namespace:   "test-namespace",
					Annotations: map[string]string{},
				},
			}

			result := engine.update(snp)
			Expect(result).To(BeTrue())

			tcpProto := numorstring.ProtocolFromString("TCP")
			Expect(snp).To(Equal(&v3.StagedNetworkPolicy{
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionLearn,
					Egress: []v3.Rule{
						{
							Action:   v3.Allow,
							Protocol: &tcpProto,
							Destination: v3.EntityRule{
								Ports: []numorstring.Port{
									{MinPort: 80, MaxPort: 80},
								},
								Domains: []string{"www.test-domain.com"},
							},
							Metadata: &v3.RuleMetadata{
								Annotations: map[string]string{
									"policyrecommendation.tigera.io/scope":       "Domains",
									"policyrecommendation.tigera.io/lastUpdated": "2022-01-01T00:00:00Z",
								},
							},
						},
					},
					Types: []v3.PolicyType{v3.PolicyTypeEgress},
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-policy",
					Namespace: "test-namespace",
					Annotations: map[string]string{
						"policyrecommendation.tigera.io/status":      "Learning",
						"policyrecommendation.tigera.io/lastUpdated": "2022-01-01T00:00:00Z",
					},
				},
			}))
		})
	})

	Context("getLookback", func() {
		It("should return initial lookback if LastUpdatedKey annotation is not present", func() {
			snp := v3.StagedNetworkPolicy{}
			lookback := engine.getLookback(snp)
			Expect(lookback).To(Equal(engine.scope.initialLookback))
		})

		It("should return twice the engine-run interval if LastUpdatedKey annotation is present", func() {
			snp := v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						calicores.LastUpdatedKey: "2022-01-01T00:00:00Z",
					},
				},
			}
			lookback := engine.getLookback(snp)
			expectedLookback := engine.scope.interval * 2
			Expect(lookback).To(Equal(expectedLookback))
		})
	})

	Context("removeRulesReferencingDeletedNamespace", func() {
		var (
			engine    *recommendationEngine
			snp       *v3.StagedNetworkPolicy
			namespace string
		)

		BeforeEach(func() {
			engine = &recommendationEngine{
				clog: log.WithField("test", "test"),
			}
			snp = &v3.StagedNetworkPolicy{
				Spec: v3.StagedNetworkPolicySpec{
					Ingress: []v3.Rule{
						{
							Source: v3.EntityRule{
								NamespaceSelector: "namespace1",
							},
						},
						{
							Source: v3.EntityRule{
								NamespaceSelector: "namespace2",
							},
						},
					},
					Egress: []v3.Rule{
						{
							Destination: v3.EntityRule{
								NamespaceSelector: "namespace1",
							},
						},
						{
							Destination: v3.EntityRule{
								NamespaceSelector: "namespace2",
							},
						},
					},
				},
			}
			namespace = "namespace1"
		})

		It("should remove rules referencing the deleted namespace", func() {
			engine.removeRulesReferencingDeletedNamespace(snp, namespace)

			Expect(snp.Spec.Ingress).To(HaveLen(1))
			Expect(snp.Spec.Ingress[0].Source.NamespaceSelector).To(Equal("namespace2"))

			Expect(snp.Spec.Egress).To(HaveLen(1))
			Expect(snp.Spec.Egress[0].Destination.NamespaceSelector).To(Equal("namespace2"))
		})

		It("should not remove any rules if the namespace is not referenced", func() {
			namespace = "namespace3"

			engine.removeRulesReferencingDeletedNamespace(snp, namespace)

			Expect(snp.Spec.Ingress).To(HaveLen(2))
			Expect(snp.Spec.Egress).To(HaveLen(2))
		})
	})
})
