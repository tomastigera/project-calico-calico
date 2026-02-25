// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
package recommendation_controller

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	recengine "github.com/projectcalico/calico/policy-recommendation/pkg/engine"
	querymocks "github.com/projectcalico/calico/policy-recommendation/pkg/flows/mocks"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

var mt *string

type MockClock struct{}

func (MockClock) NowRFC3339() string { return *mt }

var _ = Describe("NamespaceReconciler", func() {
	const (
		// kindRecommendations is the kind of the recommendations resource.
		kindRecommendations = "recommendations"

		testNamespace  = "test-namespace"
		testNamespace2 = "test-namespace2"

		// retryInterval is the interval between retries.
		retryInterval = time.Second * 2
	)

	var (
		mockClientSet *lmak8s.MockClientSet
		r             *namespaceReconciler
	)

	BeforeEach(func() {
		ctx := context.TODO()
		buffer := &bytes.Buffer{}
		// Create a new Logrus logger instance
		logger := log.New()
		// Set the logger's output to the buffer
		logger.SetOutput(buffer)
		// Create a new managed cluster logger entry
		logEntry := logger.WithField("ManagedCluster", "controller")

		mockClientSet = &lmak8s.MockClientSet{}
		mockClientSet.On("ProjectcalicoV3").Return(fakecalico.NewSimpleClientset().ProjectcalicoV3()).Maybe()
		mockClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1()).Maybe()

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

		minPollInterval := metav1.Duration{Duration: time.Second * 30}
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
					NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
						Selector: "!(projectcalico.org/name starts with 'tigera-') && !(projectcalico.org/name starts with 'calico-') && " +
							"!(projectcalico.org/name starts with 'kube-') && !(projectcalico.org/name starts with 'openshift-')",
					},
				},
			},
			minPollInterval,
			mockClock,
		)

		for _, ns := range namespaces {
			engine.AddNamespace(ns)
		}

		// Create a new namespaceReconciler instance with the fake clientSet
		r = &namespaceReconciler{
			clientSet: mockClientSet,
			ctx:       ctx,
			engine:    engine,
			clog:      logEntry,
			cache:     cache,
		}
	})

	Context("When the namespace is created", func() {
		It("should add the namespace to the engine for processing if the selector is validated", func() {

			// Setup
			// Create a namespace in the mock Kubernetes client
			createNamespaces(mockClientSet, testNamespace)

			// Run
			// Reconcile the namespace
			reconcileNamespaces(r, testNamespace)

			// Verify
			// Check that the namespace was added to the engine's namespaces and filtered namespaces
			key := types.NamespacedName{
				Name:      testNamespace,
				Namespace: testNamespace,
			}
			Expect(r.engine.GetNamespaces().Contains(key.Name)).To(BeTrue())
			Expect(r.engine.GetFilteredNamespaces().Contains(key.Name)).To(BeTrue())
		})

		It("should not add the namespace to the engine for processing if the selector is not validated", func() {
			const (
				// Namespaces that should not be added to the filtered namespaces
				tigeraNamespace    = "tigera-namespace"
				calicoNamespace    = "calico-namespace"
				kubeNamespace      = "kube-namespace"
				openshiftNamespace = "openshift-namespace"
			)

			// Create a namespace that won't be filtered out
			createNamespaces(mockClientSet, testNamespace)
			// We test against the default selector, which excludes namespaces starting with "calico-",
			// "kube-", "tigera-", and  added "openshift-".
			// Create namespaces that will be filtered out
			createNamespaces(mockClientSet, tigeraNamespace, calicoNamespace, kubeNamespace, openshiftNamespace)

			// Reconcile the namespaces
			reconcileNamespaces(r, testNamespace, tigeraNamespace, calicoNamespace, kubeNamespace, openshiftNamespace)

			// Check that the namespace was added to the engine's namespaces and filtered namespaces
			key := types.NamespacedName{
				Name:      testNamespace,
				Namespace: testNamespace,
			}
			Expect(r.engine.GetNamespaces().Contains(key.Name)).To(BeTrue())
			Expect(r.engine.GetFilteredNamespaces().Contains(key.Name)).To(BeTrue())

			// Check that the namespace was added to the engine's namespaces but not the filtered namespaces
			keyTigera := types.NamespacedName{
				Name:      tigeraNamespace,
				Namespace: tigeraNamespace,
			}
			Expect(r.engine.GetNamespaces().Contains(keyTigera.Name)).To(BeTrue())
			Expect(r.engine.GetFilteredNamespaces().Contains(keyTigera.Name)).To(BeFalse())
			keyCalico := types.NamespacedName{
				Name:      calicoNamespace,
				Namespace: calicoNamespace,
			}
			Expect(r.engine.GetNamespaces().Contains(keyCalico.Name)).To(BeTrue())
			Expect(r.engine.GetFilteredNamespaces().Contains(keyCalico.Name)).To(BeFalse())
			keyKube := types.NamespacedName{
				Name:      kubeNamespace,
				Namespace: kubeNamespace,
			}
			Expect(r.engine.GetNamespaces().Contains(keyKube.Name)).To(BeTrue())
			Expect(r.engine.GetFilteredNamespaces().Contains(keyKube.Name)).To(BeFalse())
			keyOpenshift := types.NamespacedName{
				Name:      openshiftNamespace,
				Namespace: openshiftNamespace,
			}
			Expect(r.engine.GetNamespaces().Contains(keyOpenshift.Name)).To(BeTrue())
			Expect(r.engine.GetFilteredNamespaces().Contains(keyOpenshift.Name)).To(BeFalse())
		})
	})

	Context("When the namespace is deleted", func() {
		const (
			namespaceToDelete  = "test-delete-namespace"
			namespaceToDelete2 = "test-delete-namespace2"
		)

		var wg sync.WaitGroup

		BeforeEach(func() {
			// Add two namespaces to delete
			setupEngineAndCache(r, namespaceToDelete, namespaceToDelete2)
			createNamespaces(mockClientSet, namespaceToDelete, namespaceToDelete2)
		})

		It("should handle concurrent deletions from the engine's processing items and the cache", func() {
			// Setup the namespace to keep
			setupEngineAndCache(r, testNamespace)
			createNamespaces(mockClientSet, testNamespace)

			// Delete the namespaces concurrently and reconcile them
			wg.Add(1)
			go func() {
				defer GinkgoRecover() // Ensure panics are recovered and reported properly
				defer wg.Done()       // Mark as done when the goroutine completes

				deleteNamespaces(mockClientSet, namespaceToDelete)

				// Reconcile the namespaces
				reconcileNamespaces(r, namespaceToDelete)

			}()
			wg.Add(1)
			go func() {
				defer GinkgoRecover() // Ensure panics are recovered and reported properly
				defer wg.Done()       // Mark as done when the goroutine completes

				deleteNamespaces(mockClientSet, namespaceToDelete2)

				// Reconcile the namespaces
				reconcileNamespaces(r, namespaceToDelete2)

			}()

			// Wait for the goroutines to finish
			wg.Wait()

			// Verify that the namespace to keep is added to the cache and engine
			Eventually(func() bool {
				_, ok := r.cache.Get(testNamespace)
				return ok && r.engine.GetNamespaces().Contains(testNamespace) && r.engine.GetFilteredNamespaces().Contains(testNamespace)
			}, 10*time.Second).Should(BeTrue())
			// Verify that the namespace to delete is removed from the cache and engine
			Eventually(func() bool {
				_, ok := r.cache.Get(namespaceToDelete)
				if !ok && !r.engine.GetNamespaces().Contains(namespaceToDelete) && !r.engine.GetFilteredNamespaces().Contains(namespaceToDelete) {
					return true
				}
				return false
			}, 10*time.Second).Should(BeTrue())
			Eventually(func() bool {
				_, ok := r.cache.Get(namespaceToDelete2)
				if !ok && !r.engine.GetNamespaces().Contains(namespaceToDelete2) && !r.engine.GetFilteredNamespaces().Contains(namespaceToDelete2) {
					return true
				}
				return false
			}, 10*time.Second).Should(BeTrue())
		})

		It("should handle concurrent addition and deletion of namespaces to/from the engine's processing items and the cache", func() {
			setupEngineAndCache(r, testNamespace)

			// Concurrently create a new namespace
			wg.Add(1)
			go func() {
				defer GinkgoRecover() // Ensure panics are recovered and reported properly
				defer wg.Done()       // Mark as done when the goroutine completes

				createNamespaces(mockClientSet, testNamespace)

				// Reconcile the namespace
				reconcileNamespaces(r, testNamespace)

			}()

			// Concurrently delete the namespace to be removed
			wg.Add(1)
			go func() {
				defer GinkgoRecover() // Ensure panics are recovered and reported properly
				defer wg.Done()       // Mark as done when the goroutine completes

				deleteNamespaces(mockClientSet, namespaceToDelete)

				// Reconcile the namespace
				reconcileNamespaces(r, namespaceToDelete)
			}()

			// Wait for the goroutines to finish
			wg.Wait()

			// Verify that the new namespace is added to the engine's namespaces and filtered namespaces
			Eventually(func() bool {
				_, ok := r.cache.Get(testNamespace)
				return ok && r.engine.GetNamespaces().Contains(testNamespace) && r.engine.GetFilteredNamespaces().Contains(testNamespace)
			}, 10*time.Second).Should(BeTrue())
			// Verify that the namespace to be removed is removed from the cache and engine
			Eventually(func() bool {
				_, ok := r.cache.Get(namespaceToDelete)
				return !ok && !r.engine.GetNamespaces().Contains(namespaceToDelete) && !r.engine.GetFilteredNamespaces().Contains(namespaceToDelete)
			}, 10*time.Second).Should(BeTrue())
		})

		It("should remove the namespace reference from the rules of all other cache items", func() {
			r.cache.Set(testNamespace, v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testNamespace,
					Namespace: testNamespace,
				},
				Spec: v3.StagedNetworkPolicySpec{
					Egress: []v3.Rule{
						{
							Action: "Allow",
							Destination: v3.EntityRule{
								NamespaceSelector: namespaceToDelete,
							},
						},
						{
							Action: "Allow",
							Destination: v3.EntityRule{
								NamespaceSelector: testNamespace2,
							},
						},
					},
					Ingress: []v3.Rule{
						{
							Action: "Allow",
							Source: v3.EntityRule{
								NamespaceSelector: namespaceToDelete,
							},
						},
						{
							Action: "Allow",
							Source: v3.EntityRule{
								NamespaceSelector: testNamespace2,
							},
						},
					},
				},
			})
			// Delete the namespace in the mock Kubernetes client
			deleteNamespaces(mockClientSet, namespaceToDelete)

			// Reconcile the namespace
			reconcileNamespaces(r, namespaceToDelete)

			// Verify that the namespace was removed from the cache
			Eventually(func() bool {
				key := types.NamespacedName{
					Name:      namespaceToDelete,
					Namespace: namespaceToDelete,
				}
				_, exists := r.cache.Get(key.Name)
				return !exists && !r.engine.GetNamespaces().Contains(key.Name)
			}, 10*time.Second).Should(BeTrue())

			// Verify that the namespace reference was removed from the rules of all other cache items
			Eventually(func() bool {
				item, exists := r.cache.Get(testNamespace)
				if !exists {
					return false
				}
				snp := item.(v3.StagedNetworkPolicy)
				return len(snp.Spec.Egress) == 1 && len(snp.Spec.Ingress) == 1 &&
					snp.Spec.Egress[0].Destination.NamespaceSelector == testNamespace2 &&
					snp.Spec.Ingress[0].Source.NamespaceSelector == testNamespace2
			}, 10*time.Second).Should(BeTrue())
		})
	})
})

// createNamespaces creates namespaces in the mock Kubernetes client and verifies that it was created.
func createNamespaces(mockClientSet *lmak8s.MockClientSet, namespaces ...string) {
	for _, ns := range namespaces {
		// Create a namespace in the mock Kubernetes client
		_, err := mockClientSet.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: ns,
			},
		}, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
	}

	// Verify that the namespace was created
	Eventually(func() bool {
		for _, ns := range namespaces {
			if val, err := mockClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{}); err != nil || val == nil {
				return false
			}
		}
		return true
	}, 10*time.Second).Should(BeTrue())
}

// deleteNamespaces deletes namespaces in the mock Kubernetes client and verifies that it was deleted.
func deleteNamespaces(mockClientSet *lmak8s.MockClientSet, namespaces ...string) {
	for _, ns := range namespaces {
		// Delete the namespace in the mock Kubernetes client
		err := mockClientSet.CoreV1().Namespaces().Delete(context.TODO(), ns, metav1.DeleteOptions{})
		Expect(err).ToNot(HaveOccurred())
	}

	// Verify that the namespace was deleted
	Eventually(func() bool {
		for _, ns := range namespaces {
			if _, err := mockClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{}); err == nil {
				return false
			}
		}
		return true
	}, 10*time.Second).Should(BeTrue())
}

// reconcileNamespaces reconciles namespaces in the namespace reconciler.
func reconcileNamespaces(r *namespaceReconciler, namespaces ...string) {
	for _, ns := range namespaces {
		err := r.Reconcile(types.NamespacedName{
			Name:      ns,
			Namespace: ns,
		})
		Expect(err).ToNot(HaveOccurred())
	}
}

// setupEngineAndCache adds namespaces to the engine's namespaces and filtered namespaces, and adds
// it to the cache.
func setupEngineAndCache(r *namespaceReconciler, namespaces ...string) {
	for _, ns := range namespaces {
		// Add namespace to the engine's namespaces and filtered namespaces
		r.engine.GetNamespaces().Add(ns)
		Expect(r.engine.GetNamespaces().Contains(ns)).To(BeTrue())
		r.engine.GetFilteredNamespaces().Add(ns)
		Expect(r.engine.GetFilteredNamespaces().Contains(ns)).To(BeTrue())

		// Add namespace to the cache
		r.cache.Set(ns, v3.StagedNetworkPolicy{})
		v, ok := r.cache.Get(ns)
		Expect(v).ToNot(BeNil())
		Expect(ok).To(BeTrue())
	}
}
