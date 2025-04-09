// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
package managed_cluster_controller

import (
	"context"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeK8s "k8s.io/client-go/kubernetes/fake"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	k8sctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakectlrruntimeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	rscope "github.com/projectcalico/calico/policy-recommendation/pkg/controllers/recommendation_scope"
)

var _ = Describe("ManagedClusterReconciler", func() {
	var (
		ctx                      context.Context
		r                        *managedClusterReconciler
		fakek8sCtrlRuntimeClient k8sctrlclient.WithWatch
		mockClientSetFactory     *lmak8s.MockClientSetFactory
		mockClientSet            *lmak8s.MockClientSet
	)

	BeforeEach(func() {
		ctx = context.TODO()

		mockClientSet = lmak8s.NewMockClientSet(GinkgoT())
		mockClientSet.On("ProjectcalicoV3").Return(fakecalico.NewSimpleClientset().ProjectcalicoV3())
		mockClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1())

		mockClientSetFactory = lmak8s.NewMockClientSetFactory(GinkgoT())
		mockClientSetFactory.On("NewClientSetForApplication", "managed-cluster-1").Return(mockClientSet, nil)
		mockClientSetFactory.On("NewClientSetForApplication", "managed-cluster-2").Return(mockClientSet, nil)
		scheme := kscheme.Scheme
		err := v3.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		fakek8sCtrlRuntimeClient = fakectlrruntimeclient.NewClientBuilder().WithScheme(scheme).Build()
		err = fakek8sCtrlRuntimeClient.Create(ctx, &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: "managed-cluster-1",
			},
		})
		Expect(err).NotTo(HaveOccurred())
		err = fakek8sCtrlRuntimeClient.Create(ctx, &v3.ManagedCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: "managed-cluster-2",
			},
		})
		Expect(err).NotTo(HaveOccurred())

		r = &managedClusterReconciler{
			ctx:                              ctx,
			client:                           fakek8sCtrlRuntimeClient,
			clientFactory:                    mockClientSetFactory,
			linseed:                          lsclient.NewMockClient(""),
			managedClusters:                  make(map[string]*managedClusterCtrlContext),
			mutex:                            sync.Mutex{},
			newRecommendationScopeController: newMockRecommendationScopeControllers,
		}
	})

	It("should reconcile a deleted managed cluster", func() {
		stopChan := make(chan struct{})
		r.managedClusters["managed-cluster-3"] = &managedClusterCtrlContext{
			ctrl:     nil,
			stopChan: stopChan,
		}
		Expect(len(r.managedClusters)).To(Equal(1))
		Expect(r.managedClusters["managed-cluster-3"]).NotTo(BeNil())
		key := types.NamespacedName{Name: "managed-cluster-3"}
		err := r.Reconcile(key)
		Expect(err).To(BeNil())
		Expect(stopChan).To(BeClosed())
		Expect(r.managedClusters["managed-cluster-3"]).To(BeNil())
	})

	It("should reconcile a new managed cluster", func() {
		Expect(r.managedClusters["managed-cluster-2"]).To(BeNil())
		key := types.NamespacedName{Name: "managed-cluster-2"}
		err := r.Reconcile(key)
		Expect(err).To(BeNil())
		Expect(len(r.managedClusters)).To(Equal(1))
		Expect(r.managedClusters["managed-cluster-2"]).NotTo(BeNil())
	})

	It("should reconcile an existing managed cluster", func() {
		stopChan := make(chan struct{})
		r.managedClusters["managed-cluster-2"] = &managedClusterCtrlContext{
			ctrl:     nil,
			stopChan: stopChan,
		}
		Expect(len(r.managedClusters)).To(Equal(1))
		Expect(r.managedClusters["managed-cluster-2"]).NotTo(BeNil())
		key := types.NamespacedName{Name: "managed-cluster-2"}
		err := r.Reconcile(key)
		Expect(err).To(BeNil())
		Expect(len(r.managedClusters)).To(Equal(1))
		Expect(r.managedClusters["managed-cluster-2"]).NotTo(BeNil())
	})

	It("should reconcile a deleted managed cluster and a concurrent request", func() {
		stopChan := make(chan struct{})
		r.managedClusters["managed-cluster-3"] = &managedClusterCtrlContext{
			ctrl:     nil,
			stopChan: stopChan,
		}
		Expect(len(r.managedClusters)).To(Equal(1))
		Expect(r.managedClusters["managed-cluster-3"]).NotTo(BeNil())

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			err := r.Reconcile(types.NamespacedName{Name: "managed-cluster-3"})
			Expect(err).To(BeNil())
			wg.Done()
		}()

		wg.Add(1)
		go func() {
			mockClientSetFactory.On("NewClientSetForApplication", "managed-cluster-4").Return(mockClientSet, nil)
			err := r.client.Create(context.Background(), &v3.ManagedCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "managed-cluster-4",
				},
			})
			Expect(err).NotTo(HaveOccurred())
			err = r.Reconcile(types.NamespacedName{Name: "managed-cluster-4"})
			Expect(err).To(BeNil())
			wg.Done()
		}()
		wg.Wait()

		Eventually(stopChan, 1000*time.Second).Should(BeClosed())
		Eventually(len(r.managedClusters), 1000*time.Second).Should(Equal(1))
	})
})

// Create a mock implementation of the recommendationScopeController interface.
type mockRecommendationScopeController struct{}

func (m *mockRecommendationScopeController) Run(stopCh chan struct{}) {}

func newMockRecommendationScopeControllers(
	ctx context.Context,
	clusterID string,
	clientSet lmak8s.ClientSet,
	linseed lsclient.Client,
	minPollInterval metav1.Duration,
	watcherCfg rscope.WatcherConfig,
) (controller.Controller, error) {
	return &mockRecommendationScopeController{}, nil
}
