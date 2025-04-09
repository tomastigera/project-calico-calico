// Copyright (c) 2024-2025 Tigera Inc. All rights reserved.

package watcher_test

import (
	"context"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	k8scache "k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/watcher"
)

// mockReconciler is a basic mock implementation of the controller.Reconciler interface.
type mockReconciler struct {
	callCount int32
}

func (m *mockReconciler) Reconcile(key types.NamespacedName) error {
	atomic.AddInt32(&m.callCount, 1)
	return nil
}

func (m *mockReconciler) Calls() int {
	return int(atomic.LoadInt32(&m.callCount))
}

var _ = Describe("Watcher", func() {
	var (
		ctx         context.Context
		cancel      context.CancelFunc
		testWatcher watcher.Watcher

		mockRec *mockReconciler

		stopChan chan struct{}
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())
		stopChan = make(chan struct{})
		mockRec = &mockReconciler{}
	})

	AfterEach(func() {
		// Signal the watcher to stop.
		cancel()
		close(stopChan)
	})

	Describe("Run", func() {
		When("watching for calico resources", func() {
			var fakeCalicoClient *fakecalico.Clientset

			BeforeEach(func() {
				fakeCalicoClient = fakecalico.NewSimpleClientset()
				testWatcher = watcher.NewWatcher(
					mockRec,
					&k8scache.ListWatch{
						ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
							options.FieldSelector = fields.OneTermEqualSelector("metadata.namespace", "policy-recommendation").String()
							return fakeCalicoClient.ProjectcalicoV3().PolicyRecommendationScopes().List(ctx, options)
						},
						WatchFunc: func(options metav1.ListOptions) (k8swatch.Interface, error) {
							options.FieldSelector = fields.OneTermEqualSelector("metadata.namespace", "policy-recommendation").String()
							return fakeCalicoClient.ProjectcalicoV3().PolicyRecommendationScopes().Watch(ctx, options)
						},
					},
					&v3.PolicyRecommendationScope{},
				)
			})

			It("should trigger reconcile loop on each event", func() {
				go testWatcher.Run(stopChan)

				_, err := fakeCalicoClient.ProjectcalicoV3().PolicyRecommendationScopes().Create(ctx, &v3.PolicyRecommendationScope{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-recommendation",
					},
					Spec: v3.PolicyRecommendationScopeSpec{
						NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
							RecStatus: v3.PolicyRecommendationScopeEnabled,
						},
					},
				}, metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() int {
					return mockRec.Calls()
				}, 2*time.Second, 200*time.Millisecond).Should(Equal(1), "Expected Reconcile calls after creating scope")

				_, err = fakeCalicoClient.ProjectcalicoV3().PolicyRecommendationScopes().Update(ctx, &v3.PolicyRecommendationScope{
					ObjectMeta: metav1.ObjectMeta{
						Name: "policy-recommendation",
					},
					Spec: v3.PolicyRecommendationScopeSpec{
						NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
							RecStatus: v3.PolicyRecommendationScopeDisabled,
						},
					},
				}, metav1.UpdateOptions{})
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() int {
					return mockRec.Calls()
				}, 2*time.Second, 200*time.Millisecond).Should(Equal(2), "Expected Reconcile calls after creating updating scope")

				err = fakeCalicoClient.ProjectcalicoV3().PolicyRecommendationScopes().Delete(ctx, "policy-recommendation", metav1.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())

				Eventually(func() int {
					return mockRec.Calls()
				}, 2*time.Second, 200*time.Millisecond).Should(Equal(3), "Expected Reconcile calls after deleting scope")
			})
		})
	})
})
