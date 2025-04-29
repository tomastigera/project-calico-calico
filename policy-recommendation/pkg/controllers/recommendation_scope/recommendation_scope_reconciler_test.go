// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
package recommendation_scope_controller

import (
	"bytes"
	"context"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/policy-recommendation/pkg/controllers/controller"
	recengine "github.com/projectcalico/calico/policy-recommendation/pkg/engine"
	rectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

var _ = Describe("RecommendationScopeReconciler", func() {

	var (
		ctx            context.Context
		buffer         *bytes.Buffer
		mockEngine     *mockRecommendationEngine
		logEntry       *log.Entry
		mockNamespaced types.NamespacedName
		mockCtrl       *mockRecommendationController
		mockClientSet  *lmak8s.MockClientSet
	)

	BeforeEach(func() {
		buffer = &bytes.Buffer{}
		// Create a new Logrus logger instance
		logger := log.New()
		// Set the logger's output to the buffer
		logger.SetOutput(buffer)
		// Create a new managed cluster logger entry
		logEntry = logger.WithField("RecommendationScope", "controller")

		ctx = context.TODO()

		mockEngine = newMockRecommendationEngine()
		mockCtrl = newMockRecommendationController(mockEngine)

		mockNamespaced = types.NamespacedName{}

		mockClientSet = lmak8s.NewMockClientSet(GinkgoT())
		mockClientSet.On("ProjectcalicoV3").Return(fakecalico.NewSimpleClientset().ProjectcalicoV3())
	})

	Describe("Reconcile", func() {
		Context("When Reconcile is called with a PolicyRecommendationScope", func() {
			var (
				scopeReconciler *recommendationScopeReconciler
			)

			BeforeEach(func() {
				mockNamespaced.Name = rectypes.PolicyRecommendationScopeName
				mockNamespaced.Namespace = v1.NamespaceAll

				scopeReconciler = &recommendationScopeReconciler{
					reconcilerBase: &reconcilerBase{
						ctx:       ctx,
						clientSet: mockClientSet,
						enabled:   v3.PolicyRecommendationScopeDisabled,
						mutex:     sync.Mutex{},
						stopChan:  make(chan struct{}),
						clog:      logEntry,
						ctrlFactory: func(scope *v3.PolicyRecommendationScope) (controller.Controller, recengine.RecommendationEngine, error) {
							return mockCtrl, mockEngine, nil
						},
					},
				}
			})

			It("should gracefully ignore keys that don't match the target key", func() {
				mockNamespaced.Name = "other"
				err := scopeReconciler.Reconcile(mockNamespaced)
				Expect(err).To(BeNil())
				Expect(buffer.String()).To(ContainSubstring("Ignoring PolicyRecommendationScope other"))
			})

			It("should handle error retrieving the PolicyRecommendationScope (e.g., CR not found)", func() {
				// Pass in a scope that doesn’t exist
				err := scopeReconciler.Reconcile(mockNamespaced)
				Expect(err).NotTo(HaveOccurred(), "Reconcile should not fail when CR is missing or retrieval fails")
			})

			Context("When the incoming scope is enabled and the existing reconciler engine is disabled", func() {
				BeforeEach(func() {
					_, err := scopeReconciler.clientSet.ProjectcalicoV3().PolicyRecommendationScopes().Create(ctx, &v3.PolicyRecommendationScope{
						ObjectMeta: metav1.ObjectMeta{
							Name: rectypes.PolicyRecommendationScopeName,
						},
						Spec: v3.PolicyRecommendationScopeSpec{
							NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
								RecStatus: v3.PolicyRecommendationScopeEnabled,
							},
						},
					}, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())
				})

				It("should start the controller, and transition the engine status from 'Disabled' to 'Enabled'", func() {
					Expect(scopeReconciler.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 1
					}, 10*time.Second).Should(BeTrue())
				})

				It("should handle another update, the engine is enabled and the scope is still enabled", func() {
					Expect(scopeReconciler.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 1
					}, 10*time.Second).Should(BeTrue())

					Expect(scopeReconciler.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 2
					}, 10*time.Second).Should(BeTrue())
				})
			})

			Context("When the incoming scope is disabled and the existing reconciler engine is disabled", func() {
				BeforeEach(func() {
					_, err := scopeReconciler.clientSet.ProjectcalicoV3().PolicyRecommendationScopes().Create(ctx, &v3.PolicyRecommendationScope{
						ObjectMeta: metav1.ObjectMeta{
							Name: rectypes.PolicyRecommendationScopeName,
						},
						Spec: v3.PolicyRecommendationScopeSpec{
							NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
								RecStatus: v3.PolicyRecommendationScopeDisabled,
							},
						},
					}, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())
				})

				It("should not render the controller and the engine", func() {
					Expect(scopeReconciler.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeDisabled))

					Expect(scopeReconciler.ctrl).To(BeNil())
					Expect(scopeReconciler.engine).To(BeNil())
				})
			})

			Context("When the incoming scope is disabled and the existing reconciler engine is enabled", func() {
				BeforeEach(func() {
					_, err := scopeReconciler.clientSet.ProjectcalicoV3().PolicyRecommendationScopes().Create(ctx, &v3.PolicyRecommendationScope{
						ObjectMeta: metav1.ObjectMeta{
							Name: rectypes.PolicyRecommendationScopeName,
						},
						Spec: v3.PolicyRecommendationScopeSpec{
							NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
								RecStatus: v3.PolicyRecommendationScopeEnabled,
							},
						},
					}, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())

					err = scopeReconciler.Reconcile(mockNamespaced)
					Expect(err).To(BeNil())

					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))

					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 1
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())

					_, err = scopeReconciler.clientSet.ProjectcalicoV3().PolicyRecommendationScopes().Update(ctx, &v3.PolicyRecommendationScope{
						ObjectMeta: metav1.ObjectMeta{
							Name: rectypes.PolicyRecommendationScopeName,
						},
						Spec: v3.PolicyRecommendationScopeSpec{
							NamespaceSpec: v3.PolicyRecommendationScopeNamespaceSpec{
								RecStatus: v3.PolicyRecommendationScopeDisabled,
							},
						},
					}, metav1.UpdateOptions{})
					Expect(err).NotTo(HaveOccurred())

					Expect(scopeReconciler.stopChan).NotTo(BeClosed())
				})

				It("update the enabled status", func() {
					Expect(scopeReconciler.Reconcile(mockNamespaced)).NotTo(HaveOccurred())
					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeDisabled))
					Expect(scopeReconciler.stopChan).To(BeClosed())

					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeFalse())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeFalse())
				})

				It("should keep the status as disabled when the disabled scope is reconciled multiple times", func() {
					Expect(scopeReconciler.Reconcile(mockNamespaced)).NotTo(HaveOccurred())
					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeDisabled))
					Expect(scopeReconciler.stopChan).To(BeClosed())

					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeFalse())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeFalse())

					Expect(scopeReconciler.Reconcile(mockNamespaced)).NotTo(HaveOccurred())
					Expect(scopeReconciler.enabled).To(Equal(v3.PolicyRecommendationScopeDisabled))
					Expect(scopeReconciler.stopChan).To(BeClosed())

					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeFalse())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeFalse())
				})
			})
		})

		Context("When Reconcile is called with a Tier", func() {
			var (
				tr *tierReconciler
			)

			BeforeEach(func() {
				mockNamespaced.Name = rectypes.PolicyRecommendationTierName
				mockNamespaced.Namespace = v3.AllNamespaces

				tr = &tierReconciler{
					reconcilerBase: &reconcilerBase{
						ctx:       ctx,
						clientSet: mockClientSet,
						enabled:   v3.PolicyRecommendationScopeDisabled,
						mutex:     sync.Mutex{},
						stopChan:  make(chan struct{}),
						clog:      logEntry,
						ctrlFactory: func(scope *v3.PolicyRecommendationScope) (controller.Controller, recengine.RecommendationEngine, error) {
							return mockCtrl, mockEngine, nil
						},
					},
				}
			})

			It("should gracefully ignore keys that don't match the target key", func() {
				mockNamespaced.Name = "other"
				err := tr.Reconcile(mockNamespaced)
				Expect(err).To(BeNil())
				Expect(buffer.String()).To(ContainSubstring("Ignoring Tier other"))
			})

			It("should handle error retrieving the Tier (e.g., Tier not found)", func() {
				// Pass in a tier that doesn’t exist
				err := tr.Reconcile(mockNamespaced)
				Expect(err).NotTo(HaveOccurred(), "Reconcile should not fail when Tier is missing or retrieval fails")
			})

			Context("When the incoming config is enabled and the existing reconciler engine hasn't been enabled yet", func() {
				BeforeEach(func() {
					_, err := tr.clientSet.ProjectcalicoV3().Tiers().Create(ctx, &v3.Tier{
						ObjectMeta: metav1.ObjectMeta{
							Name: rectypes.PolicyRecommendationTierName,
						},
					}, metav1.CreateOptions{})
					Expect(err).NotTo(HaveOccurred())
					Expect(tr.enabled).To(Equal(v3.PolicyRecommendationScopeDisabled))
				})

				It("should start the controller, and transition the engine status from 'Disabled' to 'Enabled'", func() {
					Expect(tr.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(tr.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 1
					}, 10*time.Second).Should(BeTrue())
				})

				It("should handle another update, the engine is enabled and the scope is still enabled", func() {
					Expect(tr.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(tr.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 1
					}, 10*time.Second).Should(BeTrue())

					Expect(tr.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(tr.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 2
					}, 10*time.Second).Should(BeTrue())
				})

				It("should handle another delete, the engine is enabled and the scope is still enabled", func() {
					Expect(tr.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(tr.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 1
					}, 10*time.Second).Should(BeTrue())

					Expect(tr.clientSet.ProjectcalicoV3().Tiers().Delete(ctx, rectypes.PolicyRecommendationTierName, metav1.DeleteOptions{})).NotTo(HaveOccurred())
					Expect(tr.Reconcile(mockNamespaced)).NotTo(HaveOccurred())

					Expect(tr.enabled).To(Equal(v3.PolicyRecommendationScopeEnabled))
					Eventually(func() bool {
						return mockCtrl.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.running
					}, 10*time.Second).Should(BeTrue())
					Eventually(func() bool {
						return mockEngine.scopeUpdatedCount == 1
					}, 10*time.Second).Should(BeTrue())
				})
			})
		})
	})
})

type mockRecommendationController struct {
	running bool
	engine  recengine.RecommendationEngine
}

func (m *mockRecommendationController) Run(stopCh chan struct{}) {
	m.running = true
	go m.engine.Run(stopCh)
	<-stopCh
	m.running = false
}

func newMockRecommendationController(engine recengine.RecommendationEngine) *mockRecommendationController {
	return &mockRecommendationController{
		engine: engine,
	}
}

type mockRecommendationEngine struct {
	running           bool
	scopeUpdatedCount int
	updateScopeChan   chan struct{}
}

func newMockRecommendationEngine() *mockRecommendationEngine {
	return &mockRecommendationEngine{
		updateScopeChan: make(chan struct{}),
	}
}

func (m *mockRecommendationEngine) Run(stopCh chan struct{}) {
	m.running = true
	for {
		select {
		case <-stopCh:
			m.running = false
			return
		case <-m.updateScopeChan:
			m.scopeUpdatedCount++
		}
	}
}

func (m *mockRecommendationEngine) AddNamespace(ns string) {}

func (m *mockRecommendationEngine) RemoveNamespace(ns string) {}

func (m *mockRecommendationEngine) GetNamespaces() set.Set[string] {
	return nil
}

func (m *mockRecommendationEngine) GetFilteredNamespaces() set.Set[string] {
	return nil
}

func (m *mockRecommendationEngine) ReceiveScopeUpdate(scope v3.PolicyRecommendationScope) {
	m.updateScopeChan <- struct{}{}
}
