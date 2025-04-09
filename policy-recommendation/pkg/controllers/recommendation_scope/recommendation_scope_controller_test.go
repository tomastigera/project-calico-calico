// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

package recommendation_scope_controller

import (
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("PolicyRecommendationScopeController", func() {
	var (
		scopeWatcher       *mockWatcher
		tierWatcher        *mockWatcher
		controller         *recommendationScopeController
		stopScopeChan      chan struct{}
		stopTierChan       chan struct{}
		logEntry           *log.Entry
		stopControllerChan chan struct{}
	)

	BeforeEach(func() {
		// Create two mock watchers to simulate scope and tier watchers.
		scopeWatcher = newMockWatcher()
		tierWatcher = newMockWatcher()

		// Channels used to stop watchers.
		stopScopeChan = make(chan struct{})
		stopTierChan = make(chan struct{})

		logger := log.New()
		logEntry = logger.WithField("PolicyRecommendationScope", "controller-tests")

		stopControllerChan = make(chan struct{})
	})

	AfterEach(func() {
		close(stopControllerChan)
	})

	Context("Watching the Scope", func() {
		BeforeEach(func() {
			controller = &recommendationScopeController{
				recommendationScopeWatcher: scopeWatcher,
				stopScopeWatcherChan:       stopScopeChan,
				scopeReconciler: &recommendationScopeReconciler{
					reconcilerBase: &reconcilerBase{
						mutex: sync.Mutex{},
					},
				},
				clog: logEntry,
			}
		})

		It("should eventually stop scope watcher when the controller receives a stop signal", func() {
			// Start the controller in a separate goroutine.
			go controller.Run(stopControllerChan)

			// Confirm scope watcher has started.
			Eventually(func() string { return scopeWatcher.event }, 3*time.Second).Should(Equal("Running"))

			// Now send a stop signal to the controller.
			stopControllerChan <- struct{}{}

			// Scope watcher should eventually shut down after receiving the stop signal.
			Eventually(func() string { return scopeWatcher.event }, 3*time.Second).Should(Equal("Not Running"))
		})
	})

	Context("Watching the Tier", func() {
		BeforeEach(func() {
			controller = &recommendationScopeController{
				tierWatcher:         tierWatcher,
				stopTierWatcherChan: stopTierChan,
				tierReconciler: &tierReconciler{
					reconcilerBase: &reconcilerBase{
						mutex: sync.Mutex{},
					},
				},
				clog: logEntry,
			}
		})

		It("should eventually stop tier watcher when the controller receives a stop signal", func() {
			// Start the controller in a separate goroutine.
			go controller.Run(stopControllerChan)

			// Confirm tier watcher has started.
			Eventually(func() string { return tierWatcher.event }, 3*time.Second).Should(Equal("Running"))

			// Now send a stop signal to the controller.
			stopControllerChan <- struct{}{}

			// Tier watcher should eventually shut down after receiving the stop signal.
			Eventually(func() string { return tierWatcher.event }, 3*time.Second).Should(Equal("Not Running"))
		})
	})
})

type mockWatcher struct {
	event string
}

func (w *mockWatcher) Run(stopChan chan struct{}) {
	w.event = "Running"

	// Wait for the stop signal.
	<-stopChan

	w.event = "Not Running"
}

func newMockWatcher() *mockWatcher {
	return &mockWatcher{
		event: "Not Running",
	}
}
