// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package managed_cluster_controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ManagedClusterController", func() {
	Context("Run ManagedClusterController", func() {
		var (
			watcher  *mockWatcher
			stopChan chan struct{}
		)

		BeforeEach(func() {
			watcher = newMockWatcher()
			// Create a channel to signal when the controller should stop.
			stopChan = make(chan struct{})
		})

		It("should start and stop the controller", func() {
			// Create a new managedClusterController instance
			controller := &managedClusterController{
				watcher: watcher,
				managedClusters: map[string]*managedClusterCtrlContext{
					"managed-cluster-1": {
						stopChan: make(chan struct{}),
					},
					"managed-cluster-2": {
						stopChan: make(chan struct{}),
					},
				},
			}

			// Verify that the controller has started.
			go func() {
				// Eventually, the controller will set the watcher to "Running".
				Eventually(func() chan struct{} {
					if watcher.event == "Running" {
						// Signal that the controller has started.
						close(stopChan)
					}
					return stopChan
				}, 10*time.Second).Should(BeClosed())
			}()

			go func() {
				// Start the controller.
				Eventually(func() chan struct{} {
					if watcher.event == "Not Running" && len(controller.managedClusters) == 2 {
						controller.Run(stopChan)
					}
					return stopChan
				}, 10*time.Second).ShouldNot(BeClosed())
			}()

			// Wait for the controller to stop.
			<-stopChan

			// Verify that the controller has deleted the managed clusters.
			Eventually(func() bool {
				return len(controller.managedClusters) == 0
			}, 10*time.Second).Should(BeTrue())
		})
	})
})

type mockWatcher struct {
	event string
}

func (w *mockWatcher) Run(stopChan chan struct{}) {
	w.event = "Running"

	<-stopChan

	w.event = "Not Running"
}

func newMockWatcher() *mockWatcher {
	return &mockWatcher{
		event: "Not Running",
	}
}
