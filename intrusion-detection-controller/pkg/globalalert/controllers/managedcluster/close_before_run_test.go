// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package managedcluster

import (
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/globalalert/worker"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/health"
)

// noopWorker implements worker.Worker with no-op methods for testing.
type noopWorker struct{}

var _ worker.Worker = (*noopWorker)(nil)

func (n *noopWorker) AddWatch(cache.ListerWatcher, runtime.Object) health.Pinger { return nil }
func (n *noopWorker) Run(<-chan struct{})                                        {}
func (n *noopWorker) Close()                                                     {}

// TestCloseBeforeRun verifies that Close() does not panic when called
// before Run(), which can happen during shutdown if controllers were
// never started (e.g. no license was ever granted).
func TestCloseBeforeRun(t *testing.T) {
	g := NewGomegaWithT(t)

	m := &managedClusterController{
		worker: &noopWorker{},
	}

	// cancel is nil because Run() was never called.
	// This must not panic.
	g.Expect(func() { m.Close() }).ShouldNot(Panic())
}
