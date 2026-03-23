// Copyright 2019 Tigera Inc. All rights reserved.

package calico

import (
	"sync"

	"k8s.io/apimachinery/pkg/watch"
)

type MockWatch struct {
	C        chan watch.Event
	stopOnce sync.Once
}

func (w *MockWatch) ResultChan() <-chan watch.Event {
	return w.C
}

func (w *MockWatch) Stop() {
	w.stopOnce.Do(func() {
		close(w.C)
	})
}
