// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package worker_test

import (
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/worker"
)

type MockReconciler struct {
	f func(name types.NamespacedName) error
}

func (m *MockReconciler) Reconcile(name types.NamespacedName) error {
	return m.f(name)
}

type MockWatch struct {
	ch chan watch.Event
}

func (m *MockWatch) ResultChan() <-chan watch.Event {
	return m.ch
}

func (m *MockWatch) Stop() {
}

type MockListerWatcher struct {
	listFunc func() (runtime.Object, error)
	eventCh  chan watch.Event
}

func NewMockListerWatcher(listFunc func() (runtime.Object, error)) *MockListerWatcher {
	return &MockListerWatcher{
		listFunc: listFunc,
		eventCh:  make(chan watch.Event),
	}
}

func (m *MockListerWatcher) List(options metav1.ListOptions) (runtime.Object, error) {
	if m.listFunc != nil {
		return m.listFunc()
	}

	return nil, nil
}

func (m *MockListerWatcher) Watch(options metav1.ListOptions) (watch.Interface, error) {
	return &MockWatch{m.eventCh}, nil
}

// IsWatchListSemanticsUnSupported opts out of WatchList semantics which are
// enabled by default in client-go 1.35 but not supported by this mock.
func (m *MockListerWatcher) IsWatchListSemanticsUnSupported() bool {
	return true
}

func (m *MockListerWatcher) AddEvent(event watch.Event) {
	m.eventCh <- event
}

func (m *MockListerWatcher) Stop() {
	close(m.eventCh)
}

var _ = Describe("worker", func() {
	Context("Runs Reconcile function", func() {
		It("when a new resource is added", func() {
			simpleReconcileRunTest(watch.Added, true, worker.ResourceWatchAdd)
		})
		It("when a resource is updated", func() {
			simpleReconcileRunTest(watch.Modified, true, worker.ResourceWatchUpdate)
		})
		It("when a resource is deleted", func() {
			simpleReconcileRunTest(watch.Deleted, true, worker.ResourceWatchDelete)
		})
	})
	Context("Does not run Reconcile function", func() {
		It("when a new resource is added but the worker doesn't have ResourceWatchAdd set", func() {
			simpleReconcileRunTest(watch.Added, false, worker.ResourceWatchUpdate)
		})
		It("when a resource is updated but the worker doesn't have ResourceWatchUpdate set", func() {
			simpleReconcileRunTest(watch.Modified, false, worker.ResourceWatchDelete)
		})
		It("when a resource is deleted but the worker doesn't have ResourceWatchDelete set", func() {
			simpleReconcileRunTest(watch.Deleted, false, worker.ResourceWatchUpdate)
		})
	})
	Context("Rate limiting", func() {
		It("tests that a key that caused a previous error doesn't get ignored", func() {
			nameChan := make(chan types.NamespacedName, 5)
			defer close(nameChan)
			count := 0
			errorThreshold := 1
			r := &MockReconciler{f: func(name types.NamespacedName) error {
				nameChan <- name

				count++
				if count > errorThreshold {
					return nil
				}

				return errors.New("error")
			}}
			listFunc := func() (runtime.Object, error) { return &corev1.SecretList{}, nil }

			mockLW := NewMockListerWatcher(listFunc)
			defer mockLW.Stop()

			w := worker.New(r)
			w.AddWatch(mockLW, &corev1.Secret{})

			stop := make(chan struct{})
			defer close(stop)

			go w.Run(1, stop)

			mockLW.AddEvent(watch.Event{
				Type: watch.Added,
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "TestNamespace",
					},
				},
			})
			mockLW.AddEvent(watch.Event{
				Type: watch.Added,
				Object: &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "TestNamespace",
					},
				},
			})

			var name types.NamespacedName
			select {
			case name = <-nameChan:
				Expect(name).Should(Equal(types.NamespacedName{
					Name:      "test",
					Namespace: "TestNamespace",
				}))
			case <-time.NewTicker(500 * time.Millisecond).C:
				Fail("timeout waiting for name")
			}
			select {
			case name = <-nameChan:
				Expect(name).Should(Equal(types.NamespacedName{
					Name:      "test",
					Namespace: "TestNamespace",
				}))
			case <-time.NewTicker(500 * time.Millisecond).C:
				Fail("timeout waiting for name")
			}
		})
	})
})

func simpleReconcileRunTest(eventType watch.EventType, reconcileShouldRun bool, resourceWatchOptions ...worker.ResourceWatch) {
	nameChan := make(chan types.NamespacedName)
	defer close(nameChan)

	r := &MockReconciler{f: func(name types.NamespacedName) error {
		nameChan <- name
		return nil
	}}

	var listFunc func() (runtime.Object, error)
	// If the eventType is either Modified or Deleted the resource must already exist for the event to be triggered
	if eventType == watch.Modified || eventType == watch.Deleted {
		listFunc = func() (runtime.Object, error) {
			return &corev1.SecretList{Items: []corev1.Secret{{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "TestName",
					Namespace: "TestNamespace",
				},
			}}}, nil
		}
	} else {
		listFunc = func() (runtime.Object, error) { return &corev1.SecretList{}, nil }
	}

	mockLW := NewMockListerWatcher(listFunc)
	defer mockLW.Stop()

	w := worker.New(r)
	w.AddWatch(mockLW, &corev1.Secret{}, resourceWatchOptions...)

	stop := make(chan struct{})
	defer close(stop)

	go w.Run(1, stop)

	mockLW.AddEvent(watch.Event{
		Type: eventType,
		Object: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "TestName",
				Namespace: "TestNamespace",
			},
		},
	})

	var name types.NamespacedName

	select {
	case name = <-nameChan:
	case <-time.NewTicker(500 * time.Millisecond).C:
	}

	if reconcileShouldRun {
		Expect(name).Should(Equal(types.NamespacedName{Name: "TestName", Namespace: "TestNamespace"}))
	} else {
		Expect(name).Should(Equal(types.NamespacedName{Name: "", Namespace: ""}))
	}
}
