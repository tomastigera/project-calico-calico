// Copyright (c) 2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package remotecluster_test

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	. "github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/remotecluster"
)

var (
	data1 = map[string][]byte{
		"test": []byte("test1"),
	}
	data2 = map[string][]byte{
		"test": []byte("test2"),
	}
	secret1 = &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "namespace1",
			Name:      "name1",
		},
		Data: data1,
	}
	secret2 = &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "namespace1",
			Name:      "name1",
		},
		Data: data2,
	}
	nn = types.NamespacedName{
		Namespace: "namespace1",
		Name:      "name1",
	}
)

type mockSecretWatcherBackend struct {
	handler cache.ResourceEventHandler
	getVal  *v1.Secret
	getErr  error
	watches []types.NamespacedName
	gets    []types.NamespacedName
	updates []types.NamespacedName
}

func (s *mockSecretWatcherBackend) Watch(namespace, name string, handler cache.ResourceEventHandler, stopCh <-chan struct{}) {
	s.watches = append(s.watches, types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	})
	s.handler = handler
}

func (s *mockSecretWatcherBackend) Get(namespace, name string) (*v1.Secret, error) {
	s.gets = append(s.gets, types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	})
	return s.getVal, s.getErr
}

func (s *mockSecretWatcherBackend) OnSecretUpdated(namespace, name string) {
	s.updates = append(s.updates, types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	})
}

var _ = Describe("Secret watcher tests", func() {

	It("returns nothing if secret does not exist", func() {
		mock := &mockSecretWatcherBackend{
			getErr: kerrors.NewNotFound(schema.GroupResource{Group: "v1", Resource: "Secret"}, "name1"),
		}

		watcher := NewSecretWatcherWithBackend(mock, mock)

		By("invoking GetSecretData when backend responds with not found")
		d, err := watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(HaveLen(0))

		By("invoking GetSecretData again, backend should not be invoked again")
		d, err = watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(BeNil())
		Expect(err).ToNot(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(HaveLen(0))
	})

	It("returns error if get secret returns error", func() {
		mock := &mockSecretWatcherBackend{
			getErr: kerrors.NewForbidden(schema.GroupResource{Group: "v1", Resource: "Secret"}, "name1", errors.New("error")),
		}

		watcher := NewSecretWatcherWithBackend(mock, mock)

		By("invoking GetSecretData when backend responds with error")
		d, err := watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(HaveLen(0))

		By("invoking GetSecretData again, backend should be invoked again")
		d, err = watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn, nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(HaveLen(0))

		By("watcher provides update and invoking GetSecretData again - value should be retureds, no backend requests")
		watcher.OnAdd(secret1, true)
		d, err = watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(Equal(data1))
		Expect(err).ToNot(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn, nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(Equal([]types.NamespacedName{nn}))

		By("watcher provides update and invoking GetSecretData again - new value should be returned, no backend requests")
		watcher.OnAdd(secret2, true)
		d, err = watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(Equal(data2))
		Expect(err).ToNot(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn, nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(Equal([]types.NamespacedName{nn, nn}))
	})

	It("returns secret if it exists", func() {
		mock := &mockSecretWatcherBackend{
			getVal: secret1,
		}

		watcher := NewSecretWatcherWithBackend(mock, mock)

		By("invoking GetSecretData when backend responds with secret")
		d, err := watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(Equal(data1))
		Expect(err).ToNot(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(HaveLen(0))

		By("invoking GetSecretData again, backend should not be invoked again")
		d, err = watcher.GetSecretData("namespace1", "name1")
		Expect(d).To(Equal(data1))
		Expect(err).ToNot(HaveOccurred())
		Expect(mock.gets).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.watches).To(Equal([]types.NamespacedName{nn}))
		Expect(mock.updates).To(HaveLen(0))
	})
})
