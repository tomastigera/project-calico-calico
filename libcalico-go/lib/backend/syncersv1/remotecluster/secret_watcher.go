// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
//
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

// This file was originally copied from confd-private:pkg/backends/calico/secret_watcher.go
package remotecluster

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type secretWatchData struct {
	// The channel that we should write to when we no longer want this watch.
	stopCh chan struct{}

	// Stale marker.
	stale bool

	// Secret value.
	secret *v1.Secret

	// Error from the original Get request.
	err error
}

type secretKey struct {
	namespace string
	name      string
}

type SecretUpdateReceiver interface {
	OnSecretUpdated(namespace, name string)
}

type secretWatcher struct {
	secretReceiver SecretUpdateReceiver
	mutex          sync.Mutex
	watches        map[secretKey]*secretWatchData
	backend        SecretWatcherBackend
}

type SecretWatcherBackend interface {
	Watch(namespace, name string, handler cache.ResourceEventHandler, stopChan <-chan struct{})
	Get(namespace, name string) (*v1.Secret, error)
}

func NewSecretWatcher(sur SecretUpdateReceiver, k8sClient *kubernetes.Clientset) *secretWatcher {
	if k8sClient == nil {
		log.Infof("No kubernetes client available, secrets will not be available for RemoteClusterConfiguration")
		return nil
	}
	backend := &secretWatcherBackend{
		k8sClientset: k8sClient,
	}
	return NewSecretWatcherWithBackend(sur, backend)
}

func NewSecretWatcherWithBackend(sur SecretUpdateReceiver, backend SecretWatcherBackend) *secretWatcher {
	return &secretWatcher{
		secretReceiver: sur,
		watches:        make(map[secretKey]*secretWatchData),
		backend:        backend,
	}
}

func (sw *secretWatcher) MarkStale() {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	for _, watchData := range sw.watches {
		watchData.stale = true
	}
}

func (sw *secretWatcher) ensureWatchingSecret(sk secretKey) {
	if _, ok := sw.watches[sk]; ok {
		log.Debugf("Already watching secret '%v' (namespace %v)", sk.name, sk.namespace)
	} else {
		log.Debugf("Start a watch for secret '%v' (namespace %v)", sk.name, sk.namespace)
		// We're not watching this secret yet, so start a watch for it.
		sw.watches[sk] = &secretWatchData{stopCh: make(chan struct{})}
		sw.backend.Watch(sk.namespace, sk.name, sw, sw.watches[sk].stopCh)
		log.Debugf("Controller for secret '%v' (namespace %v) is now running", sk.name, sk.namespace)
	}
}

// ensureSecret is invoked when first querying a secret (or re-querying after initial failure). It updates the
// existing entry with the current secret, obtained using Get.
func (sw *secretWatcher) ensureSecret(sk secretKey) {
	secret, err := sw.backend.Get(sk.namespace, sk.name)

	if err != nil {
		if !kerrors.IsNotFound(err) {
			// Store this error. If the next call to GetSecretData sees this error, it'll trigger it to recall ensureSecret.
			// The error is cleared after a successful Get or after a successful update from the informer.
			sw.watches[sk].err = err
			sw.watches[sk].secret = nil
		} else {
			// Secret is not found, this is not an error condition, nil out secret and error.
			sw.watches[sk].err = nil
			sw.watches[sk].secret = nil
		}
	} else {
		// No error - store the secret.
		sw.watches[sk].err = nil
		sw.watches[sk].secret = secret
	}
}

func (sw *secretWatcher) GetSecretData(namespace, name string) (map[string][]byte, error) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	log.Debugf("Get secret in namespace '%v' for name '%v'", namespace, name)

	sk := secretKey{namespace, name}

	// If this is the first time we've seen this secret then ensure we are watching it.
	if _, ok := sw.watches[sk]; !ok {
		// Ensure that we're watching this secret.
		sw.ensureWatchingSecret(sk)

		// Ensure the secret value is initialized.
		sw.ensureSecret(sk)
	} else if sw.watches[sk].err != nil {
		// Previous attempt to get the secret resulted in an error. Try again.
		sw.ensureSecret(sk)
	}

	// Mark it as still in use.
	sw.watches[sk].stale = false

	// Return the secret data.  If no secret return the error (if there is one) - no error and no secret indicates the
	// secret did not exist when queried.
	if secret := sw.watches[sk].secret; secret == nil {
		return nil, sw.watches[sk].err
	} else {
		return secret.Data, nil
	}
}

func (sw *secretWatcher) IgnoreSecret(namespace, name string) {
	sk := secretKey{namespace, name}
	sw.deleteSecretWatcher(sk)
}

func (sw *secretWatcher) SweepStale() {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	for sk, watchData := range sw.watches {
		if watchData.stale {
			close(watchData.stopCh)
			delete(sw.watches, sk)
		}
	}
}

func (sw *secretWatcher) OnAdd(obj any, isInInitialList bool) {
	log.Debug("Secret added")
	s := obj.(*v1.Secret)
	sw.updateSecret(s)
	sw.secretReceiver.OnSecretUpdated(s.Namespace, s.Name)
}

func (sw *secretWatcher) OnUpdate(oldObj, newObj any) {
	log.Debug("Secret updated")
	s := newObj.(*v1.Secret)
	sw.updateSecret(s)
	sw.secretReceiver.OnSecretUpdated(s.Namespace, s.Name)
}

func (sw *secretWatcher) OnDelete(obj any) {
	log.Debug("Secret deleted")
	s := obj.(*v1.Secret)
	sk := secretKey{s.Namespace, s.Name}
	sw.deleteSecret(sk)
	sw.secretReceiver.OnSecretUpdated(s.Namespace, s.Name)
}

func (sw *secretWatcher) updateSecret(secret *v1.Secret) {
	sk := secretKey{secret.Namespace, secret.Name}
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	if _, ok := sw.watches[sk]; ok {
		sw.watches[sk].secret = secret
		sw.watches[sk].err = nil
	}
}

func (sw *secretWatcher) deleteSecret(sk secretKey) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	if _, ok := sw.watches[sk]; ok {
		sw.watches[sk].secret = nil
		sw.watches[sk].err = nil
	}
}

func (sw *secretWatcher) deleteSecretWatcher(sk secretKey) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	if _, ok := sw.watches[sk]; ok {
		if sw.watches[sk].stopCh != nil {
			close(sw.watches[sk].stopCh)
			sw.watches[sk].stopCh = nil
		}
		delete(sw.watches, sk)
	}
}

// secretWatcherBackend implements the SecretWatcherBackend interface.
type secretWatcherBackend struct {
	k8sClientset *kubernetes.Clientset
}

func (s *secretWatcherBackend) Watch(namespace, name string, handler cache.ResourceEventHandler, stopCh <-chan struct{}) {
	watcher := cache.NewListWatchFromClient(s.k8sClientset.CoreV1().RESTClient(), "secrets", namespace, fields.OneTermEqualSelector("metadata.name", name))
	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: watcher,
		ObjectType:    &v1.Secret{},
		ResyncPeriod:  0,
		Handler:       handler,
	})
	go controller.Run(stopCh)
}

func (s *secretWatcherBackend) Get(namespace, name string) (*v1.Secret, error) {
	return s.k8sClientset.CoreV1().Secrets(namespace).Get(context.Background(), name, metav1.GetOptions{})
}
