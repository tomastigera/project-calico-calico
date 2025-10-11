// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package cache

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
	k8scache "k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/es-gateway/pkg/clients/kubernetes"
)

const (
	retryWatchInterval = time.Second * 3

	// All ES gateway credentials should be K8s secrets located within the below namespace.
	ElasticsearchNamespace = "tigera-elasticsearch"

	// All ES gateway credentials should be K8s secrets tagged with the following label (key/value).
	// This allows us to filter down to only the secrets we're interested in, in the corresponding
	// namespace.
	ESGatewaySelectorLabel      = "esgateway.tigera.io/secrets"
	ESGatewaySelectorLabelValue = "credentials"
)

type secretCache struct {
	k8sClient kubernetes.Client
	cache     k8scache.ThreadSafeStore
}

// SecretsCache is an interface that exposes the required operations for managing a cache of secrets.
type SecretsCache interface {
	GetSecret(string) (*v1.Secret, error)
}

// NewSecretCache creates a new secret cache. It attempts to load all the secrets from the given namespace
// as part of initialization.
func NewSecretCache(ctx context.Context, k8sClient kubernetes.Client) (SecretsCache, error) {
	secretStore := k8scache.NewThreadSafeStore(k8scache.Indexers{}, k8scache.Indices{})
	sanityChecklist := []string{}

	// Initialize by retrieving a listing of the secrets in the correct namespace, filtered by the relevant label(s).
	labelSelectors := map[string]string{ESGatewaySelectorLabel: ESGatewaySelectorLabelValue}
	list, err := k8sClient.GetSecretList(ctx, ElasticsearchNamespace, labelSelectors)
	if err != nil {
		return nil, err
	}
	for _, i := range list.Items {
		secretName := i.Name
		sanityChecklist = append(sanityChecklist, secretName)

		// Add secret to the store, using the resource name as the key.
		entry := &v1.Secret{}
		*entry = i // Need to create a separate pointer from i (since i is an iterator)
		secretStore.Add(secretName, entry)
	}

	sc := &secretCache{
		k8sClient: k8sClient,
		cache:     secretStore,
	}

	// Sanity check to ensure we have all secrets loaded
	log.Debugf("Secret cache loaded %+v", sanityChecklist)

	// Keep the secret cache in sync.
	go sc.sync(ctx, ElasticsearchNamespace)

	return sc, nil
}

// GetSecret attempts to retrieve a secret from the secret cache with the given name.
func (sc *secretCache) GetSecret(name string) (*v1.Secret, error) {
	obj, ok := sc.cache.Get(name)
	if !ok {
		return nil, fmt.Errorf("secret %s not found in cache", name)
	}

	secret, ok := obj.(*v1.Secret)
	// This should never happen (logical bug in the code) as we only ever put secrets into the store.
	if !ok {
		return nil, fmt.Errorf("object %s in cache is not a secret", name)
	}

	return secret, nil
}

// sync ensures that the given secret cache is kept in sync with values of the secrets in the datastore.
func (sc *secretCache) sync(ctx context.Context, namespace string) {
	var watcher watch.Interface
	var err error

	// Ensure we filter the watch down to only the releveant secrests we are interested in.
	labelSelectors := map[string]string{ESGatewaySelectorLabel: ESGatewaySelectorLabelValue}

LOOP:
	for {
		// If we did not clean up watcher from previous iteration, do that now.
		if watcher != nil {
			watcher.Stop()
		}

		watcher, err = sc.k8sClient.GetSecretWatcher(ctx, namespace, labelSelectors)
		// If watch failed, just retry the pre-defined interval.
		if err != nil {
			log.WithError(err).Warnf("unable to watch secrets in %s namespace", namespace)
			time.Sleep(retryWatchInterval)
			continue LOOP
		}

		// Begin listening for events from the watcher channel.
		for e := range watcher.ResultChan() {
			secret, ok := e.Object.(*v1.Secret)
			if !ok {
				log.WithError(err).Errorf("unable to process event from watching secrets in %s namespace", namespace)
				time.Sleep(retryWatchInterval)
				continue LOOP
			}
			key := secret.Name

			switch e.Type {
			case watch.Error:
				// Watch error; restart from beginning. Note that k8s watches terminate periodically but these
				// terminate without error - in this case we'll just attempt to watch from the latest snapshot rev.
				log.WithError(err).Errorf("error watching secrets in %s namespace", namespace)
				time.Sleep(retryWatchInterval)
				continue LOOP
			case watch.Added:
				log.Debugf("Adding new secret %s", key)
				sc.cache.Add(key, secret)
			case watch.Modified:
				log.Debugf("Updating existing secret %s", key)
				sc.cache.Update(key, secret)
			case watch.Deleted:
				log.Debugf("Deleteing existing secret %s", key)
				sc.cache.Delete(key)
			}
		}
	}
}
