// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
package endpoint

import (
	"context"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/config"
	"github.com/projectcalico/calico/pkg/nonclusterhost"
)

type EndpointController struct {
	dynamicClient  dynamic.Interface
	dynamicFactory dynamicinformer.DynamicSharedInformerFactory

	mu       sync.RWMutex
	endpoint string
}

func NewController(cfg *config.Config) (*EndpointController, error) {
	// initialize kubernetes clients
	dynamicClient, err := dynamic.NewForConfig(cfg.RestConfig)
	if err != nil {
		return nil, err
	}

	return &EndpointController{
		dynamicClient:  dynamicClient,
		dynamicFactory: dynamicinformer.NewDynamicSharedInformerFactory(dynamicClient, 0),

		endpoint: cfg.Endpoint,
	}, nil
}

func (c *EndpointController) Run(stopCh <-chan struct{}) error {
	if c.endpoint == "" {
		logrus.Debug("empty endpoint from environment variable or plugin config. read cluster resource instead")

		if err := c.getAndWatchEndpoint(); err != nil {
			return err
		}
		logrus.Infof("log ingestion endpoint is set to %q", c.Endpoint())

		// Start initializes all requested informers. They are handled in goroutines
		// which run until the stop channel gets closed.
		c.dynamicFactory.Start(stopCh)
		c.dynamicFactory.WaitForCacheSync(stopCh)
		logrus.Debug("dynamic shared informer factory is started")
	}

	logrus.Info("linseed plugin endpoint controller is started")
	return nil
}

func (c *EndpointController) Endpoint() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.endpoint
}

func (c *EndpointController) getAndWatchEndpoint() error {
	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   2,
		Jitter:   0.2,
		Steps:    6,
	}

	// Context timeout must exceed the maximum total backoff duration.
	// With Steps=6, Factor=2, Duration=15s, Jitter=0.2:
	// Worst-case total sleep = 15*(1+2+4+8+16)*1.2 ≈ 9m18s, plus API call latency per step.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	var nch *unstructured.Unstructured
	if err := wait.ExponentialBackoff(backoff, func() (bool, error) {
		var err error
		nch, err = nonclusterhost.GetNonClusterHost(ctx, c.dynamicClient)
		if err != nil {
			// If the context has expired, return a permanent error to stop retrying
			// instead of burning remaining backoff steps on dead calls.
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			logrus.WithError(err).Info("failed to get nonclusterhost resource. will retry...")
			return false, nil
		}
		return true, nil
	}); err != nil {
		return err
	}

	// extract endpoint from the NonClusterHost resource
	endpoint, err := extractEndpoint(nch)
	if err != nil {
		return err
	}

	// watch for NonClusterHost resource changes
	nonClusterHostInformer := c.dynamicFactory.ForResource(nonclusterhost.NonClusterHostGVR).Informer()
	if _, err = nonClusterHostInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: c.updateFunc,
	}); err != nil {
		return err
	}

	// Set the endpoint under the lock since the informer's updateFunc may
	// already be writing to c.endpoint concurrently after cache sync.
	c.mu.Lock()
	c.endpoint = endpoint
	c.mu.Unlock()

	return nil
}

func (c *EndpointController) updateFunc(oldObj, newObj any) {
	logrus.Debug("receive nonclusterhost update event")

	unstructuredObj, ok := newObj.(*unstructured.Unstructured)
	if !ok {
		logrus.Warn("failed to cast new nonclusterhost object. skip update")
		return
	}

	endpoint, err := extractEndpoint(unstructuredObj)
	if err != nil {
		logrus.WithError(err).Warn("failed to extract endpoint from the nonclusterhost object. skip update")
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.endpoint = endpoint
	logrus.Infof("log ingestion endpoint is changed to %q", c.endpoint)
}

func extractEndpoint(unstructuredObj *unstructured.Unstructured) (string, error) {
	validator := func(endpoint string) error {
		_, err := url.ParseRequestURI(endpoint)
		return err
	}

	endpoint, err := nonclusterhost.ExtractFromNonClusterHostSpec(unstructuredObj, "endpoint", validator)
	if err != nil {
		return "", err
	}
	return endpoint, nil
}
