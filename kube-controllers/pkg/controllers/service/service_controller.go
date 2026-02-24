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

package service

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// serviceController implements the Controller interface for managing Kubernetes services
// and endpoints, syncing them to the Calico datastore as NetworkSet.
type serviceController struct {
	svcInformer, epInformer cache.Controller
	svcIndexer, epIndexer   cache.Store
	calicoClient            client.Interface
	ctx                     context.Context
	serviceConverter        converter.Converter
	endpointConverter       converter.Converter
	resourceCache           rcache.ResourceCache
	sync.Mutex
	cfg config.GenericControllerConfig
}

// NewServiceController returns a controller which manages Service objects.
func NewServiceController(ctx context.Context, clientset *kubernetes.Clientset, c client.Interface, cfg config.GenericControllerConfig) controller.Controller {
	sc := &serviceController{
		calicoClient: c,
		ctx:          ctx,
		cfg:          cfg,
	}

	// set up service informer
	svcWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "services", "", fields.Everything())
	svcHandler := cache.ResourceEventHandlerFuncs{AddFunc: sc.onSvcAdd, UpdateFunc: sc.onSvcUpdate, DeleteFunc: sc.onSvcDelete}
	sc.svcIndexer, sc.svcInformer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: svcWatcher,
		ObjectType:    &v1.Service{},
		ResyncPeriod:  0,
		Handler:       svcHandler,
		Indexers:      cache.Indexers{},
	})

	// set up endpoints informer
	epWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "endpoints", "", fields.Everything())
	epHandler := cache.ResourceEventHandlerFuncs{AddFunc: sc.onEndpointsAdd, UpdateFunc: sc.onEndpointsUpdate, DeleteFunc: sc.onEPDelete}
	sc.epIndexer, sc.epInformer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: epWatcher,
		ObjectType:    &v1.Endpoints{}, //nolint:staticcheck
		ResyncPeriod:  0,
		Handler:       epHandler,
		Indexers:      cache.Indexers{},
	})

	sc.serviceConverter = converter.NewServiceConverter()
	sc.endpointConverter = converter.NewEndpointConverter()

	// GetKey returns the 'namespace/name' for the given Calico NetworkSet as its key.
	getKey := func(obj any) string {
		networkset := obj.(api.NetworkSet)
		return fmt.Sprintf("%s/%s", networkset.Namespace, networkset.Name)
	}

	// Function returns map of networksetName:networkset stored by networkset controller
	// in datastore.
	listFunc := func() (map[string]any, error) {
		// Get all policies from datastore
		calicoPolicies, err := c.NetworkSets().List(ctx, options.ListOptions{})
		if err != nil {
			return nil, err
		}

		// Filter in only objects that are written by networkset controller.
		m := make(map[string]any)
		for _, networkset := range calicoPolicies.Items {
			if strings.HasPrefix(networkset.Name, converter.NetworkSetNamePrefix) {
				// Update the networkset's ObjectMeta/Spec so that it simply contains needed fields.
				networkset.ObjectMeta = metav1.ObjectMeta{Name: networkset.Name, Namespace: networkset.Namespace, Annotations: networkset.Annotations, Labels: networkset.Labels}
				networkset.Spec = api.NetworkSetSpec{Nets: networkset.Spec.Nets}
				k := getKey(networkset)
				m[k] = networkset
			}
		}

		log.Debugf("Found %d policies in Calico datastore:", len(m))
		return m, nil
	}

	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeFor[api.NetworkSet](),
	}
	sc.resourceCache = rcache.NewResourceCache(cacheArgs)

	return sc
}

// getServiceKey returns the key corresponding to service
func (c *serviceController) getServiceKey(svc *v1.Service) string {
	serviceKey, err := cache.MetaNamespaceKeyFunc(svc)
	if err != nil {
		log.WithField("svc", svc.Name).WithError(err).Warn("error on retrieving key for service, passing")
		return ""
	}
	return serviceKey
}

// getEndpointKey returns the key corresponding to service
func (c *serviceController) getEndpointKey(ep *v1.Endpoints) string { //nolint:staticcheck
	serviceKey, err := cache.MetaNamespaceKeyFunc(ep)
	if err != nil {
		log.WithField("ep", ep.Name).WithError(err).Warn("error on retrieving key for endpoints, passing")
		return ""
	}
	return serviceKey
}

// getServiceForEndpoints retrieves the corresponding svc for the given ep
func (c *serviceController) getServiceForEndpoints(endpointKey string) *v1.Service {
	// get svc
	svcIface, exists, err := c.svcIndexer.GetByKey(endpointKey)
	if err != nil {
		log.WithField("key", endpointKey).WithError(err).Warn("error on retrieving service for key, passing")
		return nil
	} else if !exists {
		log.WithField("key", endpointKey).Debug("service for key not found, passing")
		return nil
	}
	return svcIface.(*v1.Service)
}

// getEndpointsForService retrieves the corresponding ep for the given svc
func (c *serviceController) getEndpointsForService(serviceKey string) *v1.Endpoints { //nolint:staticcheck
	// get ep
	epIface, exists, err := c.epIndexer.GetByKey(serviceKey)
	if err != nil {
		log.WithField("key", serviceKey).WithError(err).Warn("error on retrieving endpoint for key, passing")
		return nil
	} else if !exists {
		log.WithField("key", serviceKey).Debug("endpoint for service not found, passing")
		return nil
	}
	return epIface.(*v1.Endpoints) //nolint:staticcheck
}

// shouldCreateNetworkSet return false if networkset corresponding to service/endpoint pair should not be created. True otherwise.
// If service should be created, it also returns the NetworkSet from service to networkset conversion and the NetworkSet from
// endpoints to networkset conversion
func (c *serviceController) shouldCreateNetworkSet(svc *v1.Service, ep *v1.Endpoints) (bool, *api.NetworkSet, *api.NetworkSet) { //nolint:staticcheck
	// Both must be not present for a networkset to be eventually created.
	if (svc != nil && ep == nil) || (ep != nil && svc == nil) {
		return false, nil, nil
	}

	// Convert service to networkset
	fromService, err := c.serviceConverter.Convert(svc)
	if err != nil {
		return false, nil, nil
	}

	// Convert endpoint to networkset
	fromEndpoints, err := c.endpointConverter.Convert(ep)
	if err != nil {
		return false, nil, nil
	}

	nsFromService := fromService.(api.NetworkSet)
	nsFromEndpoints := fromEndpoints.(api.NetworkSet)

	return true, &nsFromService, &nsFromEndpoints
}

// convertToNetworkSet create the NetworkSet merging content from service and endpoints
func (c *serviceController) convertToNetworkSet(nsFromSvc, nsFromEp *api.NetworkSet) *api.NetworkSet {
	networkSet := api.NewNetworkSet()

	if nsFromSvc == nil && nsFromEp == nil {
		log.Error("both service and endpoint networkset cannot be nil, passing...")
		return networkSet
	}

	networkSet.ObjectMeta = metav1.ObjectMeta{
		Name:      nsFromSvc.Name,
		Namespace: nsFromSvc.Namespace,
	}

	if len(nsFromSvc.Labels) > 0 {
		networkSet.Labels = make(map[string]string)
		maps.Copy(networkSet.Labels, nsFromSvc.Labels)
	}

	if len(nsFromSvc.Annotations) > 0 {
		networkSet.Annotations = make(map[string]string)
		maps.Copy(networkSet.Annotations, nsFromSvc.Annotations)
	}

	if len(nsFromEp.Spec.Nets) > 0 {
		networkSet.Spec.Nets = make([]string, len(nsFromEp.Spec.Nets))
		copy(networkSet.Spec.Nets, nsFromEp.Spec.Nets)
	}

	return networkSet
}

// setNetworkSetForSvc handles the main logic to check if a specified service or endpoint
// should have corresponding calico networkset created
func (c *serviceController) setNetworkSetForSvc(svc *v1.Service, ep *v1.Endpoints) { //nolint:staticcheck
	// ensure both are not nil
	if svc == nil && ep == nil {
		log.Error("both service and endpoint cannot be nil, passing...")
		return
	}

	// Locking here to avoid scenarios like following one:
	// 1)SvcInformer sends update notification while corresponding Endpoints still exists (which should lead to creation of NetworkSet)
	// 2)EpInformer sends delete notification (which should lead to deletion of NetworkSet)
	// 3)Code triggered by SvcInformer update verifies Endpoints existance before #2 happens
	// 4)Code triggered by EpInformer delete takes the Lock first (which could happen if we don't lock here)
	c.Lock()
	defer c.Unlock()

	var nsKey, serviceKey string
	if svc == nil {
		serviceKey = c.getEndpointKey(ep)
		nsKey = c.endpointConverter.GetKey(ep)
		// ep received but svc nil
		svc = c.getServiceForEndpoints(serviceKey)
	} else if ep == nil {
		serviceKey = c.getServiceKey(svc)
		nsKey = c.serviceConverter.GetKey(svc)
		// svc received but ep nil
		ep = c.getEndpointsForService(serviceKey)
	}

	doCreate, nsFromSvc, nsFromEp := c.shouldCreateNetworkSet(svc, ep)
	if !doCreate {
		c.resourceCache.Delete(nsKey)
	} else {
		// create NetworkSet to be stored, which is a combination of the two
		networkSet := c.convertToNetworkSet(nsFromSvc, nsFromEp)
		c.resourceCache.Set(nsKey, *networkSet)
	}
}

// unsetNetworkSetForSvc removes the NetworkSet created for this service.
func (c *serviceController) unsetNetworkSetForSvc(svc *v1.Service, ep *v1.Endpoints) { //nolint:staticcheck
	// ensure both are not nil
	if svc == nil && ep == nil {
		log.Error("both service and endpoint cannot be nil, passing...")
		return
	}

	c.Lock()
	defer c.Unlock()

	var nsKey string
	if svc == nil {
		nsKey = c.endpointConverter.GetKey(ep)
	} else if ep == nil {
		nsKey = c.serviceConverter.GetKey(svc)
	}

	c.resourceCache.Delete(nsKey)
}

// updateDatastore syncs the given update to the Calico datastore.
func (c *serviceController) updateDatastore(key string, ns *api.NetworkSet) error {
	clog := log.WithField("key", key)

	clog.Infof("Create/Update NetworkSet in Calico datastore")

	// Lookup to see if this object already exists in the datastore.
	nsFromDatastore, err := c.calicoClient.NetworkSets().Get(c.ctx, ns.Namespace, ns.Name, options.GetOptions{})
	if err != nil {
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			clog.WithError(err).Warning("Failed to get networkset from datastore")
			return err
		}

		// Doesn't exist - create it.
		_, err := c.calicoClient.NetworkSets().Create(c.ctx, ns, options.SetOptions{})
		if err != nil {
			clog.WithError(err).Warning("Failed to create networkset")
			return err
		}

		clog.Infof("Successfully created networkset")
		return nil
	}

	// The networkset already exists, update it and write it back to the datastore.
	nsFromDatastore.Spec = ns.Spec
	nsFromDatastore.Labels = ns.Labels
	nsFromDatastore.Annotations = ns.Annotations
	clog.Infof("Update NetworkSet in Calico datastore with resource version %s", ns.ResourceVersion)
	_, err = c.calicoClient.NetworkSets().Update(c.ctx, nsFromDatastore, options.SetOptions{})
	if err != nil {
		clog.WithError(err).Warning("Failed to update network set")
		return err
	}

	clog.Infof("Successfully updated network set")

	return nil
}

// deleteFromDatastore syncs the given update to the Calico datastore.
func (c *serviceController) deleteFromDatastore(key string) error {
	clog := log.WithField("key", key)

	// The object no longer exists - delete from the datastore.
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		clog.WithError(err).Warning("Failed to get namespace/name from key")
		return err
	}

	_, err = c.calicoClient.NetworkSets().Delete(c.ctx, namespace, name, options.DeleteOptions{})
	if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
		// We hit an error other than "does not exist".
		return err
	}

	return nil
}

// Run starts the controller.
func (c *serviceController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Start the Kubernetes informer, which will start syncing with the Kubernetes API.
	log.Info("Starting Service controller")
	go c.svcInformer.Run(stopCh)
	go c.epInformer.Run(stopCh)

	// Wait until we are in sync with the Kubernetes API before starting the
	// resource cache.
	log.Debug("Waiting to sync with Kubernetes API (Service)")
	for !c.svcInformer.HasSynced() || !c.epInformer.HasSynced() {
		time.Sleep(100 * time.Millisecond)
	}
	log.Debug("Finished syncing with Kubernetes API (Service)")

	// Start the resource cache - this will trigger the queueing of any keys
	// that are out of sync onto the resource cache event queue.
	c.resourceCache.Run(c.cfg.ReconcilerPeriod.String())

	// Start a number of worker threads to read from the queue. Each worker
	// will pull keys off the resource cache event queue and sync them to the
	// Calico datastore.
	for i := 0; i < c.cfg.NumberOfWorkers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}
	log.Info("Service controller is now running")

	<-stopCh

	log.Info("Stopping Service controller")
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *serviceController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *serviceController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.resourceCache.GetQueue()
	k, quit := workqueue.Get()
	if quit {
		return false
	}

	key := k.(string)

	clog := log.WithField("key", key)
	// Check if it exists in the controller's cache.
	obj, exists := c.resourceCache.Get(key)
	if !exists {
		// The object no longer exists - delete from the datastore.
		clog.Debug("Deleting NetworkSet from Calico datastore")
		if err := c.deleteFromDatastore(key); err != nil {
			c.handleErr(err, key)
		} else {
			clog.Debug("Successfully deleted NetworkSet")
		}
	} else {
		// The object exists - update the datastore to reflect.
		clog.Debug("Create/Update NetworkSet in Calico datastore")
		p := obj.(api.NetworkSet)
		if err := c.updateDatastore(key, &p); err != nil {
			c.handleErr(err, key)
		} else {
			clog.Debug("Successfully updated NetworkSet")
		}
	}

	// Indicate that we're done processing this key, allowing for safe parallel processing such that
	// two objects with the same key are never processed in parallel.
	workqueue.Done(key)
	return true
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *serviceController) handleErr(err error, key string) {
	workqueue := c.resourceCache.GetQueue()
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < 5 {
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		log.WithError(err).Errorf("Error syncing NetworkSet %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping NetworkSet %q out of the queue: %v", key, err)
}

// onSvcAdd is called when a k8s service is created
func (c *serviceController) onSvcAdd(obj any) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Warn("failed to assert type to service, passing")
		return
	}

	c.setNetworkSetForSvc(svc, nil)
}

// onSvcUpdate is called when a k8s service is updated
func (c *serviceController) onSvcUpdate(_, obj any) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Warn("onSvcUpdate: failed to assert type to service, passing")
		return
	}

	c.setNetworkSetForSvc(svc, nil)
}

// onSvcUpdate is called when a k8s service is deleted
func (c *serviceController) onSvcDelete(obj any) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		log.Warn("failed to assert type to service, passing")
		return
	}

	c.unsetNetworkSetForSvc(svc, nil)
}

// onEndpointsAdd is called when a k8s endpoint is created
func (c *serviceController) onEndpointsAdd(obj any) {
	ep, ok := obj.(*v1.Endpoints) //nolint:staticcheck
	if !ok {
		log.Warn("failed to assert type to endpoints, passing")
		return
	}

	c.setNetworkSetForSvc(nil, ep)
}

// onEndpointsUpdates is called when a k8s endpoint is updated
func (c *serviceController) onEndpointsUpdate(oldObj, currentObj any) {
	current, ok := currentObj.(*v1.Endpoints) //nolint:staticcheck
	if !ok {
		log.Warn("failed to assert type to endpoints, passing")
		return
	}
	old, ok := oldObj.(*v1.Endpoints) //nolint:staticcheck
	if !ok {
		log.Warn("failed to assert type to endpoints, passing")
		return
	}

	// Create the NetworkSet: only fields used are name, namespace and subsets.
	// If any other field is used when converting from Endpoints to NetworkSet, change also k8sEndpointToNetworkSet
	// This check is in place cause we used to receive tons of updates because renewTime changed. Subsets is the only
	// field whose changes we are interested in. Discard any other update
	if !reflect.DeepEqual(current.Subsets, old.Subsets) {
		c.setNetworkSetForSvc(nil, current)
	}
}

// onEPDelete is called when a k8s endpoint is deleted
func (c *serviceController) onEPDelete(obj any) {
	ep, ok := obj.(*v1.Endpoints) //nolint:staticcheck
	if !ok {
		log.Warn("failed to assert type to endpoints, passing")
		return
	}

	c.unsetNetworkSetForSvc(nil, ep)
}
