// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.

package federatedservices

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/api/v1/endpoints"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/labelindex"
	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/federationsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/remotecluster"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	FederationAnnotationPrefix          = "federation.tigera.io/"
	FederationServiceSelectorAnnotation = FederationAnnotationPrefix + "serviceSelector"
	LabelClusterName                    = FederationAnnotationPrefix + "remoteClusterName"
)

// backendClientAccessor is an interface to access the backend client from the main v2 client.
type backendClientAccessor interface {
	Backend() bapi.Client
}

// federatedServicesController implements the Controller interface for managing federated service endpoints
// and syncing them to the local Kubernetes datastore.
type federatedServicesController struct {
	cache        rcache.ResourceCache
	calicoClient client.Interface
	ctx          context.Context
	k8sClientset *kubernetes.Clientset

	// Syncers used to monitor services and endpoints locally and on remote clusters.
	syncer   bapi.Syncer
	isInSync bool
	inSync   chan struct{}

	// The serviceLabelHandler handler for matching federated services to the backing services.
	serviceLabelHandler *labelindex.InheritIndex

	// The set of all known services and endpoints keyed off the cluster/key string.
	allServices map[serviceID]*serviceInfo

	// The set of all services whose endpoints need to be recalculated or deleted.
	dirtyServices set.Set[serviceID]

	// Syncer callback decoupler ensures syncer callbacks are serialized. This avoids the need
	// for locking our datastructures.
	decoupler *calc.SyncerCallbacksDecoupler

	cfg config.GenericControllerConfig
}

// serviceInfo contains the details about a single service on a cluster. In particular it contains the various
// relationship maps between a service and the services it is linked to through federation.
type serviceInfo struct {
	// The service and corresponding endpoints.
	service   *v1.Service
	endpoints *v1.Endpoints //nolint:staticcheck

	// The service federation config (or the error parsing the config). If either are non-nil then this is a federated
	// service.  If this service is local to this cluster then the endpoints will be updated by this controller.  If
	// this service is on a remote cluster then the endpoints will not be included in any federated services on this
	// cluster.
	federationConfig    *federatedServiceConfig
	federationConfigErr error

	// The backing services is the set of services that are used to calculate the federated service endpoints.
	backingServices set.Set[serviceID]

	// The set of federated services that this backing service is used by, this is used to determine which federated
	// services need to be recalculated in the event of an endpoint update.
	federatedServices set.Set[serviceID]
}

// serviceID contains the key identifiers for a service (local and remote).
type serviceID struct {
	// The cluster name (matching the name configured on the associated RemoteClusterConfiguration resource).
	// Blank indicates this is a service on the local cluster.
	cluster string

	// The namespace and name of the service.
	namespace string
	name      string
}

// federatedServiceConfig contains the federation information configured through a services annotations.
type federatedServiceConfig struct {
	annotations map[string]string
	selector    *selector.Selector
}

// NewFederatedServicesController returns a controller which manages FederatedServices objects.
func NewFederatedServicesController(ctx context.Context, k8sClientset *kubernetes.Clientset, c client.Interface, cfg config.GenericControllerConfig, restartChan chan<- string) controller.Controller {
	fec := &federatedServicesController{
		calicoClient:  c,
		ctx:           ctx,
		k8sClientset:  k8sClientset,
		inSync:        make(chan struct{}),
		allServices:   make(map[serviceID]*serviceInfo),
		dirtyServices: set.New[serviceID](),
		decoupler:     calc.NewSyncerCallbacksDecoupler(),
		cfg:           cfg,
	}

	// Function returns map of kubernetes services that are owned by the federated services controller.
	listFunc := func() (map[string]any, error) {
		log.Debug("Listing federated endpoints from k8s datastore")
		filteredEndpoint := make(map[string]any)

		// Get all endpoints objects from Kubernetes datastore.
		endpointsList, err := k8sClientset.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}

		for i := range endpointsList.Items {
			endpoints := &endpointsList.Items[i]
			// Only return endpoints with the service selector annotation and sanitize the data for easy comparison.
			if _, ok := endpoints.Annotations[FederationServiceSelectorAnnotation]; ok {
				fec.sanitizeEndpoints(endpoints)
				key := nameNamespaceToCacheKey(endpoints.Namespace, endpoints.Name)
				filteredEndpoint[key] = *endpoints
			}
		}
		log.Debugf("Found %d federated endpoints in Kubernetes datastore", len(filteredEndpoint))
		return filteredEndpoint, nil
	}

	// Create a Cache to store federated Endpoints in.
	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:    listFunc,
		ObjectType:  reflect.TypeFor[v1.Endpoints](), //nolint:staticcheck
		LogTypeDesc: "FederatedEndpoints",
	}

	fec.cache = rcache.NewResourceCache(cacheArgs)
	fec.serviceLabelHandler = labelindex.NewInheritIndex(fec.onServiceMatchStarted, fec.onServiceMatchStopped)
	restartMonitor := remotecluster.NewRemoteClusterRestartMonitor(fec.decoupler, func(msg string) {
		restartChan <- msg
	})
	fec.syncer = federationsyncer.New(
		c.(backendClientAccessor).Backend(),
		k8sClientset,
		restartMonitor,
	)

	return fec
}

// Run starts the controller.
func (c *federatedServicesController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	log.Info("Starting FederatedServices controller")

	// Start the federation processor.
	c.startFederating(stopCh)

	select {
	case <-stopCh:
		log.Info("FederatedServices controller stopping before starting reconciliation")
	default:
		log.Info("Finished syncing with Calico API (FederatedServices)")

		// The startFederating call blocks until the syncer has finished its initial sync. At this point the reconciler
		// cache will have been programmed with the current required set of data.  Start the Kubernetes reconciler
		// cache to fix up any deltas between the required and configured data.
		c.cache.Run(c.cfg.ReconcilerPeriod.String())
		defer c.cache.GetQueue().ShutDown()

		// Start a number of worker threads to read from the queue.
		for i := 0; i < c.cfg.NumberOfWorkers; i++ {
			go c.runWorker()
		}
		log.Info("FederatedServices controller is now running")
	}

	// Block until the controller is shut down. Ideally we should shut down the syncers as part of this shutdown (which
	// is a little tricky). However, since the main routine only shuts down as the result of a panic, there seems very
	// little point in fully tidying up.
	<-stopCh

	log.Info("Stopping FederatedServices controller")
}

func (c *federatedServicesController) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem waits for an event on the output queue from the endpoints resource cache and syncs
// any received keys to the kubernetes datastore.
func (c *federatedServicesController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.cache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync the object to the Calico datastore.
	if err := c.syncToDatastore(key.(string)); err != nil {
		c.handleErr(err, key.(string))
	}

	// Indicate that we're done processing this key, allowing for safe parallel processing such that
	// two objects with the same key are never processed in parallel.
	workqueue.Done(key)
	return true
}

// syncToDatastore syncs the given update to the Kubernetes datastore. The provided key can be used to
// find the corresponding resource within the resource cache. If the resource for the provided key
// exists in the cache, then the value should be written to the datastore. If it does not exist
// in the cache, then it should be deleted from the datastore.
func (c *federatedServicesController) syncToDatastore(key string) error {
	ctx := context.Background()
	clog := log.WithField("key", key)

	// Start by looking up the existing entry if it already exists. Double check that the annotation indicates
	// this resource is owned by the federation controller.
	namespace, name := nameNamespaceFromCacheKey(key)
	currentEP, err := c.k8sClientset.CoreV1().Endpoints(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		clog.WithError(err).Debug("Error querying endpoints")
		if !kerrors.IsNotFound(err) {
			clog.WithError(err).Info("Unexpected error querying endpoints")
			// We hit an error other than "not found".
			return err
		}
		currentEP = nil
	} else if _, ok := currentEP.Annotations[FederationServiceSelectorAnnotation]; !ok {
		clog.WithError(err).Info("No selector annotation, endpoints not owned by controller")
		return nil
	}

	// Check the controllers cache to see whether the resource *should* exist.
	value, exists := c.cache.Get(key)
	clog.Debugf("Reconciliation cache returned: %#v", value)
	clog.Debugf("Current endpoint: %#v", currentEP)

	if !exists {
		// The object does not exist in the cache (and therefore is not required) - delete from the datastore.
		clog.Info("Deleting Endpoints from Kubernetes datastore")
		err := c.k8sClientset.CoreV1().Endpoints(namespace).Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !kerrors.IsNotFound(err) {
			// We hit an error other than "not found".
			return err
		}
		return nil
	}
	// The federated object should exist - update the kubernetes datastore to reflect the latest settings.
	clog.Debug("Create/Update Endpoints in Kubernetes datastore")
	requiredEP := value.(v1.Endpoints) //nolint:staticcheck

	var newEP *v1.Endpoints //nolint:staticcheck
	if currentEP == nil {
		clog.Info("Creating Endpoints in Kubernetes datastore")
		if newEP, err = c.k8sClientset.CoreV1().Endpoints(namespace).Create(ctx, &requiredEP, metav1.CreateOptions{}); err != nil {
			clog.WithError(err).Infof("Error creating Endpoints in Kubernetes datastore: %#v", requiredEP)
			return err
		}
	} else {
		clog.Info("Updating Endpoints in Kubernetes datastore")

		// Update the annotations with those expected. We don't want to delete any existing annotations
		// that may have been added by the operator.
		currentEP.Subsets = requiredEP.Subsets
		maps.Copy(currentEP.Annotations, requiredEP.Annotations)

		if newEP, err = c.k8sClientset.CoreV1().Endpoints(namespace).Update(ctx, currentEP, metav1.UpdateOptions{}); err != nil {
			clog.WithError(err).Infof("Error updating Endpoints in Kubernetes datastore: %#v", currentEP)
			return err
		}
	}

	// Sanity check that the sanitized updated Endpoints resource is what we expect. If it isn't then
	// our sanitizing code is wrong and should be fixed - otherwise we'll end up getting unnecessary
	// churn of the endpoints.
	c.sanitizeEndpoints(newEP)
	if !reflect.DeepEqual(*newEP, requiredEP) {
		clog.Warnf("New and required endpoint configuration are not equal:"+
			"\nCurrent: %#v\nRequired: %#v", newEP, requiredEP)
	}

	return nil
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *federatedServicesController) handleErr(err error, key string) {
	clog := log.WithField("key", key)

	workqueue := c.cache.GetQueue()
	if err == nil {
		// Forget about the AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		clog.Debug("Forgetting key")
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < 5 {
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		clog.WithError(err).Errorf("Error syncing Profile %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping Profile %q out of the queue: %v", key, err)
}

// startFederating starts the syncer based federation. This blocks until the syncer is in-sync or
// we've been asked to stop.
func (c *federatedServicesController) startFederating(stopCh chan struct{}) {
	log.Debug("Start federating syncer")

	// Start the decoupler which will funnel the syncer updates to the controllers update methods
	// synchronously (so there is no chance of multiple concurrent updates).
	go c.decoupler.SendTo(c)
	c.syncer.Start()
	select {
	case <-stopCh:
	case <-c.inSync:
	}
}

// OnStatusUpdated implements the syncer interface.
func (c *federatedServicesController) OnStatusUpdated(status bapi.SyncStatus) {
	if status == bapi.InSync {
		log.Debug("Federating syncer is now in-sync")
		c.isInSync = true

		// We are now in sync with the local datastore and the remote clusters. Calculate any federated service
		// endpoints that we need to before notifying the main reconciler that we are sync'd.
		c.handleDirtyServices()
		c.inSync <- struct{}{}
	}
}

// OnUpdates implements the syncer interface.  This processes local and remote service and
// endpoints and federates based on service annotations.
func (c *federatedServicesController) OnUpdates(updates []bapi.Update) {
	for _, u := range updates {
		var id serviceID
		var kind string
		switch rk := u.Key.(type) {
		case model.RemoteClusterResourceKey:
			// Store the cluster
			id = serviceID{
				cluster:   rk.Cluster,
				namespace: rk.Namespace,
				name:      rk.Name,
			}
			kind = rk.Kind
		case model.ResourceKey:
			id = serviceID{
				namespace: rk.Namespace,
				name:      rk.Name,
			}
			kind = rk.Kind
		case model.RemoteClusterStatusKey:
			if v, ok := u.Value.(*model.RemoteClusterStatus); ok {
				log.WithFields(log.Fields{
					"Key":    rk,
					"Status": v.Status.String(),
					"Error":  v.Error,
				}).Info("Remote cluster status update")
			} else {
				log.WithFields(log.Fields{
					"Key": rk,
				}).Info("Remote cluster deleted")
			}
			continue
		default:
			log.WithField("Key", rk).Error("Unexpected resource type in syncer update")
			continue
		}

		entry := c.allServices[id]
		if entry == nil {
			// For new entries we need to do some initialization of the structure.
			entry = &serviceInfo{
				backingServices:   set.New[serviceID](),
				federatedServices: set.New[serviceID](),
			}
			c.allServices[id] = entry
		}
		wasFederated := entry.federationConfig != nil

		clog := log.WithFields(log.Fields{
			"cluster":      id.cluster,
			"name":         id.name,
			"namespace":    id.namespace,
			"wasFederated": wasFederated,
			"kind":         kind,
		})

		switch kind {
		case apiv3.KindK8sEndpoints:
			clog.Debug("Processing Endpoints")
			oldEndpoints := entry.endpoints
			var changed bool
			switch u.UpdateType {
			case bapi.UpdateTypeKVDeleted:
				entry.endpoints = nil
				changed = oldEndpoints != nil
			case bapi.UpdateTypeKVUpdated, bapi.UpdateTypeKVNew:
				// Store the endpoints associated with this service, adjusting the endpoint names to include
				// the cluster name as well.
				entry.endpoints = u.Value.(*v1.Endpoints) //nolint:staticcheck
				if id.cluster != "" {
					for _, s := range entry.endpoints.Subsets {
						for _, a := range s.Addresses {
							ref := a.TargetRef
							if ref != nil && ref.Name != "" {
								ref.Name = id.cluster + "/" + ref.Name
							}
						}
						for _, a := range s.NotReadyAddresses {
							ref := a.TargetRef
							if ref != nil && ref.Name != "" {
								ref.Name = id.cluster + "/" + ref.Name
							}
						}
					}
				}
				changed = oldEndpoints == nil || !reflect.DeepEqual(oldEndpoints.Subsets, entry.endpoints.Subsets)
			}

			// If the endpoints subsets have changed, flag as dirty all of the federated services affected by this
			// service.
			if changed {
				clog.Debug("Endpoints entry updated")
				for item := range entry.federatedServices.All() {
					clog.Debugf("Marking service as dirty: %#v", item)
					c.dirtyServices.Add(item)
				}
			}

		case model.KindKubernetesService:
			clog.Debug("Processing Service")
			switch u.UpdateType {
			case bapi.UpdateTypeKVDeleted:
				entry.service = nil
				entry.federationConfig = nil
				entry.federationConfigErr = nil
			case bapi.UpdateTypeKVUpdated, bapi.UpdateTypeKVNew:
				entry.service = u.Value.(*v1.Service)

				// In our internal stored version of the service add labels to allow us to do selector based on service
				// name, namespace and cluster.
				if entry.service.Labels == nil {
					entry.service.Labels = make(map[string]string)
				}
				entry.service.Labels[apiv3.LabelNamespace] = id.namespace
				if id.cluster != "" {
					entry.service.Labels[LabelClusterName] = id.cluster
				}

				// Extract the federation config (or parsing error) from the annotations.
				entry.federationConfig, entry.federationConfigErr = c.extractFederationConfig(entry.service)

				// Error parsing federation config. If this is on the local cluster then warn the user that we will
				// not be updating the endpoints for this service.
				if entry.federationConfigErr != nil && id.cluster == "" {
					log.WithError(entry.federationConfigErr).Warningf("Unable to parse federation config; "+
						"the Service '%v' will not be included in Calico Enterprise federation", entry.service.Name)
				}
			}

			// For services on the local cluster we need to track the federated service selectors in the label index
			// handler. We'll get callbacks when the selectors match and unmatch local and remote service labels (which
			// are added below).
			isFederated := entry.federationConfig != nil
			if id.cluster == "" {
				if isFederated {
					clog.Debug("Adding federation selector to label index handler")
					c.serviceLabelHandler.UpdateSelector(id, entry.federationConfig.selector)
					c.dirtyServices.Add(id)
				} else if wasFederated {
					clog.Debug("Removing federation selector from label index handler")
					c.serviceLabelHandler.DeleteSelector(id)
					c.dirtyServices.Add(id)
				}
			}

			// For all services, across all clusters, that do not have any federation configuration, we need to track
			// the services labels. Note that in this case, error loading federation config also counts as the service
			// having federation configuration.
			hasNoFederationConfig := !isFederated && entry.federationConfigErr == nil
			if hasNoFederationConfig && entry.service != nil && entry.service.Labels != nil {
				c.serviceLabelHandler.UpdateLabels(id, uniquelabels.Make(entry.service.Labels), nil)
			} else {
				c.serviceLabelHandler.DeleteLabels(id)
			}
		}

		// If there are no resources associated with this id anymore then remove the service entry. Note that we do
		// not have a branch updating the allServices dictionary with the latest settings - this is not required since
		// the value is a pointer and therefore any updates were made directly into the cached structure.
		if entry.service == nil && entry.endpoints == nil {
			log.Debug("Deleting service")
			delete(c.allServices, id)
		}
	}

	// If we are in-sync then handle all dirty services. We do this after injecting all of the updates to reduce
	// calculation churn. If we aren't in-sync then we'll calculate the services as soon as we are.
	if c.isInSync {
		c.handleDirtyServices()
	}
}

// handleDirtyServices processes each local service that is flagged as "dirty", i.e. that it's calculated
// endpoint list has changed, or that the associated service has been deleted.
func (c *federatedServicesController) handleDirtyServices() {
	log.Debug("Processing modified services")
	for fsid := range c.dirtyServices.All() {
		log.Debugf("Processing dirty service: %#v", fsid)

		k := fsid.namespace + "/" + fsid.name
		clog := log.WithField("key", k)
		fcEntry, existsInFederationCache := c.allServices[fsid]
		rval, existsInReconcilerCache := c.cache.Get(k)

		if !existsInFederationCache || fcEntry.federationConfig == nil {
			clog.Debug("Service does not exist or is not being federated")

			if existsInReconcilerCache {
				// This service is not federated but an entry exists in the reconciler cache - delete it.
				clog.Info("Service is no longer federated, deleting Endpoints from cache")
				c.cache.Delete(k)
			}

			continue
		}

		// The service is federated, if the required endpoints differs from the reconciler cache then update
		// the reconciler cache.
		clog.Debug("Service is federated")
		endpoints := *c.calculateEndpoints(fsid, fcEntry)
		if !existsInReconcilerCache || !reflect.DeepEqual(rval.(v1.Endpoints), endpoints) { //nolint:staticcheck
			clog.Debugf("Service Endpoints added or modified, setting in cache: %#v", endpoints)
			c.cache.Set(k, endpoints)
		}
	}

	log.Debug("Finished processing modified services")
	c.dirtyServices.Clear()
}

// calculateEndpoints calculates the federated service endpoints from the cached service and endpoint
// data.
func (c *federatedServicesController) calculateEndpoints(id serviceID, serviceInfo *serviceInfo) *v1.Endpoints { //nolint:staticcheck
	// Extract the set of ports (name and protocol) that we are federating in this service.
	ports := make(map[portId]struct{})
	for _, p := range serviceInfo.service.Spec.Ports {
		ports[portId{p.Name, p.Protocol}] = struct{}{}
	}

	log.WithFields(log.Fields{
		"ports":              ports,
		"id":                 id,
		"numBackingServices": serviceInfo.backingServices.Len(),
	}).Debug("Calculating endpoints for service")

	// Iterate through the services that are contributing to the federated service and expand out the addresses and
	// ports.  Order the services to avoid overly large deltas to the endpoints data, and to ensure a non-changing
	// update doesn't cause any unnecessary update churn.
	var subsets []v1.EndpointSubset //nolint:staticcheck
	for sid := range serviceInfo.backingServices.All() {
		if c.allServices[sid].endpoints == nil {
			// The endpoints data is missing, so nothing to include.
			continue
		}
		for i, ss := range c.allServices[sid].endpoints.Subsets {
			var filteredPorts []v1.EndpointPort
			for _, p := range ss.Ports {
				log.WithFields(log.Fields{
					"backingService": sid,
					"port":           p,
					"subsetIdx":      i,
				}).Debug("Checking port/protocol")

				if _, ok := ports[portId{p.Name, p.Protocol}]; ok {
					// Port matches name and protocol - include it.
					log.Debug("Including port")
					filteredPorts = append(filteredPorts, p)
				}
			}
			if len(filteredPorts) > 0 {
				log.Debug("Including subset")
				subsets = append(subsets, v1.EndpointSubset{ //nolint:staticcheck
					Addresses:         ss.Addresses,
					NotReadyAddresses: ss.NotReadyAddresses,
					Ports:             filteredPorts,
				})
			}
		}
	}

	// Return an Endpoints object, with deduplicated, ordered and expanded Subsets.
	return &v1.Endpoints{ //nolint:staticcheck
		ObjectMeta: metav1.ObjectMeta{
			Name:        id.name,
			Namespace:   id.namespace,
			Annotations: serviceInfo.federationConfig.annotations,
		},
		Subsets: endpoints.RepackSubsets(subsets),
	}
}

// extractFederationConfig extracts the service federation configuration from the service annotations.
// This returns an error if the annotation config could not be parsed, or if the annotation settings
// conflict with the main service configuration.
// If a service has federation config (even if errored) then the service will not itself be included in
// any other federated services.
func (c *federatedServicesController) extractFederationConfig(s *v1.Service) (*federatedServiceConfig, error) {
	clog := log.WithFields(log.Fields{
		"Name": s.Name, "Namespace": s.Namespace,
	})
	selectorExpression, ok := s.Annotations[FederationServiceSelectorAnnotation]
	if !ok {
		clog.Debug("No federation service selector, not a federated service")
		return nil, nil
	}
	if len(s.Spec.Selector) != 0 {
		clog.Debug("Service is federated, but includes a service Spec.Selector")
		return nil, fmt.Errorf("Spec.Selector is specified for a federated service: the Federated Services controller is" +
			"unable to manage and federate the service endpoints")
	}

	// Update the selector to include a namespace match.
	withNamespaceSelectorExpression := apiv3.LabelNamespace + " == '" + s.Namespace + "'"
	if selectorExpression != "" {
		withNamespaceSelectorExpression += " && (" + selectorExpression + ")"
	}

	// Parse the selector and store the parsed Selector object.
	parsedSel, err := selector.Parse(withNamespaceSelectorExpression)
	if err != nil {
		clog.WithError(err).Info("Failed to parse selector")
		return nil, fmt.Errorf("ServiceSelector expression '%s' in annotation '%s' is not valid: %s",
			selectorExpression, FederationServiceSelectorAnnotation, err)
	}

	clog.Debug("Successfully parsed federated service config from service annotations")
	return &federatedServiceConfig{
		annotations: map[string]string{
			FederationServiceSelectorAnnotation: selectorExpression,
		},
		selector: parsedSel,
	}, nil
}

// onServiceMatchStarted is the label index callback to indicate a match between a federated service and
// a backing service.
func (c *federatedServicesController) onServiceMatchStarted(federatedId, backingId any) {
	log.WithFields(log.Fields{"federatedId": federatedId, "backingId": backingId}).Debug("Services matched")
	fsid := federatedId.(serviceID)
	bsid := backingId.(serviceID)
	federatedService := c.allServices[fsid]
	backingService := c.allServices[bsid]

	// Update the federated and backing services to ensure the two services are linked. Flag the federated service as
	// dirty.
	federatedService.backingServices.Add(bsid)
	backingService.federatedServices.Add(fsid)
	c.dirtyServices.Add(fsid)
}

// onServiceMatchStopped is the label index callback to indicate a removed match between a federated service and
// a backing service.
func (c *federatedServicesController) onServiceMatchStopped(federatedId, backingId any) {
	log.WithFields(log.Fields{"federatedId": federatedId, "backingId": backingId}).Debug("Services un-matched")
	fsid := federatedId.(serviceID)
	bsid := backingId.(serviceID)
	federatedService := c.allServices[fsid]
	backingService := c.allServices[bsid]

	// Update the federated and backing services to ensure the two services are unlinked. Flag the federated service as
	// dirty.
	federatedService.backingServices.Discard(bsid)
	backingService.federatedServices.Discard(fsid)
	c.dirtyServices.Add(fsid)
}

// sanitizeMetadata returns a cleaned Metadata that allows comparison between the calculated service and endpoint
// configuration and the data actually read from the API. This removes all but the name, namespace and federation
// specific annotations.
func (_ *federatedServicesController) sanitizeEndpoints(e *v1.Endpoints) { //nolint:staticcheck
	// Sanitize the metadata: we only require the Name, Namespace and the Tigera-specific annotations.
	// Everything else we remove to ensure our cache comparisons only check the required data fields.
	annotations := make(map[string]string)
	for k, v := range e.Annotations {
		if strings.HasPrefix(k, FederationAnnotationPrefix) {
			annotations[k] = v
		}
	}
	e.ObjectMeta = metav1.ObjectMeta{
		Name:        e.Name,
		Namespace:   e.Namespace,
		Annotations: annotations,
	}
	// Remove the type data which can be inferred from the structure.
	e.TypeMeta = metav1.TypeMeta{}

	// Finally, deduplicate and order the Subsets (since Kubernetes re-orders and re-groups them).
	e.Subsets = endpoints.RepackSubsets(e.Subsets)
}

// nameNamespaceToCacheKey converts the namespace and name of a service to a key that may be used for the
// resource cache. Note that the cache only manages data on the local cluster, so there is no need to include
// a cluster parameter.
func nameNamespaceToCacheKey(namespace, name string) string {
	return namespace + "/" + name
}

// nameNamespaceFromCacheKey extracts the namespace and name from the cache key calculated in
// nameNamespaceToCacheKey.
func nameNamespaceFromCacheKey(key string) (string, string) {
	parts := strings.Split(key, "/")
	return parts[0], parts[1]
}

type portId struct {
	name     string
	protocol v1.Protocol
}
