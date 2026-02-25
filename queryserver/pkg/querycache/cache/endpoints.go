// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.
package cache

import (
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/labelhandler"
)

var matchTypeToDelta = map[labelhandler.MatchType]int{
	labelhandler.MatchStarted: 1,
	labelhandler.MatchStopped: -1,
}

// EndpointsCache implements the cache interface for both WorkloadEndpoint and HostEndpoint resource types collectively.
// This interface consists of both the query and the event update interface.
type EndpointsCache interface {
	TotalWorkloadEndpointsByNamespace() map[string]api.EndpointSummary
	TotalHostEndpoints() api.EndpointSummary
	GetEndpoint(model.Key) api.Endpoint
	GetEndpoints([]model.Key) []api.Endpoint
	RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface)
	RegisterWithLabelHandler(handler labelhandler.Interface)
	RegisterWithSharedInformer(factory informers.SharedInformerFactory, stopCh <-chan struct{})
}

// NewEndpointsCache creates a new instance of an EndpointsCache.
func NewEndpointsCache() EndpointsCache {
	return &endpointsCache{
		workloadEndpointsByNamespace: make(map[string]*endpointCache),
		hostEndpoints:                newEndpointCache(),

		converter:    conversion.NewConverter(),
		wepConverter: conversion.NewWorkloadEndpointConverter(),
	}
}

// endpointsCache implements the EndpointsCache interface.  It separates out the workload and host endpoints into
// separate sub-caches. Events and requests are handled using the appropriate sub-cache.
type endpointsCache struct {
	workloadEndpointsByNamespace map[string]*endpointCache
	hostEndpoints                *endpointCache

	converter    conversion.Converter
	wepConverter conversion.WorkloadEndpointConverter
}

// newEndpointCache creates a new endpointCache.
func newEndpointCache() *endpointCache {
	return &endpointCache{
		endpoints:            make(map[model.Key]*endpointData),
		unprotectedEndpoints: set.New[model.Key](),
		failedEndpoints:      set.New[model.Key](),
	}
}

// endpointCache is the sub-cache for a specific endpoint type.
type endpointCache struct {
	// The endpoints keyed off the resource key.
	endpoints map[model.Key]*endpointData

	// The number of unlabelled (that is explicitly added labels rather than implicitly
	// added) endpoints in this cache.
	numUnlabelled int

	// Stores endpoint keys that have no policies associated (i.e., "unprotected").
	unprotectedEndpoints set.Set[model.Key]

	// Stores workload endpoints that are failed
	failedEndpoints set.Set[model.Key]
}

func (c *endpointsCache) TotalHostEndpoints() api.EndpointSummary {
	return api.EndpointSummary{
		Total:             len(c.hostEndpoints.endpoints),
		NumWithNoLabels:   c.hostEndpoints.numUnlabelled,
		NumWithNoPolicies: c.hostEndpoints.unprotectedEndpoints.Len(),
	}
}

func (c *endpointsCache) TotalWorkloadEndpointsByNamespace() map[string]api.EndpointSummary {
	weps := make(map[string]api.EndpointSummary)
	for ns, cache := range c.workloadEndpointsByNamespace {
		weps[ns] = api.EndpointSummary{
			Total:             len(cache.endpoints),
			NumWithNoLabels:   cache.numUnlabelled,
			NumWithNoPolicies: cache.unprotectedEndpoints.Len(),
			NumFailed:         cache.failedEndpoints.Len(),
		}
	}
	return weps
}

func (c *endpointsCache) onUpdate(update dispatcherv1v3.Update) {
	uv3 := update.UpdateV3

	// Get the endpoint cache, creating if necessary.
	ec := c.getEndpointCache(uv3.Key, true)
	if ec == nil {
		return
	}
	switch uv3.UpdateType {
	case bapi.UpdateTypeKVNew:
		ed := &endpointData{resource: uv3.Value.(api.Resource)}
		ec.updateHasLabelsCounts(false, !ed.IsLabelled())
		ec.endpoints[uv3.Key] = ed
		// All endpoints are unprotected initially. policyEndpointMatch() will
		// remove them from this set if policies apply on this endpoint.
		ec.unprotectedEndpoints.Add(uv3.Key)
	case bapi.UpdateTypeKVUpdated:
		ed := ec.endpoints[uv3.Key]
		wasUnlabelled := !ed.IsLabelled()
		ed.resource = uv3.Value.(api.Resource)
		ec.updateHasLabelsCounts(wasUnlabelled, !ed.IsLabelled())
		ec.updateFailedEndpoints(uv3)
	case bapi.UpdateTypeKVDeleted:
		ed := ec.endpoints[uv3.Key]
		ec.unprotectedEndpoints.Discard(uv3.Key)
		ec.updateHasLabelsCounts(!ed.IsLabelled(), false)
		// When a Pod is failed and removed from the cluster, we will get
		// a WEP delete event together with phase equals Failed. The failed
		// WEP key is added into the failedEndpoints collection and reported
		// back to Manager. As the WEP is deleted, we won't get future events
		// for Pod deletion either by human or controllers. We need a separate
		// onPodDelete() notification function to track this and remove the
		// failed WEP from the failedEndpoints collection.
		ec.updateFailedEndpoints(uv3)
		delete(ec.endpoints, uv3.Key)
	}

	if uv3.Key.(model.ResourceKey).Kind == internalapi.KindWorkloadEndpoint {
		c.maybeDeleteEndpointCacheByNamespace(ec, uv3.Key.(model.ResourceKey).Namespace)
	}
}

func (c *endpointsCache) onPodDelete(obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		log.Debug("can't assert obj to *corev1.Pod")
		return
	}

	if !c.converter.IsValidCalicoWorkloadEndpoint(pod) {
		log.WithField("pod", pod).Debug("failed to validate a pod as a wep")
		return
	}

	kvps, err := c.wepConverter.PodToWorkloadEndpoints(pod)
	if err != nil {
		log.WithError(err).WithField("pod", pod).Debug("failed to convert a pod to a wep")
		return
	}

	for _, kvp := range kvps {
		if ec := c.getEndpointCache(kvp.Key, false); ec != nil {
			ec.failedEndpoints.Discard(kvp.Key)
			c.maybeDeleteEndpointCacheByNamespace(ec, pod.GetNamespace())
		}
	}
}

func (c *endpointsCache) GetEndpoint(key model.Key) api.Endpoint {
	if ep := c.getEndpoint(key); ep != nil {
		return ep
	}
	return nil
}

// GetEndpoints return list of all endpoints including both workload endpoints and host endpoints.
func (c *endpointsCache) GetEndpoints(keys []model.Key) []api.Endpoint {
	if len(keys) == 0 {
		eps := make([]api.Endpoint, 0)
		// getAllEndpoints returns []*endpointsData, endpointsData implements api.Endpoint, thus the conversion
		// is safe. Go doesn't do this conversion for the array though, and we need to iterate and append endpoints one by one.
		for _, ep := range c.getAllEndpoints() {
			eps = append(eps, ep)
		}
		return eps
	}
	eps := make([]api.Endpoint, len(keys))
	for _, key := range keys {
		ep := c.getEndpoint(key)
		eps = append(eps, ep)
	}
	return eps
}

func (c *endpointsCache) RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface) {
	dispatcher.RegisterHandler(internalapi.KindWorkloadEndpoint, c.onUpdate)
	dispatcher.RegisterHandler(apiv3.KindHostEndpoint, c.onUpdate)
}

func (c *endpointsCache) RegisterWithLabelHandler(handler labelhandler.Interface) {
	handler.RegisterPolicyHandler(c.policyEndpointMatch)
}

func (c *endpointsCache) RegisterWithSharedInformer(factory informers.SharedInformerFactory, stopCh <-chan struct{}) {
	informer := factory.Core().V1().Pods().Informer()
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: c.onPodDelete,
	}); err != nil {
		log.WithError(err).Error("failed to add resource event handler for endpoints")
		return
	}
	go informer.Run(stopCh)
}

func (c *endpointsCache) maybeDeleteEndpointCacheByNamespace(ec *endpointCache, namespace string) {
	if len(ec.endpoints) == 0 && ec.failedEndpoints.Len() == 0 {
		// Workload endpoints cache is empty for this namespace. Delete from the cache.
		delete(c.workloadEndpointsByNamespace, namespace)
	}
}

func (c *endpointsCache) policyEndpointMatch(matchType labelhandler.MatchType, polKey model.Key, epKey model.Key) {
	epd := c.getEndpoint(epKey)
	if epd == nil {
		// The endpoint has been deleted. Since the endpoint cache is updated before the index handler is updated this is
		// a valid scenario, and should be treated as a no-op.
		return
	}
	prk := polKey.(model.ResourceKey)
	switch prk.Kind {
	case apiv3.KindGlobalNetworkPolicy,
		apiv3.KindStagedGlobalNetworkPolicy,
		model.KindKubernetesAdminNetworkPolicy,
		model.KindKubernetesBaselineAdminNetworkPolicy:
		// For historical reasons we lump staged and Kubernetes policies in with global network policies.
		// TODO: Separate these kinds out into their own counters.
		// https://tigera.atlassian.net/browse/CORE-12225
		epd.policies.NumGlobalNetworkPolicies += matchTypeToDelta[matchType]
	case apiv3.KindNetworkPolicy,
		apiv3.KindStagedNetworkPolicy,
		apiv3.KindStagedKubernetesNetworkPolicy,
		model.KindKubernetesNetworkPolicy:
		// For historical reasons we lump staged and Kubernetes NetworkPolicies in with Calico NetworkPolicies.
		// TODO: Separate these kinds out into their own counters.
		// https://tigera.atlassian.net/browse/CORE-12225
		epd.policies.NumNetworkPolicies += matchTypeToDelta[matchType]
	default:
		log.WithField("key", prk).Error("Unexpected resource in event type, expecting a v3 policy type")
	}

	// Get the endpoint cache to update. Disallow creation of the cache if it doesn't exist, however we know
	// it exists since we successfully got the endpoint above.
	ec := c.getEndpointCache(epKey, false)
	if epd.IsProtected() {
		ec.unprotectedEndpoints.Discard(epKey)
	} else {
		ec.unprotectedEndpoints.Add(epKey)
	}
}

func (c *endpointCache) updateHasLabelsCounts(before, after bool) {
	if before == after {
		return
	}
	if after {
		c.numUnlabelled++
	} else {
		c.numUnlabelled--
	}
}

func (c *endpointCache) updateFailedEndpoints(uv3 *bapi.Update) {
	// We only consider failed WEPs (Pods) for now. HEPs failures are not monitored yet.
	if wep, ok := uv3.Value.(*internalapi.WorkloadEndpoint); ok {
		if wep.Status.Phase == string(corev1.PodFailed) {
			c.failedEndpoints.Add(uv3.Key)
		} else {
			c.failedEndpoints.Discard(uv3.Key)
		}
	}
}

func (c *endpointsCache) getEndpoint(key model.Key) *endpointData {
	// Get the endpoint cache to update. Disallow creation of the cache if it doesn't exist and just return a nil
	// result if it doesn't.
	ec := c.getEndpointCache(key, false)
	if ec == nil {
		return nil
	}
	return ec.endpoints[key]
}

// getAllEndpoints returns a list of both workload endpoints and host endpoints
func (c *endpointsCache) getAllEndpoints() []*endpointData {
	endpointsResult := make([]*endpointData, 0)

	// add workloadEndpoints
	for _, epcache := range c.workloadEndpointsByNamespace {
		for _, ep := range epcache.endpoints {
			endpointsResult = append(endpointsResult, ep)
		}
	}

	// add hostendpoints
	hostEPCache := c.hostEndpoints
	for _, ep := range hostEPCache.endpoints {
		endpointsResult = append(endpointsResult, ep)
	}

	return endpointsResult
}

func (c *endpointsCache) getEndpointCache(epKey model.Key, create bool) *endpointCache {
	if rKey, ok := epKey.(model.ResourceKey); ok {
		switch rKey.Kind {
		case internalapi.KindWorkloadEndpoint:
			workloadEndpoints := c.workloadEndpointsByNamespace[rKey.Namespace]
			if workloadEndpoints == nil && create {
				workloadEndpoints = newEndpointCache()
				c.workloadEndpointsByNamespace[rKey.Namespace] = workloadEndpoints
			}
			return workloadEndpoints
		case apiv3.KindHostEndpoint:
			return c.hostEndpoints
		default:
			log.WithField("kind", rKey.Kind).Fatal("unexpected resource kind")
			return nil
		}
	}
	log.WithField("key", epKey).Error("Unexpected resource, expecting a v3 endpoint type")
	return nil
}

type endpointData struct {
	resource api.Resource
	policies api.PolicyCounts
}

func (e *endpointData) GetPolicyCounts() api.PolicyCounts {
	return e.policies
}

func (e *endpointData) GetResource() api.Resource {
	return e.resource
}

func (e *endpointData) GetNode() string {
	switch r := e.resource.(type) {
	case *internalapi.WorkloadEndpoint:
		return r.Spec.Node
	case *apiv3.HostEndpoint:
		return r.Spec.Node
	}
	return ""
}

// IsProtected returns true when an endpoint has one or more GlobalNetworkPolicies
// or NetworkPolicies that apply to it.
func (e *endpointData) IsProtected() bool {
	return e.policies.NumGlobalNetworkPolicies > 0 || e.policies.NumNetworkPolicies > 0
}

// IsLabelled returns true when there are explicitly configured labels on the endpoint.
// This ignores implicitly added labels such as projectcalico/org/namespace, or labels
// inherited through a profile.
func (e *endpointData) IsLabelled() bool {
	switch e.resource.GetObjectKind().GroupVersionKind().Kind {
	case internalapi.KindWorkloadEndpoint:
		// WEPs automatically have a namespace and orchestrator label added to them.
		return len(e.resource.GetObjectMeta().GetLabels()) > 2
	case apiv3.KindHostEndpoint:
		return len(e.resource.GetObjectMeta().GetLabels()) > 0
	}
	return false
}
