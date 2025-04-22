// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.
package client

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/strings/slices"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/cache"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/labelhandler"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/utils"
)

// NewQueryInterface returns a queryable resource cache.
func NewQueryInterface(k8sClient kubernetes.Interface, ci clientv3.Interface, stopCh <-chan struct{}) QueryInterface {
	cq := &cachedQuery{
		policies:                   cache.NewPoliciesCache(),
		endpoints:                  cache.NewEndpointsCache(),
		nodes:                      cache.NewNodeCache(),
		networksets:                cache.NewNetworkSetsCache(),
		policyEndpointLabelHandler: labelhandler.NewLabelHandler(),
		labelAggregator:            NewLabelsAggregator(k8sClient, ci),
		wepConverter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewWorkloadEndpointUpdateProcessor(),
		),
		gnpConverter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(),
		),
		npConverter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewNetworkPolicyUpdateProcessor(),
		),
		sgnpConverter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewStagedGlobalNetworkPolicyUpdateProcessor(),
		),
		snpConverter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewStagedNetworkPolicyUpdateProcessor(),
		),
		sk8snpConverter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewStagedKubernetesNetworkPolicyUpdateProcessor(),
		),
		nsConverter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
			updateprocessors.NewNetworkSetUpdateProcessor(),
		),
	}

	// We want to watch the v3 resource types (so that we can cache the actual configured
	// data), but we need the v1 version of several of the resources to feed into the various
	// Felix helper helper modules. The dispatcherv1v3 converts the updates from v3 to v1 (using
	// the watchersyncer update processor functionality used by Felix), and fans out an update
	// containing both the v1 and v3 data to any handlers registered for notifications.
	dispatcherTypes := getDispachers(cq)
	dispatcher := dispatcherv1v3.New(dispatcherTypes)

	// Register the caches for updates from the dispatcher.
	cq.endpoints.RegisterWithDispatcher(dispatcher)
	cq.policies.RegisterWithDispatcher(dispatcher)
	cq.nodes.RegisterWithDispatcher(dispatcher)
	cq.networksets.RegisterWithDispatcher(dispatcher)

	// Register the label handlers *after* the actual resource caches (since the
	// resource caches register for updates from the label handler)
	cq.policyEndpointLabelHandler.RegisterWithDispatcher(dispatcher)

	// Register the policy and endpoint caches for updates from the label handler.
	cq.endpoints.RegisterWithLabelHandler(cq.policyEndpointLabelHandler)
	cq.policies.RegisterWithLabelHandler(cq.policyEndpointLabelHandler)

	// Register informers for resource caches.
	factory := informers.NewSharedInformerFactory(k8sClient, 0)
	cq.endpoints.RegisterWithSharedInformer(factory, stopCh)

	// Create a SyncerQueryHandler which ensures syncer updates and query requests are
	// serialized. This handler will pass syncer updates to the dispatcher (see below),
	// and pass query update into this cahcedQuery instance.
	scb, qi := NewSerializedSyncerQuery(dispatcher, cq)

	// Create a watchersyncer for the same resource types that the dispatcher handles.
	// The syncer will call into the SyncerQuerySerializer.
	wsResourceTypes := make([]watchersyncer.ResourceType, 0, len(dispatcherTypes))
	for _, r := range dispatcherTypes {
		wsResourceTypes = append(wsResourceTypes, watchersyncer.ResourceType{
			ListInterface: model.ResourceListOptions{Kind: r.Kind},
		})
	}
	syncer := watchersyncer.New(
		ci.(backend).Backend(),
		wsResourceTypes,
		scb,
	)

	// Start the syncer and return the synchronized query interface.
	syncer.Start()

	return qi
}

// We know the calico clients implement the Backend() method, so define an interface
// to allow us to access that method.
type backend interface {
	Backend() bapi.Client
}

// cachedQuery implements the QueryInterface.
type cachedQuery struct {
	// A cache of all loaded policy (keyed off name) and endpoint resources (keyed off key).
	// The cache includes Tiers, GNPs and NPs.
	policies cache.PoliciesCache

	// A cache of all loaded endpoints. The cache includes both HEPs and WEPs.
	endpoints cache.EndpointsCache

	// A cache of all loaded nodes. The cache includes directly configured node resources, as
	// well as those configured indirectly via WEPs and HEPs.
	nodes cache.NodeCache

	// A cache of all loaded networksets.
	networksets cache.NetworkSetsCache

	// An interface for retrieving aggregated resource labels
	labelAggregator LabelAggregator

	// policyEndpointLabelHandler handles the relationship between policy and rule selectors
	// and endpoint and networkset labels.
	policyEndpointLabelHandler labelhandler.Interface

	// Converters for some of the resources.
	wepConverter dispatcherv1v3.Converter
	gnpConverter dispatcherv1v3.Converter
	npConverter  dispatcherv1v3.Converter

	sgnpConverter   dispatcherv1v3.Converter
	snpConverter    dispatcherv1v3.Converter
	sk8snpConverter dispatcherv1v3.Converter

	nsConverter dispatcherv1v3.Converter
}

// RunQuery is a callback from the SyncerQuerySerializer to run a query.  It is guaranteed
// not to be called at the same time as OnUpdates and OnStatusUpdated.
func (c *cachedQuery) RunQuery(cxt context.Context, req interface{}) (interface{}, error) {
	switch qreq := req.(type) {
	case QueryClusterReq:
		return c.runQuerySummary(cxt, qreq)
	case QueryEndpointsReq:
		return c.runQueryEndpoints(qreq)
	case QueryPoliciesReq:
		return c.runQueryPolicies(cxt, qreq)
	case QueryNodesReq:
		return c.runQueryNodes(cxt, qreq)
	case QueryLabelsReq:
		return c.runQueryLabels(cxt, qreq)
	default:

		return nil, fmt.Errorf("unhandled query type: %#v", req)
	}
}

func (c *cachedQuery) runQuerySummary(cxt context.Context, req QueryClusterReq) (*QueryClusterResp, error) {
	// This function is called by /summary (from Manager dashboard) and /metrics (from Prometheus).
	// Queryserver serves both as a data source and a consumer. When time range is invalid,
	// we get summary data from the in-memory cache (Prometheus and dashboard "to" equals now).
	// when time range is valid, we get historical summary data from time-series database.
	endpointsCache := c.endpoints
	policiesCache := c.policies
	nodeCache := c.nodes
	if req.Timestamp != nil {
		promClient, err := cache.NewPrometheusClient(req.PrometheusEndpoint, req.Token)
		if err != nil {
			return nil, err
		}

		endpointsCache = cache.NewEndpointsCacheHistory(promClient, *req.Timestamp)
		policiesCache = cache.NewPoliciesCacheHistory(promClient, *req.Timestamp)
		nodeCache = cache.NewNodeCacheHistory(promClient, *req.Timestamp)
	}

	// Get the summary counts for the endpoints, summing up the per namespace counts.
	hepSummary := endpointsCache.TotalHostEndpoints()
	totWEP := 0
	numUnlabelledWEP := 0
	numUnprotectedWEP := 0
	numFailedWEP := 0
	namespaceSummary := make(map[string]QueryClusterNamespaceCounts)
	for ns, weps := range endpointsCache.TotalWorkloadEndpointsByNamespace() {
		totWEP += weps.Total
		numUnlabelledWEP += weps.NumWithNoLabels
		numUnprotectedWEP += weps.NumWithNoPolicies
		numFailedWEP += weps.NumFailed
		namespaceSummary[ns] = QueryClusterNamespaceCounts{
			NumWorkloadEndpoints:            weps.Total,
			NumUnlabelledWorkloadEndpoints:  weps.NumWithNoLabels,
			NumUnprotectedWorkloadEndpoints: weps.NumWithNoPolicies,
			NumFailedWorkloadEndpoints:      weps.NumFailed,
		}
	}

	// Get the summary counts for policies, summing up the per namespace counts.
	gnpSummary := policiesCache.TotalGlobalNetworkPolicies()
	totNP := 0
	numUnmatchedNP := 0
	for ns, nps := range policiesCache.TotalNetworkPoliciesByNamespace() {
		totNP += nps.Total
		numUnmatchedNP += nps.NumUnmatched

		// Update the existing entry with the NP counts, or create a new one if it doesn't exist.
		counts := namespaceSummary[ns]
		counts.NumNetworkPolicies = nps.Total
		counts.NumUnmatchedNetworkPolicies = nps.NumUnmatched
		namespaceSummary[ns] = counts
	}

	resp := &QueryClusterResp{
		NumGlobalNetworkPolicies:          gnpSummary.Total,
		NumNetworkPolicies:                totNP,
		NumHostEndpoints:                  hepSummary.Total,
		NumWorkloadEndpoints:              totWEP,
		NumUnmatchedGlobalNetworkPolicies: gnpSummary.NumUnmatched,
		NumUnmatchedNetworkPolicies:       numUnmatchedNP,
		NumUnlabelledHostEndpoints:        hepSummary.NumWithNoLabels,
		NumUnlabelledWorkloadEndpoints:    numUnlabelledWEP,
		NumUnprotectedHostEndpoints:       hepSummary.NumWithNoPolicies,
		NumUnprotectedWorkloadEndpoints:   numUnprotectedWEP,
		NumFailedWorkloadEndpoints:        numFailedWEP,
		NumNodes:                          nodeCache.TotalNodes(),
		NumNodesWithNoEndpoints:           nodeCache.TotalNodesWithNoEndpoints(),
		NumNodesWithNoWorkloadEndpoints:   nodeCache.TotalNodesWithNoWorkloadEndpoints(),
		NumNodesWithNoHostEndpoints:       nodeCache.TotalNodesWithNoHostEndpoints(),
		NamespaceCounts:                   namespaceSummary,
	}
	return resp, nil
}

// runQueryEndpoints is searching for endpoints based on the provided parameters in QueryEndpointsReq
//
// if EndpointsList is provided as part of the QueryEndpointsReq, search will only run on the provided EndpointsList,
// not all the endpoints in the environment.
func (c *cachedQuery) runQueryEndpoints(req QueryEndpointsReq) (*QueryEndpointsResp, error) {
	// If an endpoint was specified, just return that (if it exists).
	if req.Endpoint != nil {
		ep := c.endpoints.GetEndpoint(req.Endpoint)
		if ep == nil {
			// Endpoint does not exist, return no results.
			return nil, errors.ErrorResourceDoesNotExist{
				Identifier: req.Endpoint,
			}
		}
		return &QueryEndpointsResp{
			Count: 1,
			Items: []Endpoint{
				*c.apiEndpointToQueryEndpoint(ep),
			},
		}, nil
	}

	var err error
	selector := req.Selector
	if req.Policy != nil {
		selector, err = c.getPolicySelector(
			req.Policy, req.RuleDirection, req.RuleIndex, req.RuleEntity, req.RuleNegatedSelector,
		)
		if err != nil {
			// When the policy requested from Manager can't be found, we should still return
			// a 200 OK response with an empty list of items instead of a 400 Bad Request.
			// It is still a valid request but we just can't find anything requested.
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				return &QueryEndpointsResp{
					Count: 0,
					Items: []Endpoint{},
				}, nil
			}
			return nil, err
		}
	}

	// skip searching of endpoint if endpointList != nil but length is 0
	if req.EndpointsList != nil && len(req.EndpointsList) == 0 {
		return &QueryEndpointsResp{
			Count: 0,
			Items: make([]Endpoint, 0),
		}, nil
	}

	epkeys, err := c.policyEndpointLabelHandler.QueryEndpoints(selector)
	if err != nil {
		return nil, err
	}

	// build regex pattern from the list of endpoints_name / endpoint aggregate_name
	// for a list of 100 endpoints, the resulting regexPattern will look like: ep1^|ep2^|ep3^|...|ep_100^
	var epListRegex *regexp.Regexp
	if req.EndpointsList != nil {
		epListRegex, err = utils.BuildSubstringRegexMatcher(req.EndpointsList)
		if err != nil {
			return nil, err
		}
	}

	var skippedNamespaces []string
	items := make([]Endpoint, 0, len(epkeys))
	for _, result := range epkeys {

		if req.Namespace != nil && !strings.EqualFold(result.(model.ResourceKey).Namespace, *req.Namespace) {
			skippedNamespaces = append(skippedNamespaces, result.(model.ResourceKey).Namespace)
			continue
		}
		// if endpointList is not nil --> epListRegex is not nil. Thus, we should check endpoint (result.String) to
		// be from the endpointList (by checking of epListRegex can match result.String())
		if epListRegex != nil && !epListRegex.MatchString(result.String()) {
			log.Debug("skipping endpoint: endpoint is not part of the search domain.")
			continue
		}

		ep := c.endpoints.GetEndpoint(result)
		if req.Node != "" && ep.GetNode() != req.Node {
			continue
		}
		if req.Unprotected && ep.IsProtected() {
			continue
		}
		if req.Unlabelled && ep.IsLabelled() {
			continue
		}

		// compare pod name if podNamePrefix is provided in the param set
		queryEP := *c.apiEndpointToQueryEndpoint(ep)
		if req.PodNamePrefix != nil {
			if !strings.HasPrefix(queryEP.Pod, *req.PodNamePrefix) {
				continue
			}
		}
		items = append(items, queryEP)

	}

	// log list of skipped ns if any for debugging purposes
	if log.IsLevelEnabled(log.DebugLevel) && len(skippedNamespaces) > 0 {
		log.Debugf("some endpoints are skipped due to namespace mismatch. requested:%s vs. actual:%v",
			*req.Namespace,
			strings.Join(skippedNamespaces, ","))
	}
	sortEndpoints(items, req.Sort)

	count := len(items)
	if req.Page != nil {
		fromIdx, toIdx, err := getPageFromToIdx(req.Page, count)
		if err != nil {
			return nil, err
		}
		items = items[fromIdx:toIdx]
	}

	return &QueryEndpointsResp{
		Count: count,
		Items: items,
	}, nil
}

func (c *cachedQuery) apiEndpointToQueryEndpoint(ep api.Endpoint) *Endpoint {
	pc := ep.GetPolicyCounts()
	res := ep.GetResource()
	e := &Endpoint{
		Kind:                     res.GetObjectKind().GroupVersionKind().Kind,
		Name:                     res.GetObjectMeta().GetName(),
		Namespace:                res.GetObjectMeta().GetNamespace(),
		Node:                     ep.GetNode(),
		NumGlobalNetworkPolicies: pc.NumGlobalNetworkPolicies,
		NumNetworkPolicies:       pc.NumNetworkPolicies,
		Labels:                   res.GetObjectMeta().GetLabels(),
	}

	switch rt := res.(type) {
	case *libapi.WorkloadEndpoint:
		e.Workload = rt.Spec.Workload
		e.Orchestrator = rt.Spec.Orchestrator
		e.Pod = rt.Spec.Pod
		e.InterfaceName = rt.Spec.InterfaceName
		e.IPNetworks = rt.Spec.IPNetworks
	case *apiv3.HostEndpoint:
		e.InterfaceName = rt.Spec.InterfaceName
		e.IPNetworks = rt.Spec.ExpectedIPs
	}

	return e
}

func (c *cachedQuery) runQueryPolicies(cxt context.Context, req QueryPoliciesReq) (*QueryPoliciesResp, error) {
	// If a policy was specified, just return that (if it exists).
	if req.Policy != nil {
		p := c.policies.GetPolicy(req.Policy)
		if p == nil {
			return nil, errors.ErrorResourceDoesNotExist{
				Identifier: req.Policy,
			}
		}

		resource, tier := utils.GetActualResourceAndTierFromCachedPolicyForRBAC(p)
		if !req.Permissions.IsAuthorized(resource, &tier, []rbac.Verb{rbac.VerbGet}) &&
			!req.Permissions.IsAuthorized(resource, &tier, []rbac.Verb{rbac.VerbList}) {
			return nil, errors.ErrorOperationNotSupported{
				Operation:  "Get or List",
				Identifier: req.Policy,
				Reason:     "User does not have required permissions to access this resource.",
			}
		}

		queryPolicy, err := c.apiPolicyToQueryPolicy(p, 0, req.FieldSelector)
		if err != nil {
			return nil, err
		}
		return &QueryPoliciesResp{
			Count: 1,
			Items: []Policy{
				*queryPolicy,
			},
		}, nil
	}

	var policySet set.Set[model.Key]

	// If an endpoint has been specified, determine the labels on the endpoint.
	if req.Endpoint != nil {
		// Endpoint is requested, get the labels and profiles and calculate the matching
		// policies.
		labels, profiles, err := c.getEndpointLabelsAndProfiles(req.Endpoint)
		if err != nil {
			return nil, err
		}
		policySet = c.queryPoliciesByLabel(labels, profiles, nil)
		log.WithField("policySet", policySet).Debug("Endpoint query")
	}

	// If a networkset has been specified, determine the labels on the networkset.
	if req.NetworkSet != nil {
		// NetworkSet is requested, get the labels and calculate the matching
		// policies.
		labels, profiles, err := c.getNetworkSetLabelsAndProfiles(req.NetworkSet)
		if err != nil {
			return nil, err
		}
		// Query policies for the rule selectors matching the networkset labels.
		policySet = c.queryPoliciesByLabelMatchingRule(labels, profiles, nil)
		log.WithField("policySet", policySet).Debug("NetworkSet query")
	}

	if len(req.Labels) > 0 {
		// Labels have been specified, calculate the matching policies. If we matched on endpoint
		// then only filter in the common elements.
		policySet = c.queryPoliciesByLabel(req.Labels, nil, policySet)
		log.WithField("policySet", policySet).Debug("Labels query")
	}

	var ordered []api.Tier
	if policySet == nil && len(req.Tier) > 0 {
		// If a tier has been specified, but no other query parameters then we can request just
		// the policies associated with a Tier as a minor finesse.
		for _, tierName := range req.Tier {
			if tierName != "" {
				tier := c.policies.GetTier(model.ResourceKey{
					Kind: apiv3.KindTier,
					Name: tierName,
				})
				if tier != nil {
					ordered = append(ordered, tier)
				}
			}
		}

	} else {
		// Get the required policies ordered by tier and policy Order parameter. If the policy set is
		// empty this will return all policies across all tiers.
		ordered = c.policies.GetOrderedPolicies(policySet)
	}
	log.WithField("ordered", ordered).Info("Pre filter list")

	// Compile a flat list of policies from the ordered set, filtering out based on the remaining
	// request parameters.
	items := make([]Policy, 0)
	for _, t := range ordered {
		op := t.GetOrderedPolicies()
		// If a tier is specified, filter out policies that are not in the requested tier.
		if len(req.Tier) > 0 && !slices.Contains(req.Tier, t.GetName()) {
			log.Info("Filter out unwanted tier")
			continue
		}

		for _, p := range op {
			if req.Unmatched && !p.IsUnmatched() {
				log.Info("Filter out matched policy")
				continue
			}

			// check authorization to the policy resource.
			resource, tier := utils.GetActualResourceAndTierFromCachedPolicyForRBAC(p)
			if req.Permissions.IsAuthorized(resource, &tier, []rbac.Verb{rbac.VerbList}) ||
				req.Permissions.IsAuthorized(resource, &tier, []rbac.Verb{rbac.VerbGet}) {
				queryPolicy, err := c.apiPolicyToQueryPolicy(p, len(items), req.FieldSelector)
				if err != nil {
					return nil, err
				}
				items = append(items, *queryPolicy)
			}
		}
	}

	if req.Sort != nil {
		// User has specified a different sort order, so re-order the policies according to the sort fields.
		sortPolicies(items, req.Sort)
	}

	// If we are paging results then return the required page-worths of results.
	count := len(items)
	if req.Page != nil {
		fromIdx, toIdx, err := getPageFromToIdx(req.Page, count)
		if err != nil {
			return nil, err
		}
		items = items[fromIdx:toIdx]
	}

	return &QueryPoliciesResp{
		Count: count,
		Items: items,
	}, nil
}

func (c *cachedQuery) apiPolicyToQueryPolicy(p api.Policy, idx int, fieldSelector map[string]bool) (*Policy, error) {
	ep := p.GetEndpointCounts()
	res := p.GetResource()

	creationTime := res.GetObjectMeta().GetCreationTimestamp()
	policy := Policy{
		UID:                    res.GetObjectMeta().GetUID(),
		Index:                  idx,
		Name:                   res.GetObjectMeta().GetName(),
		Namespace:              res.GetObjectMeta().GetNamespace(),
		Kind:                   res.GetObjectKind().GroupVersionKind().Kind,
		Tier:                   p.GetTier(),
		Annotations:            p.GetAnnotations(),
		NumHostEndpoints:       ep.NumHostEndpoints,
		NumWorkloadEndpoints:   ep.NumWorkloadEndpoints,
		IngressRules:           c.convertRules(p.GetRuleEndpointCounts().Ingress),
		EgressRules:            c.convertRules(p.GetRuleEndpointCounts().Egress),
		Order:                  p.GetOrder(),
		CreationTime:           &creationTime,
		StagedAction:           p.GetStagedAction(),
		Selector:               p.GetSelector(),
		NamespaceSelector:      p.GetNamespaceSelector(),
		ServiceAccountSelector: p.GetServiceAccountSelector(),
	}

	// Kubernetes network policies go through are converted to Calico network policies and in this process the UUID is getting converted
	// in libcalico-go/lib/backend/k8s/conversion/conversion.go:K8sNetworkPolicyToCalico
	// Since the UUID conversion is reversable, we run the ConvertUID here again to get the original UUID in the api resource.
	isKubeType, err := p.IsKubernetesType()
	if err != nil {
		return nil, err
	}
	if isKubeType {
		policy.UID, _ = conversion.ConvertUID(policy.UID)
	}
	if fieldSelector != nil {
		updatedPolicy := new(Policy)
		policyFields := reflect.TypeOf(policy)
		policyValues := reflect.ValueOf(policy)

		updatedPolicyFields := reflect.ValueOf(updatedPolicy).Elem()

		for i := 0; i < policyFields.NumField(); i++ {
			policyFieldName := policyFields.Field(i).Name
			fieldValue := policyValues.Field(i)

			if fieldSelector[strings.ToLower(policyFieldName)] {
				updatePolicyField := updatedPolicyFields.FieldByName(policyFields.Field(i).Name)
				switch reflect.TypeOf(fieldValue) {
				case reflect.TypeOf(reflect.Int):
					updatePolicyField.SetInt(fieldValue.Int())
				case reflect.TypeOf(reflect.String):
					updatePolicyField.Set(fieldValue)
				case reflect.TypeOf(reflect.Slice):
					updatePolicyField.SetBytes(fieldValue.Bytes())
				default:
					updatePolicyField.Set(fieldValue)
				}

			}
		}

		policy = *updatedPolicy
	}

	return &policy, nil
}

func (c *cachedQuery) convertRules(apiRules []api.RuleDirection) []RuleDirection {
	r := make([]RuleDirection, len(apiRules))
	for i, ar := range apiRules {
		r[i] = RuleDirection{
			Source: RuleEntity{
				NumWorkloadEndpoints: ar.Source.NumWorkloadEndpoints,
				NumHostEndpoints:     ar.Source.NumHostEndpoints,
			},
			Destination: RuleEntity{
				NumWorkloadEndpoints: ar.Destination.NumWorkloadEndpoints,
				NumHostEndpoints:     ar.Destination.NumHostEndpoints,
			},
		}
	}
	return r
}

func (c *cachedQuery) runQueryNodes(cxt context.Context, req QueryNodesReq) (*QueryNodesResp, error) {
	// If a policy was specified, just return that (if it exists).
	if req.Node != nil {
		n := c.nodes.GetNode(req.Node.(model.ResourceKey).Name)
		if n == nil {
			// Node does not exist.
			return nil, errors.ErrorResourceDoesNotExist{
				Identifier: req.Node,
			}
		}
		return &QueryNodesResp{
			Count: 1,
			Items: []Node{
				*c.apiNodeToQueryNode(n),
			},
		}, nil
	}

	// Sort the nodes by name (which is the only current option).
	nodes := c.nodes.GetNodes()

	items := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		items = append(items, *c.apiNodeToQueryNode(n))
	}
	sortNodes(items, req.Sort)

	// If we are paging the results then only keep the required page worth of results.
	count := len(nodes)
	if req.Page != nil {
		fromIdx, toIdx, err := getPageFromToIdx(req.Page, count)
		if err != nil {
			return nil, err
		}
		items = items[fromIdx:toIdx]
	}

	return &QueryNodesResp{
		Count: count,
		Items: items,
	}, nil
}

func (c *cachedQuery) runQueryLabels(cxt context.Context, req QueryLabelsReq) (*QueryLabelsResp, error) {
	var allLabels api.LabelsMapInterface
	var err error
	var warning []string
	switch req.ResourceType {
	case api.LabelsResourceTypePods:
		allLabels, warning, err = c.labelAggregator.GetPodsLabels(cxt, req.Permission, c.endpoints)
	case api.LabelsResourceTypeNamespaces:
		allLabels, warning, err = c.labelAggregator.GetNamespacesLabels(cxt, req.Permission)
	case api.LabelsResourceTypeServiceAccounts:
		allLabels, warning, err = c.labelAggregator.GetServiceAccountsLabels(cxt, req.Permission)
	case api.LabelsResourceTypeManagedClusters:
		allLabels, warning, err = c.labelAggregator.GetManagedClustersLabels(cxt, req.Permission)
	case api.LabelsResourceTypeGlobalThreatFeeds:
		allLabels, warning, err = c.labelAggregator.GetGlobalThreatfeedsLabels(cxt, req.Permission)
	// returns combined policy labels in one response
	case api.LabelsResourceTypeAllPolicies:
		allLabels, warning, err = c.labelAggregator.GetAllPoliciesLabels(cxt, req.Permission, c.policies)
	// returns combined networkset / globalnetworkset labels in one response
	case api.LabelsResourceTypeAllNetworkSets:
		allLabels, warning, err = c.labelAggregator.GetAllNetworkSetsLabels(cxt, req.Permission, c.networksets)
	}

	if err != nil {
		return nil, err
	}

	response := &QueryLabelsResp{
		ResourceTypeLabelMap: map[api.ResourceType][]LabelKeyValuePair{
			req.ResourceType: {},
		},
	}

	if allLabels != nil {
		labels := allLabels.GetLabels()

		// sort keys
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// sort values per key
		items := make([]LabelKeyValuePair, 0, len(keys))
		for _, k := range keys {
			values := labels[k].Slice()
			sort.Strings(values)

			items = append(items, LabelKeyValuePair{
				LabelKey:    k,
				LabelValues: values,
			})
		}
		response.ResourceTypeLabelMap[req.ResourceType] = items
	}

	if warning != nil {
		response.RBACWarnings = warning
	}

	return response, nil
}

func (c *cachedQuery) apiNodeToQueryNode(n api.Node) *Node {
	ep := n.GetEndpointCounts()
	node := &Node{
		Name:                 n.GetName(),
		NumHostEndpoints:     ep.NumHostEndpoints,
		NumWorkloadEndpoints: ep.NumWorkloadEndpoints,
	}

	r := n.GetResource()

	if r != nil {
		nr := r.(*libapi.Node)

		nodeAddresses := getNodeIPAddresses(nr)

		node.Addresses = nodeAddresses

		if nr.Spec.BGP != nil {

			if len(nr.Spec.BGP.IPv4Address) > 0 {
				node.BGPIPAddresses = append(node.BGPIPAddresses, nr.Spec.BGP.IPv4Address)
			}
			if len(nr.Spec.BGP.IPv6Address) > 0 {
				node.BGPIPAddresses = append(node.BGPIPAddresses, nr.Spec.BGP.IPv6Address)
			}
		}
	}

	return node
}

// getNodeIPAddresses returns the ip addresses defined in nr as a list of strings,  Empty list if nr.Addresses contains no addresses
func getNodeIPAddresses(nr *libapi.Node) []string {
	var addressStrings []string
	if len(nr.Spec.Addresses) > 0 {
		for _, nodeAddress := range nr.Spec.Addresses {
			addressStrings = append(addressStrings, nodeAddress.Address)
		}
	}
	return addressStrings
}

func (c *cachedQuery) getEndpointLabelsAndProfiles(key model.Key) (map[string]string, []string, error) {
	ep := c.endpoints.GetEndpoint(key)
	if ep == nil {
		return nil, nil, errors.ErrorResourceDoesNotExist{
			Identifier: key,
		}
	}

	// For host endpoints, return the labels unchanged.
	var labels map[string]string
	var profiles []string
	if hep, ok := ep.GetResource().(*apiv3.HostEndpoint); ok {
		labels = hep.Labels
		profiles = hep.Spec.Profiles
	} else {
		// For workload endpoints we need to convert the resource to ensure our labels are
		// cleaned of any potentially conflicting overridden values.
		epv1 := c.wepConverter.ConvertV3ToV1(&bapi.Update{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   key,
				Value: ep.GetResource(),
			},
		})
		// If the WEP has been filtered out, then the value may be nil.
		if epv1 == nil {
			return nil, nil, fmt.Errorf("endpoint %s is not valid: no policy is enforced on this endpoint", key)
		}
		wep := epv1.Value.(*model.WorkloadEndpoint)
		labels = wep.Labels
		profiles = wep.ProfileIDs
	}

	// If labels are nil, convert to an empty map.
	if labels == nil {
		labels = make(map[string]string)
	}

	return labels, profiles, nil
}

func (c *cachedQuery) getNetworkSetLabelsAndProfiles(key model.Key) (map[string]string, []string, error) {
	netset := c.networksets.GetNetworkSet(key)
	if netset == nil {
		return nil, nil, errors.ErrorResourceDoesNotExist{
			Identifier: key,
		}
	}

	// For global namespace, return the labels unchanged.
	var labels map[string]string
	var profiles []string

	if rKey, ok := key.(model.ResourceKey); ok {
		switch rKey.Kind {
		case apiv3.KindGlobalNetworkSet:
			labels = netset.GetObjectMeta().GetLabels()
		case apiv3.KindNetworkSet:
			// For namespaced networkset convert
			nsv1 := c.nsConverter.ConvertV3ToV1(&bapi.Update{
				UpdateType: bapi.UpdateTypeKVNew,
				KVPair: model.KVPair{
					Key:   key,
					Value: netset,
				},
			})
			ns := nsv1.Value.(*model.NetworkSet)
			labels = ns.Labels
			profiles = ns.ProfileIDs
		}
	}

	// If labels are nil, convert to an empty map.
	if labels == nil {
		labels = make(map[string]string)
	}

	return labels, profiles, nil
}

func (c *cachedQuery) queryPoliciesByLabel(labels map[string]string, profiles []string, filterIn set.Set[model.Key]) set.Set[model.Key] {
	policies := c.policyEndpointLabelHandler.QueryPolicies(labels, profiles)

	// Filter out the rule matches, and only filter in those in the supplied set (if supplied).
	results := set.New[model.Key]()
	for _, p := range policies {
		if filterIn != nil && !filterIn.Contains(p) {
			continue
		}
		results.Add(p)
	}
	log.WithField("NumResults", results.Len()).Info("Returning policies from label query")
	return results
}

func (c *cachedQuery) queryPoliciesByLabelMatchingRule(labels map[string]string, profiles []string, filterIn set.Set[model.Key]) set.Set[model.Key] {
	selectors := c.policyEndpointLabelHandler.QueryRuleSelectors(labels, profiles)

	// Convert the selectors to a set of the policy matches.
	results := set.New[model.Key]()

	// Iterate over all the selectors and join the sets
	for _, selector := range selectors {
		matching := c.policies.GetPolicyKeySetByRuleSelector(selector)
		matching.Iter(func(k model.Key) error {
			// Only filter policies in if they are in the supplied set (if supplied).
			if filterIn != nil && !filterIn.Contains(k) {
				return nil
			}

			results.Add(k)
			return nil
		})
	}
	log.WithField("NumResults", results.Len()).Info("Returning policies from label query against rule selectors")
	return results
}

func (c *cachedQuery) getPolicySelector(key model.Key, direction string, index int, entity string, negatedSelector bool) (string, error) {
	p := c.policies.GetPolicy(key)
	if p == nil {
		return "", errors.ErrorResourceDoesNotExist{
			Identifier: key,
		}
	}
	pr := p.GetResource()

	// We need to convert the policy to the v1 equivalent so that we get the correct converted
	// selector.
	var converted *bapi.Update
	switch pr.GetObjectKind().GroupVersionKind().Kind {
	case apiv3.KindNetworkPolicy:
		converted = c.npConverter.ConvertV3ToV1(&bapi.Update{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   key,
				Value: pr,
			},
		})
	case apiv3.KindGlobalNetworkPolicy:
		converted = c.gnpConverter.ConvertV3ToV1(&bapi.Update{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   key,
				Value: pr,
			},
		})
	case apiv3.KindStagedGlobalNetworkPolicy:
		converted = c.sgnpConverter.ConvertV3ToV1(&bapi.Update{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   key,
				Value: pr,
			},
		})
	case apiv3.KindStagedNetworkPolicy:
		converted = c.snpConverter.ConvertV3ToV1(&bapi.Update{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   key,
				Value: pr,
			},
		})
	case apiv3.KindStagedKubernetesNetworkPolicy:
		converted = c.sk8snpConverter.ConvertV3ToV1(&bapi.Update{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key:   key,
				Value: pr,
			},
		})
	}

	if converted == nil {
		return "", fmt.Errorf("unable to process resource: %s", key.String())
	}

	// Extract selector from the indexed rule. This safely handles bad input parameters since they
	// are provided over the API.
	pv1 := converted.Value.(*model.Policy)
	var rd []model.Rule
	switch direction {
	case "":
		return pv1.Selector, nil
	case RuleDirectionIngress:
		rd = pv1.InboundRules
	case RuleDirectionEgress:
		rd = pv1.OutboundRules
	default:
		return "", fmt.Errorf("rule direction not valid: %s", direction)
	}

	if len(rd) == 0 {
		return "", fmt.Errorf("there are no %s rules configured", direction)
	}

	if index < 0 || index >= len(rd) {
		return "", fmt.Errorf("rule index out of range, expected: 0-%d; requested index: %d", len(rd)-1, index)
	}

	r := rd[index]
	switch entity {
	case RuleEntitySource:
		switch negatedSelector {
		case false:
			return r.SrcSelector, nil
		case true:
			return r.NotSrcSelector, nil
		}
	case RuleEntityDestination:
		switch negatedSelector {
		case false:
			return r.DstSelector, nil
		case true:
			return r.NotDstSelector, nil
		}
	}
	return "", fmt.Errorf("rule entity not valid: %s", entity)
}

func getPageFromToIdx(p *Page, numItems int) (int, int, error) {
	// Perform simple policing of the page number and num per page. This should already be policed
	// by the HTTP server, but we'll police here to be safe.
	perPage := p.NumPerPage
	pageNum := p.PageNum
	if perPage <= 0 {
		return 0, 0, fmt.Errorf("number of results must be >0, requested number: %d", perPage)
	}
	if pageNum < 0 {
		return 0, 0, fmt.Errorf("page number should be an integer >=0, requested number: %d", pageNum)
	}

	// Check if the requested page number is out of range, we can only do this once we collate our results.
	// We don't treat this as an error since it could be a timing window where the number of results has
	// changed. Also, by returning a valid response the consumer is able to find out how any results there
	// are.
	maxPageNum := (numItems - 1) / perPage
	if pageNum > maxPageNum {
		return 0, 0, nil
	}

	// Calculate the from and to indexes from our page number and per page.
	fromIdx := p.PageNum * perPage
	toIdx := fromIdx + perPage

	// Ensure the toIdx does not exceed the length of the slice, capping at numItems if it does.
	if toIdx > numItems {
		toIdx = numItems
	}

	return fromIdx, toIdx, nil
}

// getDispachers returns a list of dispatcher v1, v3 resources. Used for keeping track of which
// dispatchers are generated for queries in this context.
func getDispachers(cq *cachedQuery) []dispatcherv1v3.Resource {
	dispatchers := []dispatcherv1v3.Resource{
		{
			// We need to convert the GNP for use with the policy sorter, and to get the
			// correct selectors for the labelhandler.
			Kind:      apiv3.KindGlobalNetworkPolicy,
			Converter: cq.gnpConverter,
		},
		{
			Kind:      model.KindKubernetesAdminNetworkPolicy,
			Converter: cq.gnpConverter,
		},
		{
			Kind:      model.KindKubernetesBaselineAdminNetworkPolicy,
			Converter: cq.gnpConverter,
		},
		{
			// Convert the KubernetesNetworkPolicy to NP.
			Kind:      model.KindKubernetesNetworkPolicy,
			Converter: cq.npConverter,
		},
		{
			// We need to convert the NP for use with the policy sorter, and to get the
			// correct selectors for the labelhandler.
			Kind:      apiv3.KindNetworkPolicy,
			Converter: cq.npConverter,
		},
		{
			// Convert the SGNP to GNP
			Kind:      apiv3.KindStagedGlobalNetworkPolicy,
			Converter: cq.sgnpConverter,
		},
		{
			// Convert the SNP to NP
			Kind:      apiv3.KindStagedNetworkPolicy,
			Converter: cq.snpConverter,
		},
		{
			// Convert the SK8SNP to NP
			Kind:      apiv3.KindStagedKubernetesNetworkPolicy,
			Converter: cq.sk8snpConverter,
		},
		{
			// We need to convert the Tier for use with the policy sorter.
			Kind: apiv3.KindTier,
			Converter: dispatcherv1v3.NewConverterFromSyncerUpdateProcessor(
				updateprocessors.NewTierUpdateProcessor(),
			),
		},
		{
			// We need to convert the WEP to get the corrected labels for the labelhandler.
			Kind:      libapi.KindWorkloadEndpoint,
			Converter: cq.wepConverter,
		},
		{
			Kind: apiv3.KindHostEndpoint,
		},
		{
			Kind: apiv3.KindProfile,
		},
		{
			// We don't need these to be converted.
			Kind: libapi.KindNode,
		},
		{
			Kind: apiv3.KindGlobalNetworkSet,
		},
		{
			Kind:      apiv3.KindNetworkSet,
			Converter: cq.nsConverter,
		},
	}

	return dispatchers
}
