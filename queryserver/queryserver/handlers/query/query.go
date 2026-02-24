// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.
package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/lma/pkg/timeutils"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/client"
	authhandler "github.com/projectcalico/calico/queryserver/queryserver/auth"
	"github.com/projectcalico/calico/queryserver/queryserver/config"
)

const (
	QueryEndpoint            = "endpoint"
	QueryLabelPrefix         = "label_"
	QuerySelector            = "selector"
	QueryPolicy              = "policy"
	QueryNode                = "node"
	QueryRuleDirection       = "ruleDirection"
	QueryRuleIndex           = "ruleIndex"
	QueryRuleEntity          = "ruleEntity"
	QueryRuleNegatedSelector = "ruleNegatedSelector"
	QueryPageNum             = "page"
	QueryNetworkSet          = "networkset"
	QueryNumPerPage          = "maxItems"
	QuerySortBy              = "sortBy"
	QueryReverseSort         = "reverseSort"
	QueryUnmatched           = "unmatched"
	QueryUnprotected         = "unprotected"
	QueryUnlabelled          = "unlabelled"
	QueryTier                = "tier"
	QueryFieldSelector       = "fields"

	AllResults     = "all"
	resultsPerPage = 100

	numURLSegmentsWithName = 3
)

var (
	ErrorPolicyMultiParm = errors.New("invalid query: specify only one of " + QueryEndpoint +
		" or " + QueryUnmatched)
	ErrorEndpointMultiParm = errors.New("invalid query: specify only one of " + QuerySelector +
		" or " + QueryPolicy + ", or specify one of " + QueryPolicy + " or " + QueryUnprotected)
	ErrorInvalidEndpointName = errors.New("invalid query: the endpoint name is not valid; it should be of the format " +
		"<HostEndpoint name> or <namespace>/<WorkloadEndpoint name>")
	ErrorInvalidNetworkSetName = errors.New("invalid query: the networkset name is not valid; it should be of the format " +
		"<GlobalNetworkSet name> or <namespace>/<NetworkSet name>")
	ErrorInvalidEndpointURL = errors.New("the URL does not contain a valid endpoint name; the final URL segments should " +
		"be of the format <HostEndpoint name> or <namespace>/<WorkloadEndpoint name>")
	ErrorInvalidPolicyURL = errors.New("the URL does not contain a valid policy name; the final URL segments should " +
		"be of the format <GlobalNetworkPolicy name> or <namespace>/<NetworkPolicy name>")
	ErrorInvalidNodeURL = errors.New("the URL does not contain a valid node name; the final URL segments should " +
		"be of the format <Node name>")
)

type Query interface {
	GetPolicy(w http.ResponseWriter, r *http.Request)
	LegacyPolicy(w http.ResponseWriter, r *http.Request)
	Policies(w http.ResponseWriter, r *http.Request)
	Node(w http.ResponseWriter, r *http.Request)
	Nodes(w http.ResponseWriter, r *http.Request)
	Endpoint(w http.ResponseWriter, r *http.Request)
	Endpoints(w http.ResponseWriter, r *http.Request)
	Summary(w http.ResponseWriter, r *http.Request)
	Metrics(w http.ResponseWriter, r *http.Request)
	Labels(api.ResourceType) http.HandlerFunc
}

func NewQuery(qi client.QueryInterface, cfg *config.Config, authz authhandler.Authorizer) Query {
	return &query{cfg: cfg, qi: qi, authorizer: authz}
}

type query struct {
	cfg        *config.Config
	qi         client.QueryInterface
	authorizer authhandler.Authorizer
}

func (q *query) Summary(w http.ResponseWriter, r *http.Request) {
	ts, err := q.getTimestamp(r)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}
	// /summary endpoint is called by Manager dashboard endpoints card.
	q.runQuery(w, r, client.QueryClusterReq{
		Timestamp:          ts,
		PrometheusEndpoint: q.cfg.PrometheusEndpoint,
		Token:              q.getToken(r),
	}, false)
}

func (q *query) Metrics(w http.ResponseWriter, r *http.Request) {
	// /metrics endpoint is called by Prometheus to fetch historical data.
	resp, err := q.qi.RunQuery(context.Background(), client.QueryClusterReq{})
	if err != nil {
		log.Warnf("failed to get metrics")
		return
	}

	clusterResp, ok := resp.(*client.QueryClusterResp)
	if !ok {
		log.Warnf("failed to convert metrics response type")
		return
	}

	hostEndpointsGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": ""}).Set(float64(clusterResp.NumHostEndpoints))
	hostEndpointsGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": "unlabeled"}).Set(float64(clusterResp.NumUnlabelledHostEndpoints))
	hostEndpointsGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": "unprotected"}).Set(float64(clusterResp.NumUnprotectedHostEndpoints))

	workloadEndpointsGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": ""}).Set(float64(clusterResp.NumWorkloadEndpoints))
	workloadEndpointsGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": "unlabeled"}).Set(float64(clusterResp.NumUnlabelledWorkloadEndpoints))
	workloadEndpointsGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": "unprotected"}).Set(float64(clusterResp.NumUnprotectedWorkloadEndpoints))
	workloadEndpointsGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": "failed"}).Set(float64(clusterResp.NumFailedWorkloadEndpoints))

	networkPolicyGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": ""}).Set(float64(clusterResp.NumNetworkPolicies))
	networkPolicyGauge.With(prometheus.Labels{"namespace": corev1.NamespaceAll, "type": "unmatched"}).Set(float64(clusterResp.NumUnmatchedNetworkPolicies))

	globalNetworkPolicyGauge.With(prometheus.Labels{"type": ""}).Set(float64(clusterResp.NumGlobalNetworkPolicies))
	globalNetworkPolicyGauge.With(prometheus.Labels{"type": "unmatched"}).Set(float64(clusterResp.NumUnmatchedGlobalNetworkPolicies))

	nodeGauge.With(prometheus.Labels{"type": ""}).Set(float64(clusterResp.NumNodes))
	nodeGauge.With(prometheus.Labels{"type": "no-endpoints"}).Set(float64(clusterResp.NumNodesWithNoEndpoints))
	nodeGauge.With(prometheus.Labels{"type": "no-host-endpoints"}).Set(float64(clusterResp.NumNodesWithNoHostEndpoints))
	nodeGauge.With(prometheus.Labels{"type": "no-workload-endpoints"}).Set(float64(clusterResp.NumNodesWithNoWorkloadEndpoints))

	for k, v := range clusterResp.NamespaceCounts {
		workloadEndpointsGauge.With(prometheus.Labels{"namespace": k, "type": ""}).Set(float64(v.NumWorkloadEndpoints))
		workloadEndpointsGauge.With(prometheus.Labels{"namespace": k, "type": "unlabeled"}).Set(float64(v.NumUnlabelledWorkloadEndpoints))
		workloadEndpointsGauge.With(prometheus.Labels{"namespace": k, "type": "unprotected"}).Set(float64(v.NumUnprotectedWorkloadEndpoints))
		workloadEndpointsGauge.With(prometheus.Labels{"namespace": k, "type": "failed"}).Set(float64(v.NumFailedWorkloadEndpoints))

		networkPolicyGauge.With(prometheus.Labels{"namespace": k, "type": ""}).Set(float64(v.NumNetworkPolicies))
		networkPolicyGauge.With(prometheus.Labels{"namespace": k, "type": "unmatched"}).Set(float64(v.NumUnmatchedNetworkPolicies))
	}

	prometheusHandler.ServeHTTP(w, r)
}

func (q *query) Endpoints(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}

	endpointsReq, err := parseEndpointsBody(bodyBytes)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}

	q.runQuery(w, r, *endpointsReq, false)
}

func parseEndpointsBody(bodyBytes []byte) (*client.QueryEndpointsReq, error) {
	body := client.QueryEndpointsReqBody{}

	if len(bodyBytes) > 0 {
		err := json.Unmarshal(bodyBytes, &body)
		if err != nil {
			log.Debugf("unmarshing failed: %s", err)
			return nil, err
		}
	}

	var policy model.Key
	if len(body.Policy) > 0 {
		policies, err := getPolicies(body.Policy)
		if err != nil {
			return nil, err
		}

		if (len(body.Policy) > 0 && (body.Selector != "" || body.Unprotected)) || len(body.Policy) > 1 {
			return nil, ErrorEndpointMultiParm
		}

		if len(policies) > 0 {
			policy = policies[0]
		}
	}

	var endpoint model.Key
	if body.Endpoint != "" {
		var ok bool
		endpoint, ok = getEndpointKeyFromCombinedName(body.Endpoint)
		if !ok {
			return nil, ErrorInvalidEndpointName
		}
	}

	request := client.QueryEndpointsReq{
		Policy:              policy,
		RuleDirection:       body.RuleDirection,
		RuleIndex:           body.RuleIndex,
		RuleEntity:          body.RuleEntity,
		RuleNegatedSelector: body.RuleNegatedSelector,
		Selector:            body.Selector,
		Endpoint:            endpoint,
		Unprotected:         body.Unprotected,
		EndpointsList:       body.EndpointsList,
		Node:                body.Node,
		Namespace:           body.Namespace,
		PodNamePrefix:       body.PodNamePrefix,
		Unlabelled:          body.Unlabelled,
		Page:                body.Page,
		Sort:                body.Sort,
	}

	return &request, nil
}

func (q *query) Endpoint(w http.ResponseWriter, r *http.Request) {
	urlParts := strings.SplitN(r.URL.Path, "/", numURLSegmentsWithName)
	if len(urlParts) != numURLSegmentsWithName {
		q.writeError(w, ErrorInvalidEndpointURL, http.StatusBadRequest)
		return
	}
	endpointString := urlParts[numURLSegmentsWithName-1]
	endpoint, ok := getEndpointKeyFromCombinedName(endpointString)
	if !ok {
		q.writeError(w, ErrorInvalidEndpointURL, http.StatusBadRequest)
		return
	}
	q.runQuery(w, r, client.QueryEndpointsReq{
		Endpoint: endpoint,
	}, true)
}

// Policies handles GET requets to /policies api
//
// list of parameters that can be passed in the url:
//   - endpoint (endpoints:<endpoint name>)
//   - labels (list of labels staritng with labels_ ex. labels_a)
//   - networkset (networkset:<ns name>)
//   - unmatched (unmatched:<true/false>)
//   - items in a page (maxItems:10)
//   - page number (page:0)
//   - list of tiers (tier=t1,t2,t3)
//   - sorting attribute (sortBy=<index/kind/name/namespace/tier/numHostEndpoints/numWorkloadEndpoints/numEndpoints>)
//   - sort ascending or descending (reverseSort=<true/false>)
//   - fields: list of fields to be returned in the resultset (if not passed all fields will be returned).
//     exmaple: fields=id,name,namespace (this will only return id, name, and namespace for each policy in the resultset)
func (q *query) Policies(w http.ResponseWriter, r *http.Request) {
	permissions, err := q.authorizer.PerformUserAuthorizationReview(r.Context(), authhandler.PolicyAuthReviewAttrList)
	if err != nil {
		q.writeError(w, err, http.StatusInternalServerError)
		return
	}

	endpoints, err := getEndpoints(r)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}
	networksets, err := getNetworkSets(r)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}

	unmatched := getBool(r, QueryUnmatched)
	if (unmatched && (len(endpoints) > 0 || len(networksets) > 0)) || len(endpoints) > 1 || len(networksets) > 1 {
		q.writeError(w, ErrorPolicyMultiParm, http.StatusBadRequest)
		return
	}

	page, err := q.getPage(r)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}

	fieldSelector := getPolicyFieldSelector(r)

	var endpoint model.Key
	if len(endpoints) > 0 {
		endpoint = endpoints[0]
	}
	var networkset model.Key
	if len(networksets) > 0 {
		networkset = networksets[0]
	}

	var tiers []string
	tiersString := r.URL.Query().Get(QueryTier)
	if tiersString != "" {
		tiers = strings.Split(tiersString, ",")
	}

	q.runQuery(w, r, client.QueryPoliciesReq{
		Tier:          tiers,
		Labels:        getLabels(r),
		Endpoint:      endpoint,
		NetworkSet:    networkset,
		Unmatched:     unmatched,
		Page:          page,
		Sort:          q.getSort(r),
		FieldSelector: fieldSelector,
		Permissions:   permissions,
	}, false)
}

// GetPolicy handles GET requests to /<kind>/<namespace>/<name> api to get a specific policy.
func (q *query) GetPolicy(w http.ResponseWriter, r *http.Request) {
	permissions, err := q.authorizer.PerformUserAuthorizationReview(r.Context(), authhandler.PolicyAuthReviewAttrList)
	if err != nil {
		q.writeError(w, err, http.StatusInternalServerError)
		return
	}

	key, err := getPolicyKeyFromIDString(r.URL.Path)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}

	log.WithField("policy", key).Info("Getting policy by kind/namespace/name")

	q.runQuery(w, r, client.QueryPoliciesReq{
		Policy:      key,
		Permissions: permissions,
	}, true)
}

// LegacyPolicy handles GET requests to /policies/{policy name} api for backward compatibility. Most callers
// should use GetPolicy instead.
func (q *query) LegacyPolicy(w http.ResponseWriter, r *http.Request) {
	permissions, err := q.authorizer.PerformUserAuthorizationReview(r.Context(), authhandler.PolicyAuthReviewAttrList)
	if err != nil {
		q.writeError(w, err, http.StatusInternalServerError)
		return
	}

	urlParts := strings.SplitN(r.URL.Path, "/", numURLSegmentsWithName)
	if len(urlParts) != numURLSegmentsWithName {
		q.writeError(w, ErrorInvalidPolicyURL, http.StatusBadRequest)
		return
	}
	policy, ok := getPolicyKeyFromName(urlParts[numURLSegmentsWithName-1])
	if !ok {
		q.writeError(w, ErrorInvalidPolicyURL, http.StatusBadRequest)
		return
	}
	q.runQuery(w, r, client.QueryPoliciesReq{
		Policy:      policy,
		Permissions: permissions,
	}, true)
}

func (q *query) Nodes(w http.ResponseWriter, r *http.Request) {
	page, err := q.getPage(r)
	if err != nil {
		q.writeError(w, err, http.StatusBadRequest)
		return
	}
	q.runQuery(w, r, client.QueryNodesReq{
		Page: page,
		Sort: q.getSort(r),
	}, false)
}

func (q *query) Node(w http.ResponseWriter, r *http.Request) {
	urlParts := strings.SplitN(r.URL.Path, "/", numURLSegmentsWithName)
	if len(urlParts) != numURLSegmentsWithName {
		q.writeError(w, ErrorInvalidNodeURL, http.StatusBadRequest)
		return
	}
	node, ok := getNodeKeyFromCombinedName(urlParts[numURLSegmentsWithName-1])
	if !ok {
		q.writeError(w, ErrorInvalidNodeURL, http.StatusBadRequest)
		return
	}
	q.runQuery(w, r, client.QueryNodesReq{
		Node: node,
	}, true)
}

func (q *query) Labels(resourceType api.ResourceType) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error

		permissions, err := q.authorizer.PerformUserAuthorizationReview(r.Context(), client.LabelsResourceAuthReviewAttrList)
		if err != nil {
			log.WithError(err).Debug("PerfomUserAuthorizationReview failed.")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		q.runQuery(w, r, client.QueryLabelsReq{
			ResourceType: resourceType,
			Permission:   permissions,
		}, false)
	}
}

// Convert a query parameter to a int. We are pretty relaxed about what we accept, using the
// default or min value when the requested value is bogus.
func getInt(r *http.Request, queryParm string, def int) int {
	qp := r.URL.Query().Get(queryParm)
	if len(qp) == 0 {
		return def
	}
	val, err := strconv.ParseInt(qp, 0, 0)
	if err != nil {
		return def
	}

	return int(val)
}

func getBool(r *http.Request, queryParm string) bool {
	qp := strings.ToLower(r.URL.Query().Get(queryParm))
	return qp == "true" || qp == "t" || qp == "1" || qp == "y" || qp == "yes"
}

func getLabels(r *http.Request) map[string]string {
	parms := r.URL.Query()
	labels := make(map[string]string)
	for k, pvs := range parms {
		if after, ok := strings.CutPrefix(k, QueryLabelPrefix); ok {
			labels[after] = pvs[0]
		}
	}
	return labels
}

func getEndpoints(r *http.Request) ([]model.Key, error) {
	eps := r.URL.Query()[QueryEndpoint]
	reps := make([]model.Key, 0, len(eps))
	for _, ep := range eps {
		rep, ok := getEndpointKeyFromCombinedName(ep)
		if !ok {
			return nil, ErrorInvalidEndpointName
		}
		reps = append(reps, rep)
	}
	return reps, nil
}

func getPolicies(pols []string) ([]model.Key, error) {
	rpols := make([]model.Key, 0, len(pols))
	for _, pol := range pols {
		// TODO: support legacy policy name format for backward compatibility?
		rpol, err := getPolicyKeyFromIDString(pol)
		if err != nil {
			return nil, err
		}
		rpols = append(rpols, rpol)
	}
	return rpols, nil
}

func getNetworkSets(r *http.Request) ([]model.Key, error) {
	netsets := r.URL.Query()[QueryNetworkSet]
	rnetsets := make([]model.Key, 0, len(netsets))
	for _, netset := range netsets {
		rnetset, ok := getNetworkSetKeyFromCombinedName(netset)
		if !ok {
			return nil, ErrorInvalidNetworkSetName
		}
		rnetsets = append(rnetsets, rnetset)
	}
	return rnetsets, nil
}

func getNameAndNamespaceFromCombinedName(combined string) ([]string, bool) {
	parts := strings.Split(combined, "/")
	if slices.Contains(parts, "") {
		return nil, false
	}
	if len(parts) != 1 && len(parts) != 2 {
		return nil, false
	}
	return parts, true
}

func getPolicyKeyFromIDString(combined string) (model.Key, error) {
	// Trim leading slash if present.
	combined = strings.TrimPrefix(combined, "/")

	logCxt := log.WithField("name", combined)
	logCxt.Info("Extracting policy key from combined name")

	// Split the combined name into parts. This is either:
	// - kind/name
	// - kind/namespace/name
	parts := strings.Split(combined, "/")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid policy name format, expected kind/name or kind/namespace/name")
	}

	kind, err := parseKind(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to determine kind for request: %s", err)
	}

	switch len(parts) {
	case 2:
		return model.ResourceKey{
			Kind: kind,
			Name: parts[1],
		}, nil
	case 3:
		return model.ResourceKey{
			Kind:      kind,
			Namespace: parts[1],
			Name:      parts[2],
		}, nil
	}
	return nil, fmt.Errorf("invalid policy name format, expected kind/name or kind/namespace/name")
}

// parseKind converts a string representation of a policy kind as seen on a URL to the corresponding model.Key kind value.
func parseKind(kindStr string) (string, error) {
	switch strings.ToLower(kindStr) {
	case "networkpolicy":
		return apiv3.KindNetworkPolicy, nil
	case "globalnetworkpolicy":
		return apiv3.KindGlobalNetworkPolicy, nil
	case "kubernetesnetworkpolicy":
		return model.KindKubernetesNetworkPolicy, nil
	case "stagednetworkpolicy":
		return apiv3.KindStagedNetworkPolicy, nil
	case "stagedglobalnetworkpolicy":
		return apiv3.KindStagedGlobalNetworkPolicy, nil
	case "stagedkubernetesnetworkpolicy":
		return apiv3.KindStagedKubernetesNetworkPolicy, nil
	case "adminnetworkpolicy":
		return model.KindKubernetesAdminNetworkPolicy, nil
	case "baselineadminnetworkpolicy":
		return model.KindKubernetesBaselineAdminNetworkPolicy, nil
	default:
		return "", fmt.Errorf("unknown policy kind: %s", kindStr)
	}
}

// getPolicyKeyFromName extracts a policy key from a legacy name string.
func getPolicyKeyFromName(combined string) (model.Key, bool) {
	// Split the combined name into parts. This is either:
	// - <name>
	// - <namespace>/<name-with-prefix>
	parts := strings.Split(combined, "/")
	if len(parts) < 1 || len(parts) > 2 {
		return nil, false
	}

	switch len(parts) {
	case 1:
		return model.ResourceKey{
			Kind: apiv3.KindGlobalNetworkPolicy,
			Name: parts[0],
		}, true
	case 2:
		return model.ResourceKey{
			Kind:      apiv3.KindNetworkPolicy,
			Namespace: parts[0],
			Name:      parts[1],
		}, true
	}
	return nil, false
}

func getEndpointKeyFromCombinedName(combined string) (model.Key, bool) {
	parts, ok := getNameAndNamespaceFromCombinedName(combined)
	if !ok {
		return nil, false
	}
	switch len(parts) {
	case 1:
		return model.ResourceKey{
			Kind: apiv3.KindHostEndpoint,
			Name: parts[0],
		}, true
	case 2:
		return model.ResourceKey{
			Kind:      internalapi.KindWorkloadEndpoint,
			Namespace: parts[0],
			Name:      parts[1],
		}, true
	}
	return nil, false
}

func getNodeKeyFromCombinedName(combined string) (model.Key, bool) {
	parts, ok := getNameAndNamespaceFromCombinedName(combined)
	if !ok || len(parts) != 1 {
		return nil, false
	}
	return model.ResourceKey{
		Kind: internalapi.KindNode,
		Name: parts[0],
	}, true
}

func getNetworkSetKeyFromCombinedName(combined string) (model.Key, bool) {
	parts, ok := getNameAndNamespaceFromCombinedName(combined)
	if !ok {
		return nil, false
	} else if len(parts) == 2 {
		return model.ResourceKey{
			Kind:      apiv3.KindNetworkSet,
			Name:      parts[1],
			Namespace: parts[0],
		}, true
	} else if len(parts) == 1 {
		return model.ResourceKey{
			Kind: apiv3.KindGlobalNetworkSet,
			Name: parts[0],
		}, true
	}

	log.WithField("name", combined).Info("Extracting policy key from combined name failed with unknown name format")
	return nil, false
}

// getPolicyFieldSelector parses the query params of pattern fields=f1,f2,f3,... and return the values in a map.
// if fields is not set in the query params, all fields will be returned in the result set and if field= (field is set to empty list)
// none of the fields will be returned in the result set.
//
// returns a map[string]bool including the requested fields.
func getPolicyFieldSelector(r *http.Request) map[string]bool {
	if r.URL.Query().Has(QueryFieldSelector) {
		fieldSelector := r.URL.Query().Get(QueryFieldSelector)
		fields := strings.Split(fieldSelector, ",")
		fieldMap := make(map[string]bool)
		for _, f := range fields {
			if len(strings.TrimSpace(f)) > 0 {
				fieldMap[strings.ToLower(f)] = true
			}
		}

		return fieldMap
	}
	return nil
}

func (q *query) runQuery(w http.ResponseWriter, r *http.Request, req any, exact bool) {
	resp, err := q.qi.RunQuery(context.Background(), req)
	if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok && exact {
		// This is an exact get and the resource does not exist. Return a 404 not found.
		q.writeError(w, err, http.StatusNotFound)
		return
	} else if _, ok := err.(*httputils.HttpStatusError); ok {
		q.writeError(w, err, err.(*httputils.HttpStatusError).Status)
	} else if err != nil {
		// All other errors return as a 400 Bad request.
		q.writeError(w, err, http.StatusBadRequest)
		return
	}

	js, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		q.writeError(w, err, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(js)
	_, _ = w.Write([]byte{'\n'})
}

func (q *query) writeError(w http.ResponseWriter, err error, code int) {
	http.Error(w, "Error: "+err.Error(), code)
}

func (q *query) getPage(r *http.Request) (*client.Page, error) {
	if r.URL.Query().Get(QueryPageNum) == AllResults {
		return nil, nil
	}
	// We perform as much sanity checking as we can without performing an actual query.
	pageNum := getInt(r, QueryPageNum, 0)
	numPerPage := getInt(r, QueryNumPerPage, resultsPerPage)

	if pageNum < 0 {
		return nil, fmt.Errorf("page number should be an integer >=0, requested number: %d", pageNum)
	}
	if numPerPage <= 0 {
		return nil, fmt.Errorf("number of results must be >0, requested number: %d", numPerPage)
	}

	return &client.Page{
		PageNum:    pageNum,
		NumPerPage: numPerPage,
	}, nil
}

func (q *query) getSort(r *http.Request) *client.Sort {
	sortBy := r.URL.Query()[QuerySortBy]
	reverse := getBool(r, QueryReverseSort)
	if len(sortBy) == 0 && !reverse {
		return nil
	}
	return &client.Sort{
		SortBy:  sortBy,
		Reverse: reverse,
	}
}

func (q *query) getTimestamp(r *http.Request) (*time.Time, error) {
	// "from" and "to" query string parameters are sent when /summary endpoint gets called.
	// As the summary data reflects a single data point, we have decided to use the end (to)
	// timestamp to fetch current (in-memory) or historical (time-series data store) data.
	qsTo := r.URL.Query().Get("to")
	if qsTo == "" {
		err := fmt.Errorf("failed to get timestamp from query parameter")
		log.Warn(err.Error())
		return nil, err
	}

	now := time.Now()
	to, _, err := timeutils.ParseTime(now, &qsTo)
	if err != nil || to == nil {
		log.WithError(err).Warnf("failed to parse datetime from query parameter to=%s", qsTo)
		return nil, err
	}

	// if to equals now, reset time range to nil to get data from memory.
	if to.Equal(now) {
		log.Debug("set time range to nil when to == now")
		return nil, nil
	}
	return to, nil
}

func (q *query) getToken(r *http.Request) string {
	if _, err := jws.ParseJWTFromRequest(r); err != nil {
		log.WithError(err).Debug("failed to parse token from request header")
		return ""
	}

	authHeader := r.Header.Get("Authorization")
	// Strip the "Bearer " part of the token.
	return strings.TrimSpace(authHeader[7:])
}
