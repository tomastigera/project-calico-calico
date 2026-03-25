// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
package client

import (
	"context"
	"fmt"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/queryserver/queryserver/auth"
)

// TODO (rlb):  These data types are basically focussed on the requirements of the web server
// and calicoq.  However this means we have already selected what data we want to return to
// the client application.  This feels wrong.  We should probably just return a full copy of
// the data associated with each resource and let the app display it however it wants. Not
// worrying about this for now, but may prove important for AAPIS integration.

// QueryInterface is the (very generic) interface used to perform simple synchronous queries
// against the cached data.  It takes one of the Query*Req structures as the query request
// and returns the corresponding Query*Resp structure, or an error.
type QueryInterface interface {
	RunQuery(ctx context.Context, req any) (any, error)
}

type QueryClusterReq struct {
	// timestamp for the historical summary data point
	Timestamp *time.Time
	// prometheus endpoint to retrieve historical data
	PrometheusEndpoint string
	Token              string
}

type QueryClusterResp struct {
	NumGlobalNetworkPolicies          int                                    `json:"numGlobalNetworkPolicies"`
	NumNetworkPolicies                int                                    `json:"numNetworkPolicies"`
	NumHostEndpoints                  int                                    `json:"numHostEndpoints"`
	NumWorkloadEndpoints              int                                    `json:"numWorkloadEndpoints"`
	NumUnmatchedGlobalNetworkPolicies int                                    `json:"numUnmatchedGlobalNetworkPolicies"`
	NumUnmatchedNetworkPolicies       int                                    `json:"numUnmatchedNetworkPolicies"`
	NumUnlabelledHostEndpoints        int                                    `json:"numUnlabelledHostEndpoints"`
	NumUnlabelledWorkloadEndpoints    int                                    `json:"numUnlabelledWorkloadEndpoints"`
	NumUnprotectedHostEndpoints       int                                    `json:"numUnprotectedHostEndpoints"`
	NumUnprotectedWorkloadEndpoints   int                                    `json:"numUnprotectedWorkloadEndpoints"`
	NumFailedWorkloadEndpoints        int                                    `json:"numFailedWorkloadEndpoints"`
	NumNodes                          int                                    `json:"numNodes"`
	NumNodesWithNoEndpoints           int                                    `json:"numNodesWithNoEndpoints"`
	NumNodesWithNoHostEndpoints       int                                    `json:"numNodesWithNoHostEndpoints"`
	NumNodesWithNoWorkloadEndpoints   int                                    `json:"numNodesWithNoWorkloadEndpoints"`
	NamespaceCounts                   map[string]QueryClusterNamespaceCounts `json:"namespaceCounts"`
}

type QueryClusterNamespaceCounts struct {
	NumNetworkPolicies              int `json:"numNetworkPolicies"`
	NumWorkloadEndpoints            int `json:"numWorkloadEndpoints"`
	NumUnmatchedNetworkPolicies     int `json:"numUnmatchedNetworkPolicies"`
	NumUnlabelledWorkloadEndpoints  int `json:"numUnlabelledWorkloadEndpoints"`
	NumUnprotectedWorkloadEndpoints int `json:"numUnprotectedWorkloadEndpoints"`
	NumFailedWorkloadEndpoints      int `json:"numFailedWorkloadEndpoints"`
}

type QueryNodesReq struct {
	// Queries
	Node model.Key

	// Filters
	Page *Page
	Sort *Sort
}

type QueryNodesResp struct {
	Count int    `json:"count"`
	Items []Node `json:"items"`
}

type Node struct {
	Name                 string   `json:"name"`
	BGPIPAddresses       []string `json:"bgpIPAddresses"`
	Addresses            []string `json:"addresses"`
	NumHostEndpoints     int      `json:"numHostEndpoints"`
	NumWorkloadEndpoints int      `json:"numWorkloadEndpoints"`
}

type QueryPoliciesReq struct {
	// Queries (select one)
	Endpoint   model.Key
	Labels     map[string]string
	Policy     model.Key
	NetworkSet model.Key

	// Filters
	Unmatched     bool
	Tier          []string
	Page          *Page
	Sort          *Sort
	FieldSelector map[string]bool

	// Authorization
	Permissions auth.Permission

	// Time range for policy activity enrichment (optional)
	From *time.Time
	To   *time.Time
}

type QueryPoliciesResp struct {
	Count int      `json:"count"`
	Items []Policy `json:"items"`
}

// The names of the members in the Policy struct should match their corresponding json name for field selection feature to work for the /policies API.
type Policy struct {
	UID                    types.UID         `json:"uid,omitempty"`
	Index                  int               `json:"index,omitempty"`
	Kind                   string            `json:"kind,omitempty"`
	Name                   string            `json:"name,omitempty"`
	Namespace              string            `json:"namespace,omitempty"`
	Tier                   string            `json:"tier,omitempty"`
	Annotations            map[string]string `json:"annotations,omitempty"`
	NumHostEndpoints       int               `json:"numHostEndpoints,omitempty"`
	NumWorkloadEndpoints   int               `json:"numWorkloadEndpoints,omitempty"`
	IngressRules           []RuleInfo        `json:"ingressRules,omitempty"`
	EgressRules            []RuleInfo        `json:"egressRules,omitempty"`
	Order                  *float64          `json:"order,omitempty"`
	CreationTime           *v1.Time          `json:"creationTime,omitempty"`
	StagedAction           *v3.StagedAction  `json:"stagedAction,omitempty" validate:"omitempty"`
	Selector               *string           `json:"selector,omitempty" validate:"omitempty"`
	NamespaceSelector      *string           `json:"namespaceSelector,omitempty" validate:"omitempty"`
	ServiceAccountSelector *string           `json:"serviceAccountSelector,omitempty" validate:"omitempty"`
	// LastEvaluated is the most recent time any rule in this policy was evaluated
	// by the dataplane at the policy's current Generation. It is nil when the
	// policy has not yet been evaluated at this generation, even if it was evaluated
	// at a previous generation. Always serialized without omitempty so callers can
	// distinguish "no activity at this generation" (null) from "field not requested".
	LastEvaluated *time.Time `json:"lastEvaluated"`
	// LastEvaluatedAnyGeneration is the most recent time any rule in this policy was
	// evaluated by the dataplane, across all generations. It is nil only when the
	// policy has never been evaluated. Always serialized without omitempty so callers
	// can distinguish "never evaluated" (null) from "field not requested".
	LastEvaluatedAnyGeneration *time.Time `json:"lastEvaluatedAnyGeneration"`
	Generation                 int64      `json:"generation,omitempty"`
}

type RuleInfo struct {
	Source        RuleEntity `json:"source"`
	Destination   RuleEntity `json:"destination"`
	LastEvaluated *time.Time `json:"lastEvaluated"`
	// ImplicitDenyLastEvaluated is the most recent time the implicit deny
	// for this direction was evaluated at the current generation. This is
	// populated from Linseed's "implicit_deny" sentinel rule index.
	ImplicitDenyLastEvaluated *time.Time `json:"implicitDenyLastEvaluated"`
	// UnknownLastEvaluated is the most recent time an unknown rule for this
	// direction was evaluated at the current generation. This is populated
	// from Linseed's "unknown" sentinel rule index.
	UnknownLastEvaluated *time.Time `json:"unknownLastEvaluated"`
}

type RuleEntity struct {
	NumHostEndpoints     int `json:"numHostEndpoints"`
	NumWorkloadEndpoints int `json:"numWorkloadEndpoints"`
}

// QueryEndpointsReqBody is used to UnMarshal endpoints request body.
// if any member is added / removed / changed in this struct, also update:
// 1. QueryEndpointsReq struct defined below
// 2. getQueryServerRequestParams in ui-apis/pkg/middleware/endpoints_aggregation.go as needed.
// 3. update tests and test function calculateQueryBody in queryserver/tests/fv/query_e2e_test.go
type QueryEndpointsReqBody struct {
	// Queries
	Policy              []string `json:"policy,omitempty" validate:"omitempty"`
	RuleDirection       string   `json:"ruleDirection,omitempty" validate:"omitempty"`
	RuleIndex           int      `json:"ruleIndex,omitempty" validate:"omitempty"`
	RuleEntity          string   `json:"ruleEntity,omitempty" validate:"omitempty"`
	RuleNegatedSelector bool     `json:"ruleNegatedSelector,omitempty" validate:"omitempty"`
	Selector            string   `json:"selector,omitempty" validate:"omitempty"`
	Endpoint            string   `json:"endpoint,omitempty" validate:"omitempty"`
	Unprotected         bool     `json:"unprotected,omitempty" validate:"omitempty"`

	// Filters
	EndpointsList []string `json:"endpointsList"` // we need to identify when this field is passed as empty list or is not passed
	Node          string   `json:"node,omitempty" validate:"omitempty"`
	Namespace     *string  `json:"namespace,omitempty" validate:"omitempty"`
	PodNamePrefix *string  `json:"podNamePrefix,omitempty" validate:"omitempty"`
	Unlabelled    bool     `json:"unlabelled,omitempty"  validate:"omitempty"`
	Page          *Page    `json:"page,omitempty" validate:"omitempty"`
	Sort          *Sort    `json:"sort,omitempty" validate:"omitempty"`
}

// QueryEndpointsReq is the internal struct. Endpoints request.body --> QueryEndpointsReqBody --> QueryEndpointReq
// if any member is added / removed / changed in this struct, also update:
// 1. QueryEndpointsRequestBody struct defined above
// 2. getQueryServerRequestParams in ui-apis/pkg/middleware/endpoints_aggregation.go as needed.
// 3. update tests and test function calculateQueryBody in queryserver/tests/fv/query_e2e_test.go
type QueryEndpointsReq struct {
	// Queries
	Policy              model.Key
	RuleDirection       string
	RuleIndex           int
	RuleEntity          string
	RuleNegatedSelector bool
	Selector            string
	Endpoint            model.Key
	Unprotected         bool

	// Filters
	EndpointsList []string
	Node          string
	Namespace     *string
	PodNamePrefix *string
	Unlabelled    bool
	Page          *Page
	Sort          *Sort
}

const (
	RuleDirectionIngress  = "ingress"
	RuleDirectionEgress   = "egress"
	RuleEntitySource      = "source"
	RuleEntityDestination = "destination"
)

type QueryEndpointsResp struct {
	Count int        `json:"count"`
	Items []Endpoint `json:"items"`
}

type EndpointCount struct {
	NumHostEndpoints     int `json:"numHostEndpoints"`
	NumWorkloadEndpoints int `json:"numWorkloadEndpoints"`
}

type PolicyCount struct {
	NumGlobalNetworkPolicies int `json:"numGlobalNetworkPolicies"`
	NumNetworkPolicies       int `json:"numNetworkPolicies"`
}

type Endpoint struct {
	Kind                     string            `json:"kind"`
	Name                     string            `json:"name"`
	Namespace                string            `json:"namespace,omitempty"`
	Node                     string            `json:"node"`
	Workload                 string            `json:"workload"`
	Orchestrator             string            `json:"orchestrator"`
	Pod                      string            `json:"pod"`
	InterfaceName            string            `json:"interfaceName"`
	IPNetworks               []string          `json:"ipNetworks"`
	Labels                   map[string]string `json:"labels"`
	NumGlobalNetworkPolicies int               `json:"numGlobalNetworkPolicies"`
	NumNetworkPolicies       int               `json:"numNetworkPolicies"`
}

type Page struct {
	PageNum    int `json:"pageNum,omitempty" validate:"gte=0,omitempty"`
	NumPerPage int `json:"numPerPage,omitempty" validate:"gt=0,omitempty"`
}

type Sort struct {
	SortBy  []string `json:"sortBy,omitempty" validate:"omitempty"`
	Reverse bool     `json:"reverse,omitempty" validate:"omitempty"`
}

// policyActivityKey returns the map key for a policy identified by kind, namespace, and name.
// Generation is not included because a single query never contains duplicate policies —
// the key only needs to correlate request items with response items.
func policyActivityKey(kind, namespace, name string) string {
	return fmt.Sprintf("%s/%s/%s", kind, namespace, name)
}

// ruleActivityKey returns the map key for a rule identified by direction and index.
// The index is a string because Linseed may return non-integer sentinels such as
// "implicit_deny" or "unknown". These are surfaced via the ImplicitDenyLastEvaluated
// and UnknownLastEvaluated fields on RuleInfo.
func ruleActivityKey(direction string, index string) string {
	return direction + "/" + index
}
