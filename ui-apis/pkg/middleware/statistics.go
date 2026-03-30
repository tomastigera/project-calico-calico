// Copyright (c) 2025 Tigera, Inc. All rights reserved.
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"google.golang.org/grpc/metadata"

	goldmane "github.com/projectcalico/calico/goldmane/pkg/client"
	"github.com/projectcalico/calico/goldmane/proto"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

type List struct {
	Total int                  `json:"total"`
	Items []StatisticsResponse `json:"items"`
}

type StatisticsResponse struct {
	Policy *PolicyHit `json:"policy"`

	GroupBy   string `json:"groupBy"`
	Type      string `json:"type"`
	Direction string `json:"direction"`

	AllowedIn  []int64 `json:"allowedIn"`
	AllowedOut []int64 `json:"allowedOut"`
	DeniedIn   []int64 `json:"deniedIn"`
	DeniedOut  []int64 `json:"deniedOut"`
	PassedIn   []int64 `json:"passedIn"`
	PassedOut  []int64 `json:"passedOut"`

	X []int64 `json:"x"`
}

type PolicyHit struct {
	Kind        string     `json:"kind"`
	Namespace   string     `json:"namespace"`
	Name        string     `json:"name"`
	Tier        string     `json:"tier"`
	Action      string     `json:"action"`
	PolicyIndex int64      `json:"policyIndex"`
	RuleIndex   int64      `json:"ruleIndex"`
	Trigger     *PolicyHit `json:"trigger"`
}

const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func NewStatsHandler(c goldmane.StatisticsClient) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract parameters from the request and convert them to the Goldmane API format.
		params, err := buildParams(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Load our serviceaccount token and add it to the request context. This is necessary so that
		// we can authorize with Voltron. Requests made with a Kubernetes client do this automatically,
		// but since we're using a gRPC client we need to do this ourselves.
		token, err := os.ReadFile(tokenPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Add the cluster ID to the gRPC request context. This is necessary to ensure the
		// request is routed to the correct managed cluster by Voltron.
		cluster := MaybeParseClusterNameFromRequest(r)
		meta := metadata.New(map[string]string{
			// Add cluster header.
			lmak8s.XClusterIDHeader: cluster,

			// Add authorization token for access to Voltron. Voltron checks our own permissions
			// to use the tunnel before forwarding the request.
			"Authorization": fmt.Sprintf("Bearer %s", token),
		})
		ctx := metadata.NewOutgoingContext(context.Background(), meta)

		// Call Goldmane.
		stats, err := c.List(ctx, params)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Convert the Goldmane API response to the API response format and write it to the response.
		response := List{Total: 0}
		for _, p := range stats {
			stat := protoToStats(p)
			response.Items = append(response.Items, stat)
			response.Total++
		}
		if err = json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func protoToStats(s *proto.StatisticsResult) StatisticsResponse {
	return StatisticsResponse{
		Policy:     protoToPolicyHit(s.Policy),
		GroupBy:    s.GroupBy.String(),
		Type:       s.Type.String(),
		Direction:  s.Direction.String(),
		AllowedIn:  s.AllowedIn,
		AllowedOut: s.AllowedOut,
		DeniedIn:   s.DeniedIn,
		DeniedOut:  s.DeniedOut,
		PassedIn:   s.PassedIn,
		PassedOut:  s.PassedOut,
		X:          s.X,
	}
}

func protoToPolicyHit(p *proto.PolicyHit) *PolicyHit {
	if p == nil {
		return nil
	}

	return &PolicyHit{
		Kind:        p.Kind.String(),
		Namespace:   p.Namespace,
		Name:        p.Name,
		Tier:        p.Tier,
		Action:      strings.ToLower(p.Action.String()),
		PolicyIndex: p.PolicyIndex,
		RuleIndex:   p.RuleIndex,
		Trigger:     protoToPolicyHit(p.Trigger),
	}
}

func buildParams(r *http.Request) (*proto.StatisticsRequest, error) {
	// Extract parameters from the request and convert them to the Goldmane API format.
	urlParams := r.URL.Query()
	params := &proto.StatisticsRequest{}
	var err error
	if v, ok := urlParams["startTimeGt"]; ok {
		params.StartTimeGte, err = strconv.ParseInt(v[0], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if v, ok := urlParams["startTimeLt"]; ok {
		params.StartTimeLt, err = strconv.ParseInt(v[0], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if v, ok := urlParams["type"]; ok {
		params.Type = proto.StatisticType(proto.StatisticType_value[v[0]])
	}
	if v, ok := urlParams["groupBy"]; ok {
		params.GroupBy = proto.StatisticsGroupBy(proto.StatisticsGroupBy_value[v[0]])
	}
	if v, ok := urlParams["timeSeries"]; ok {
		params.TimeSeries, err = strconv.ParseBool(v[0])
		if err != nil {
			return nil, err
		}
	}

	// Extract the policy hit parameters.
	hit := proto.PolicyMatch{}
	match := false
	if v, ok := urlParams["kind"]; ok {
		match = true
		hit.Kind = proto.PolicyKind(proto.PolicyKind_value[v[0]])
	}
	if v, ok := urlParams["namespace"]; ok {
		match = true
		hit.Namespace = &proto.StringMatch{Value: v[0], Type: proto.MatchType_Exact}
	}
	if v, ok := urlParams["name"]; ok {
		match = true
		hit.Name = &proto.StringMatch{Value: v[0], Type: proto.MatchType_Exact}
	}
	if v, ok := urlParams["tier"]; ok {
		match = true
		hit.Tier = &proto.StringMatch{Value: v[0], Type: proto.MatchType_Exact}
	}
	if v, ok := urlParams["action"]; ok {
		match = true
		switch v[0] {
		case "allow":
			hit.Action = proto.Action_Allow
		case "deny":
			hit.Action = proto.Action_Deny
		case "pass":
			hit.Action = proto.Action_Pass
		}
	}
	if match {
		params.PolicyMatch = &hit
	}
	return params, nil
}
