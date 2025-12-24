// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package policy

import (
	authzv1 "k8s.io/api/authorization/v1"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/handler"
)

const (
	ReadLogPath  = "/policy_activity/logs"
	AggsPath     = "/policy_activity/logs/aggregation"
	WriteLogPath = "/policy_activity/logs/bulk"
)

type policy struct {
	logs handler.GenericHandler[v1.PolicyActivity, v1.PolicyActivityParams, v1.PolicyActivity, v1.PolicyActivityParams]
}

func New(b bapi.PolicyBackend) *policy {
	return &policy{
		logs: handler.NewCompositeHandler(b.Create, b.List, b.Aggregations),
	}
}

func (h policy) APIS() []handler.API {
	return []handler.API{
		{
			Method:          "POST",
			URL:             WriteLogPath,
			Handler:         h.logs.Create(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Create, Group: handler.APIGroup, Resource: "policyactivity"},
		},
		{
			Method:          "POST",
			URL:             ReadLogPath,
			Handler:         h.logs.List(),
			AuthzAttributes: &authzv1.ResourceAttributes{Verb: handler.Get, Group: handler.APIGroup, Resource: "policyactivity"},
		},
	}
}
