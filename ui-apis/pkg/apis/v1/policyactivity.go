// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package v1

import "time"

// PolicyActivityResponse is the JSON response for the /policies/activities endpoint.
type PolicyActivityResponse struct {
	Items []PolicyActivityItem `json:"items"`
}

// PolicyActivity holds the activity timestamps for a policy.
type PolicyActivity struct {
	LastEvaluated              *time.Time `json:"lastEvaluated"`
	LastEvaluatedAnyGeneration *time.Time `json:"lastEvaluatedAnyGeneration"`
	LastEvaluatedGeneration    *int64     `json:"lastEvaluatedGeneration"`
}

// PolicyActivityItem represents a single policy's activity data.
type PolicyActivityItem struct {
	PolicyKey      `json:",inline"`
	PolicyActivity `json:",inline"`
}

// PolicyActivityQuery identifies a single policy to query.
type PolicyActivityQuery struct {
	Kind       string `json:"kind" validate:"required,oneof=GlobalNetworkPolicy StagedGlobalNetworkPolicy NetworkPolicy StagedNetworkPolicy"`
	Name       string `json:"name" validate:"required"`
	Namespace  string `json:"namespace,omitempty"`
	Generation int64  `json:"generation" validate:"required,gt=0"`
}

// PolicyActivityRequest is the JSON request body for POST /policies/activities.
type PolicyActivityRequest struct {
	Policies []PolicyActivityQuery `json:"policies" validate:"required,gt=0,dive"`
}
