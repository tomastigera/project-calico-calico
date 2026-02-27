package v1

import (
	"fmt"
	"time"
)

type PolicyActivity struct {
	Policy        PolicyInfo `json:"policy"`
	Rule          string     `json:"rule"`
	LastEvaluated time.Time  `json:"last_evaluated"`

	Cluster string `json:"cluster,omitempty"`
	Tenant  string `json:"tenant,omitempty"`

	// GeneratedTime is populated by Linseed when ingesting data to Elasticsearch.
	GeneratedTime *time.Time `json:"generated_time,omitempty"`
	ID            string     `json:"_id,omitempty"`
}

type PolicyInfo struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// PolicyActivityRequest is the request type for the /policyactivity endpoint.
// It accepts a list of policies (with generation) and returns aggregated policy
// activity data with per-rule details.
type PolicyActivityRequest struct {
	From     *time.Time                  `json:"from,omitempty"`
	To       *time.Time                  `json:"to,omitempty"`
	Policies []PolicyActivityQueryPolicy `json:"policies"`
}

// PolicyActivityQueryPolicy identifies a specific policy and generation to query.
type PolicyActivityQueryPolicy struct {
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Generation int64  `json:"generation"`
}

// PolicyActivityResponse is the response type for the /policyactivity endpoint.
type PolicyActivityResponse struct {
	Items []PolicyActivityResult `json:"items"`
}

// PolicyActivityResult contains aggregated policy activity for a single policy.
type PolicyActivityResult struct {
	Policy        PolicyInfo                 `json:"policy"`
	LastEvaluated *time.Time                 `json:"last_evaluated,omitempty"`
	Rules         []PolicyActivityRuleResult `json:"rules"`
}

// PolicyActivityRuleResult contains activity details for a single rule within a policy.
type PolicyActivityRuleResult struct {
	Direction     string    `json:"direction"`
	Index         string    `json:"index"`
	LastEvaluated time.Time `json:"last_evaluated"`
}

func (r *PolicyActivityRequest) Valid() error {
	if r.From != nil && r.To != nil && r.To.Before(*r.From) {
		return fmt.Errorf("invalid time range: 'to' %q is before 'from' %q", r.To, r.From)
	}
	return nil
}
