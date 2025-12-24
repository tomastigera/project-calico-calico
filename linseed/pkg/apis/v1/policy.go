package v1

import (
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
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

type PolicyActivityParams struct {
	QueryParams `json:",inline" validate:"required"`

	Cluster string     `json:"cluster,omitempty"`
	Tenant  string     `json:"tenant,omitempty"`
	Policy  PolicyInfo `json:"policy"`
	Rules   []string   `json:"rules,omitempty"`

	LastEvaluated time.Time `json:"last_evaluated"`
	// Sort configures the sorting of results.
	Sort []SearchRequestSortBy `json:"sort"`

	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`

	QuerySortParams `json:",inline"`
	Selector        string `json:"selector"`
}

func (w *PolicyActivityParams) SetSelector(s string) {
	w.Selector = s
}

func (w *PolicyActivityParams) GetSelector() string {
	return w.Selector
}

func (w *PolicyActivityParams) SetPermissions(verbs []v3.AuthorizedResourceVerbs) {
	// Intentionally left empty.
	// This method is a placeholder for interface implementation and is not currently used.
}

func (w *PolicyActivityParams) GetPermissions() []v3.AuthorizedResourceVerbs {
	return nil
}
