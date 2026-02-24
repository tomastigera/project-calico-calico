// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package v1

import (
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// Make sure QueryParams implements the interface.
var _ Params = &QueryParams{}

// DefaultTimeOut is the default timeout that an API will run its query
// until it cancels the execution
const DefaultTimeOut = 60 * time.Second

type Params interface {
	GetMaxPageSize() int
	SetMaxPageSize(int)
	SetAfterKey(map[string]any)
	GetAfterKey() map[string]any
	SetTimeout(*v1.Duration)
	SetTimeRange(*lmav1.TimeRange)
	GetTimeRange() *lmav1.TimeRange
	IsAllClusters() bool
	SetAllClusters(bool)
	GetClusters() []string
	SetClusters([]string)
}

type LogParams interface {
	Params
	SortParams
	SetSelector(string)
	GetSelector() string
	SetPermissions([]v3.AuthorizedResourceVerbs)
	GetPermissions() []v3.AuthorizedResourceVerbs
}

type SortParams interface {
	SetSortBy([]SearchRequestSortBy)
	GetSortBy() []SearchRequestSortBy
}

// QueryParams are request parameters that are shared across all APIs
type QueryParams struct {
	// TimeRange will filter data generated within the specified time range
	// If omitted, the server will default to an appropriate time range depending on
	// the requested resource.
	TimeRange *lmav1.TimeRange `json:"time_range" validate:"omitempty"`

	// Timeout will limit requests to read/write data to the desired duration
	Timeout *v1.Duration `json:"timeout" validate:"omitempty"`

	// Limit the maximum number of returned results.
	MaxPageSize int `json:"max_page_size"`

	// AfterKey is used for pagination. If set, the query will start from the given AfterKey.
	// This is generally passed straight through to the datastore, and its type cannot be
	// guaranteed.
	AfterKey map[string]any `json:"after_key"`

	// AllClusters when true, no cluster filtering is performed
	//
	// For this value to be considered, the x-cluster-id header must be set to `v1.QueryMultipleClusters` : "_MULTI_"
	AllClusters bool `json:"all_clusters,omitempty"`

	// Clusters filters results to only include data from the given clusters.
	//
	// For this value to be considered, the x-cluster-id header must be set to `v1.QueryMultipleClusters` : "_MULTI_"
	Clusters []string `json:"clusters,omitempty"`
}

func (p *QueryParams) SetMaxPageSize(i int) {
	p.MaxPageSize = i
}

func (p *QueryParams) GetMaxPageSize() int {
	if p == nil || p.MaxPageSize == 0 {
		return 1000
	}
	return p.MaxPageSize
}

func (p *QueryParams) SetAfterKey(k map[string]any) {
	p.AfterKey = k
}

func (p *QueryParams) GetAfterKey() map[string]any {
	return p.AfterKey
}

func (p *QueryParams) SetTimeout(t *v1.Duration) {
	p.Timeout = t
}

func (p *QueryParams) SetTimeRange(t *lmav1.TimeRange) {
	p.TimeRange = t
}

func (p *QueryParams) GetTimeRange() *lmav1.TimeRange {
	return p.TimeRange
}

func (p *QueryParams) IsAllClusters() bool {
	return p.AllClusters
}

func (p *QueryParams) SetAllClusters(b bool) {
	p.AllClusters = b
	if b {
		p.Clusters = nil
	}
}

func (p *QueryParams) GetClusters() []string {
	return p.Clusters
}

func (p *QueryParams) SetClusters(c []string) {
	p.AllClusters = false
	p.Clusters = c
}

// LogSelectionParams are common for all log APIs.
type LogSelectionParams struct {
	// Permissions define a set of resource kinds and namespaces that
	// should be used to filter-in results. If present, any results that
	// do not match the given permissions will be omitted.
	Permissions []v3.AuthorizedResourceVerbs `json:"permissions"`

	// If present, returns only the logs that match the query.
	Selector string `json:"selector"`
}

func (l *LogSelectionParams) SetSelector(s string) {
	l.Selector = s
}

func (l *LogSelectionParams) GetSelector() string {
	return l.Selector
}

func (l *LogSelectionParams) SetPermissions(p []v3.AuthorizedResourceVerbs) {
	l.Permissions = p
}

func (l *LogSelectionParams) GetPermissions() []v3.AuthorizedResourceVerbs {
	return l.Permissions
}

// SearchRequestSortBy allows configuration of sorting of results.
type SearchRequestSortBy struct {
	// The field to sort by.
	Field string `json:"field"`

	// True if the returned results should be in descending order. Default is ascending order.
	Descending bool `json:"descending,omitempty"`
}

// QuerySortParams are common for all APIs that can return
// sorted results
type QuerySortParams struct {
	// Sort configures the sorting of results.
	Sort []SearchRequestSortBy `json:"sort"`
}

func (l *QuerySortParams) SetSortBy(s []SearchRequestSortBy) {
	l.Sort = s
}

func (l *QuerySortParams) GetSortBy() []SearchRequestSortBy {
	return l.Sort
}
