// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package v1

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/lma/pkg/list"
)

type SnapshotParams struct {
	QueryParams `json:",inline" validate:"required"`

	// Match on the APIGroup and Kind of resource snapshot.
	TypeMatch *metav1.TypeMeta `json:"type_match"`

	// Sort configures the sorting of results.
	Sort []SearchRequestSortBy `json:"sort"`
}

type Snapshot struct {
	ResourceList list.TimestampedResourceList `json:"resource_list"`
	ID           string                       `json:"id"`
}

type ReportDataParams struct {
	QueryParams `json:",inline" validate:"required"`

	// TODO: Move ID into a common query struct?
	ID string `json:"id"`

	ReportMatches []ReportMatch `json:"report_matches"`

	// Sort configures the sorting of results.
	Sort []SearchRequestSortBy `json:"sort"`
}

type ReportMatch struct {
	ReportName     string
	ReportTypeName string
}

// ReportData represents data used to populate a compliance report.
type ReportData struct {
	*apiv3.ReportData `json:",inline"`
	UISummary         string `json:"uiSummary"`
	ID                string `json:"id,omitempty"`

	// Cluster is populated by linseed from the request context.
	Cluster string `json:"cluster,omitempty"`
	// GeneratedTime is populated by Linseed when ingesting data to Elasticsearch
	GeneratedTime *time.Time `json:"generated_time,omitempty"`
}

func (r *ReportData) UID() string {
	name := fmt.Sprintf("%s::%s::%s", r.ReportName, r.StartTime.Format(time.RFC3339), r.EndTime.Format(time.RFC3339))
	id := uuid.NewSHA1(uuid.NameSpaceURL, []byte(name)) // V5 uuids are deterministic

	// Encode the report name and report type name into the UID - we use this so that we can perform RBAC without
	// needing to download the report.
	return fmt.Sprintf("%s_%s_%s", r.ReportName, r.ReportTypeName, id.String())
}

// BenchmarkType is the type of benchmark.
type BenchmarkType string

const (
	TypeKubernetes BenchmarkType = "kube"
)

// Filter is the set of filters to limit the returned benchmarks.
type BenchmarksFilter struct {
	Version   string
	NodeNames []string
}

type BenchmarksParams struct {
	QueryParams `json:",inline" validate:"required"`
	ID          string                `json:"id"`
	Type        BenchmarkType         `json:"type"`
	Filters     []BenchmarksFilter    `json:"filters"`
	Sort        []SearchRequestSortBy `json:"sort"`
}

// Benchmarks is a set of benchmarks for a given node.
type Benchmarks struct {
	ID                string          `json:"id,omitempty"`
	Version           string          `json:"version"`
	KubernetesVersion string          `json:"kubernetesVersion"`
	Type              BenchmarkType   `json:"type"`
	NodeName          string          `json:"node_name"`
	Timestamp         metav1.Time     `json:"timestamp"`
	Error             string          `json:"error,omitempty"`
	Tests             []BenchmarkTest `json:"tests,omitempty"`

	// Cluster is populated by linseed from the request context.
	Cluster string `json:"cluster,omitempty"`
	// GeneratedTime is populated by Linseed when ingesting data to Elasticsearch
	GeneratedTime *time.Time `json:"generated_time,omitempty"`
}

// Test is a given test within a set of benchmarks.
type BenchmarkTest struct {
	Section     string `json:"section"`
	SectionDesc string `json:"section_desc"`
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	TestInfo    string `json:"test_info"`
	Status      string `json:"status"`
	Scored      bool   `json:"scored"`
}

// UID is a unique identifier for a set of benchmarks.
func (b Benchmarks) UID() string {
	return fmt.Sprintf("%s::%s::%s", b.Timestamp.Format(time.RFC3339), b.Type, b.NodeName)
}

// Equal computes equality between benchmark results. Does not include Timestamp in the calculation.
func (b Benchmarks) Equal(other Benchmarks) bool {
	// First check the error field.
	if b.Error != "" {
		return b.Error == other.Error
	}

	// Initial equality determined by metadata fields.
	if b.Version != other.Version || b.Type != other.Type || b.NodeName != other.NodeName {
		return false
	}

	// Finally, check the tests. Assumes that the tests in both structures are positioned in the same order.
	for i, test := range b.Tests {
		if test != other.Tests[i] {
			return false
		}
	}
	return true
}
