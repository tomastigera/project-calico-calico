// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package v1

import (
	"encoding/json"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

// WAFLogParams define querying parameters to retrieve BGP logs
type WAFLogParams struct {
	QueryParams     `json:",inline" validate:"required"`
	QuerySortParams `json:",inline"`
	Selector        string `json:"selector"`
}

func (w *WAFLogParams) SetSelector(s string) {
	w.Selector = s
}

func (w *WAFLogParams) GetSelector() string {
	return w.Selector
}

func (w *WAFLogParams) SetPermissions(verbs []v3.AuthorizedResourceVerbs) {
	panic("implement me")
}

func (w *WAFLogParams) GetPermissions() []v3.AuthorizedResourceVerbs {
	return nil
}

type WAFLogAggregationParams struct {
	// Inherit all the normal DNS log selection parameters.
	WAFLogParams `json:",inline"`
	Aggregations map[string]json.RawMessage `json:"aggregations"`
	NumBuckets   int                        `json:"num_buckets"`
}

type WAFLog struct {
	Timestamp        time.Time    `json:"@timestamp"`
	Count            int          `json:"count,omitempty"`
	Destination      *WAFEndpoint `json:"destination"`
	Level            string       `json:"level"`
	Method           string       `json:"method"`
	Msg              string       `json:"msg"`
	Path             string       `json:"path"`
	Protocol         string       `json:"protocol"`
	RequestId        string       `json:"request_id,omitempty"`
	RuleInfo         string       `json:"rule_info,omitempty"`
	Rules            []WAFRuleHit `json:"rules,omitempty"`
	Source           *WAFEndpoint `json:"source"`
	Host             string       `json:"host"`
	GatewayName      string       `json:"gateway_name,omitempty"`
	GatewayNamespace string       `json:"gateway_namespace,omitempty"`

	// Cluster is populated by linseed from the request context.
	Cluster string `json:"cluster,omitempty"`
	// GeneratedTime is populated by Linseed when ingesting data to Elasticsearch
	GeneratedTime *time.Time `json:"generated_time,omitempty"`
	ID            string     `json:"id,omitempty"`
}

type WAFEndpoint struct {
	Hostname     string `json:"hostname,omitempty"`
	IP           string `json:"ip"`
	PortNum      int32  `json:"port_num,omitempty"`
	PodName      string `json:"name,omitempty"`
	PodNameSpace string `json:"namespace,omitempty"`
}

type WAFRuleHit struct {
	Id         string `json:"id"`
	Message    string `json:"message"`
	Severity   string `json:"severity"`
	File       string `json:"file"`
	Line       string `json:"line"`
	Disruptive bool   `json:"disruptive"`
}
