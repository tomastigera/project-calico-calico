// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package client

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/olivere/elastic/v7"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

// WAFLogsInterface has methods related to waf logs.
type WAFLogsInterface interface {
	List(context.Context, v1.Params) (*v1.List[v1.WAFLog], error)
	ListInto(context.Context, v1.Params, v1.Listable) error
	Create(context.Context, []v1.WAFLog) (*v1.BulkResponse, error)
	Aggregations(context.Context, v1.Params) (elastic.Aggregations, error)
}

// WAFLogs implements WAFLogsInterface.
type waf struct {
	restClient rest.RESTClient
	clusterID  string
}

// newWAFLogs returns a new WAFLogsInterface bound to the supplied client.
func newWAFLogs(c Client, cluster string) WAFLogsInterface {
	return &waf{restClient: c.RESTClient(), clusterID: cluster}
}

// List gets the waf for the given input params.
func (f *waf) List(ctx context.Context, params v1.Params) (*v1.List[v1.WAFLog], error) {
	logs := v1.List[v1.WAFLog]{}
	err := f.ListInto(ctx, params, &logs)
	return &logs, err
}

// ListInto gets the WAF Logs for the given input params.
func (f *waf) ListInto(ctx context.Context, params v1.Params, l v1.Listable) error {
	if l == nil {
		return fmt.Errorf("list cannot be nil")
	}

	err := f.restClient.Post().
		Path("/waf/logs").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(l)
	if err != nil {
		return err
	}

	return nil
}

func (f *waf) Create(ctx context.Context, wafl []v1.WAFLog) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range wafl {
		// Add a newline between each. Do it here so that
		// we don't have a newline after the last event.
		if len(body) != 0 {
			body = append(body, []byte("\n")...)
		}

		// Add the item.
		out, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		body = append(body, out...)
	}

	resp := v1.BulkResponse{}
	err = f.restClient.Post().
		Path("/waf/logs/bulk").
		Cluster(f.clusterID).
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Do(ctx).
		Into(&resp)
	return &resp, err
}

func (f *waf) Aggregations(ctx context.Context, params v1.Params) (elastic.Aggregations, error) {
	aggs := elastic.Aggregations{}
	err := f.restClient.Post().
		Path("/waf/logs/aggregation").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&aggs)
	if err != nil {
		return nil, err
	}
	return aggs, nil
}
