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

// FlowLogsInterface has methods related to flowLogs.
type FlowLogsInterface interface {
	List(context.Context, v1.Params) (*v1.List[v1.FlowLog], error)
	ListInto(context.Context, v1.Params, v1.Listable) error
	Create(context.Context, []v1.FlowLog) (*v1.BulkResponse, error)
	Aggregations(context.Context, v1.Params) (elastic.Aggregations, error)
	Count(context.Context, v1.Params) (*v1.CountResponse, error)
}

// FlowLogs implements FlowLogsInterface.
type flowLogs struct {
	restClient rest.RESTClient
	clusterID  string
}

// newFlowLogs returns a new FlowLogsInterface bound to the supplied client.
func newFlowLogs(c Client, cluster string) FlowLogsInterface {
	return &flowLogs{restClient: c.RESTClient(), clusterID: cluster}
}

// List gets the flowLogs for the given input params.
func (f *flowLogs) List(ctx context.Context, params v1.Params) (*v1.List[v1.FlowLog], error) {
	flowLogs := v1.List[v1.FlowLog]{}
	err := f.ListInto(ctx, params, &flowLogs)
	if err != nil {
		return nil, err
	}
	return &flowLogs, err
}

// ListInto gets the flowLogs for the given input params.
func (f *flowLogs) ListInto(ctx context.Context, params v1.Params, l v1.Listable) error {
	if l == nil {
		return fmt.Errorf("list cannot be nil")
	}

	err := f.restClient.Post().
		Path("/flows/logs").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(l)
	if err != nil {
		return err
	}

	return nil
}

func (f *flowLogs) Create(ctx context.Context, flowLogs []v1.FlowLog) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range flowLogs {
		if len(body) != 0 {
			// Include a separator between logs.
			body = append(body, []byte("\n")...)
		}

		// Add each item.
		out, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		body = append(body, out...)
	}

	resp := v1.BulkResponse{}
	err = f.restClient.Post().
		Path("/flows/logs/bulk").
		Cluster(f.clusterID).
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Do(ctx).
		Into(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (f *flowLogs) Aggregations(ctx context.Context, params v1.Params) (elastic.Aggregations, error) {
	aggs := elastic.Aggregations{}
	err := f.restClient.Post().
		Path("/flows/logs/aggregation").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&aggs)
	if err != nil {
		return nil, err
	}
	return aggs, nil
}

func (f *flowLogs) Count(ctx context.Context, params v1.Params) (*v1.CountResponse, error) {
	resp := v1.CountResponse{}
	err := f.restClient.Post().
		Path("/flows/logs/count").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
