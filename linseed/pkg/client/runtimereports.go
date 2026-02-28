// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package client

import (
	"context"
	"encoding/json"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

// RuntimeReportsInterface has methods related to runtime logs.
type RuntimeReportsInterface interface {
	Create(context.Context, []v1.Report) (*v1.BulkResponse, error)
	List(context.Context, v1.Params) (*v1.List[v1.RuntimeReport], error)
}

// RuntimeReports implements RuntimeReportsInterface.
type runtime struct {
	restClient rest.RESTClient
	clusterID  string
}

// newRuntimeReports returns a new RuntimeReportsInterface bound to the supplied client.
func newRuntimeReports(c Client, cluster string) RuntimeReportsInterface {
	return &runtime{restClient: c.RESTClient(), clusterID: cluster}
}

// List gets the runtime reports for the given input params.
func (f *runtime) List(ctx context.Context, params v1.Params) (*v1.List[v1.RuntimeReport], error) {
	logs := v1.List[v1.RuntimeReport]{}
	err := f.restClient.Post().
		Path("/runtime/reports").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&logs)
	if err != nil {
		return nil, err
	}
	return &logs, nil
}

func (f *runtime) Create(ctx context.Context, items []v1.Report) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range items {
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
		Path("/runtime/reports/bulk").
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
