// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package client

import (
	"context"
	"encoding/json"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

// BGPLogsInterface has methods related to bgp logs.
type BGPLogsInterface interface {
	List(context.Context, v1.Params) (*v1.List[v1.BGPLog], error)
	Create(context.Context, []v1.BGPLog) (*v1.BulkResponse, error)
}

// BGPLogs implements BGPLogsInterface.
type bgp struct {
	restClient rest.RESTClient
	clusterID  string
}

// newBGPLogs returns a new BGPLogsInterface bound to the supplied client.
func newBGPLogs(c Client, cluster string) BGPLogsInterface {
	return &bgp{restClient: c.RESTClient(), clusterID: cluster}
}

// List gets the bgp for the given input params.
func (f *bgp) List(ctx context.Context, params v1.Params) (*v1.List[v1.BGPLog], error) {
	logs := v1.List[v1.BGPLog]{}
	err := f.restClient.Post().
		Path("/bgp/logs").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&logs)
	if err != nil {
		return nil, err
	}
	return &logs, nil
}

func (f *bgp) Create(ctx context.Context, bgpl []v1.BGPLog) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range bgpl {
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
		Path("/bgp/logs/bulk").
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
