// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package client

import (
	"context"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

// L3FlowsInterface has methods related to flows.
type L3FlowsInterface interface {
	List(ctx context.Context, params v1.Params) (*v1.List[v1.L3Flow], error)
	Count(ctx context.Context, params v1.Params) (*v1.CountResponse, error)
}

// L3Flows implements L3FlowsInterface.
type l3Flows struct {
	restClient rest.RESTClient
	clusterID  string
}

// newFlows returns a new FlowsInterface bound to the supplied client.
func newL3Flows(c Client, cluster string) L3FlowsInterface {
	return &l3Flows{restClient: c.RESTClient(), clusterID: cluster}
}

// List gets the l3 flow list for the given flow input params.
func (f *l3Flows) List(ctx context.Context, params v1.Params) (*v1.List[v1.L3Flow], error) {
	flows := v1.List[v1.L3Flow]{}
	err := f.restClient.Post().
		Path("/flows").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&flows)
	if err != nil {
		return nil, err
	}
	return &flows, nil
}

// Count gets the count information for L3 flows matching the given params.
func (f *l3Flows) Count(ctx context.Context, params v1.Params) (*v1.CountResponse, error) {
	resp := v1.CountResponse{}
	err := f.restClient.Post().
		Path("/flows/count").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
