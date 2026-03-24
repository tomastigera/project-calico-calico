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

// DNSLogsInterface has methods related to DNS logs.
type DNSLogsInterface interface {
	List(context.Context, v1.Params) (*v1.List[v1.DNSLog], error)
	ListInto(context.Context, v1.Params, v1.Listable) error
	Create(context.Context, []v1.DNSLog) (*v1.BulkResponse, error)
	Aggregations(context.Context, v1.Params) (elastic.Aggregations, error)
}

// DNSLogs implements DNSLogsInterface.
type dnsLogs struct {
	restClient rest.RESTClient
	clusterID  string
}

// newDNSLogs returns a new DNSLogsInterface bound to the supplied client.
func newDNSLogs(c Client, cluster string) DNSLogsInterface {
	return &dnsLogs{restClient: c.RESTClient(), clusterID: cluster}
}

// List gets the dnsLogs for the given input params.
func (f *dnsLogs) List(ctx context.Context, params v1.Params) (*v1.List[v1.DNSLog], error) {
	dnsLogs := v1.List[v1.DNSLog]{}
	err := f.ListInto(ctx, params, &dnsLogs)
	if err != nil {
		return nil, err
	}
	return &dnsLogs, nil
}

// ListInto gets the DNS Logs for the given input params.
func (f *dnsLogs) ListInto(ctx context.Context, params v1.Params, l v1.Listable) error {
	if l == nil {
		return fmt.Errorf("list cannot be nil")
	}

	err := f.restClient.Post().
		Path("/dns/logs").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(l)
	if err != nil {
		return err
	}
	return nil
}

func (f *dnsLogs) Aggregations(ctx context.Context, params v1.Params) (elastic.Aggregations, error) {
	aggs := elastic.Aggregations{}
	err := f.restClient.Post().
		Path("/dns/logs/aggregation").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&aggs)
	if err != nil {
		return nil, err
	}
	return aggs, nil
}

func (f *dnsLogs) Create(ctx context.Context, dnsLogs []v1.DNSLog) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range dnsLogs {
		if len(body) != 0 {
			// Include a separator between logs.
			body = append(body, []byte("\n")...)
		}

		// Add each item.
		out, err := json.Marshal(&e)
		if err != nil {
			return nil, err
		}
		body = append(body, out...)
	}

	resp := v1.BulkResponse{}
	err = f.restClient.Post().
		Path("/dns/logs/bulk").
		Cluster(f.clusterID).
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Do(ctx).
		Into(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, err
}
