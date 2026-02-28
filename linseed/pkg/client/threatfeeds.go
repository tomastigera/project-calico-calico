// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package client

import (
	"context"
	"encoding/json"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

// ThreatFeedsInterface has methods related to threat feeds.
type ThreatFeedsInterface interface {
	IPSet() IPSetInterface
	DomainNameSet() DomainNameSetInterface
}

type IPSetInterface interface {
	List(context.Context, v1.Params) (*v1.List[v1.IPSetThreatFeed], error)
	Create(context.Context, []v1.IPSetThreatFeed) (*v1.BulkResponse, error)
	Delete(context.Context, []v1.IPSetThreatFeed) (*v1.BulkResponse, error)
}

type DomainNameSetInterface interface {
	List(context.Context, v1.Params) (*v1.List[v1.DomainNameSetThreatFeed], error)
	Create(context.Context, []v1.DomainNameSetThreatFeed) (*v1.BulkResponse, error)
	Delete(context.Context, []v1.DomainNameSetThreatFeed) (*v1.BulkResponse, error)
}

// threatFeeds implements ThreatFeedsInterface.
type threatFeeds struct {
	restClient rest.RESTClient
	clusterID  string
}

func (f *threatFeeds) IPSet() IPSetInterface {
	return &ipSet{t: *f}
}

func (f *threatFeeds) DomainNameSet() DomainNameSetInterface {
	return &domainNameSet{t: *f}
}

// newThreatFeeds returns a new ThreatFeedsInterface bound to the supplied client.
func newThreatFeeds(c Client, cluster string) ThreatFeedsInterface {
	return &threatFeeds{restClient: c.RESTClient(), clusterID: cluster}
}

// ipSet implements IPSetInterface
type ipSet struct {
	t threatFeeds
}

func (f *ipSet) Create(ctx context.Context, s []v1.IPSetThreatFeed) (*v1.BulkResponse, error) {
	body := []byte{}
	for _, e := range s {
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

	res := v1.BulkResponse{}
	err := f.t.restClient.Post().
		Path("/threatfeeds/ipset/bulk").
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Cluster(f.t.clusterID).
		Do(ctx).Into(&res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (f *ipSet) Delete(ctx context.Context, s []v1.IPSetThreatFeed) (*v1.BulkResponse, error) {
	body := []byte{}
	for _, e := range s {
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

	res := v1.BulkResponse{}
	err := f.t.restClient.Delete().
		Path("/threatfeeds/ipset/bulk").
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Cluster(f.t.clusterID).
		Do(ctx).Into(&res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (f *ipSet) List(ctx context.Context, p v1.Params) (*v1.List[v1.IPSetThreatFeed], error) {
	res := v1.List[v1.IPSetThreatFeed]{}
	err := f.t.restClient.Post().
		Path("/threatfeeds/ipset").
		Params(p).
		Cluster(f.t.clusterID).
		Do(ctx).
		Into(&res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// domainNameSet implements DomainNameSetInterface
type domainNameSet struct {
	t threatFeeds
}

func (f *domainNameSet) Create(ctx context.Context, s []v1.DomainNameSetThreatFeed) (*v1.BulkResponse, error) {
	body := []byte{}
	for _, e := range s {
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

	res := v1.BulkResponse{}
	err := f.t.restClient.Post().
		Path("/threatfeeds/domainnameset/bulk").
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Cluster(f.t.clusterID).
		Do(ctx).Into(&res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (f *domainNameSet) Delete(ctx context.Context, s []v1.DomainNameSetThreatFeed) (*v1.BulkResponse, error) {
	body := []byte{}
	for _, e := range s {
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

	res := v1.BulkResponse{}
	err := f.t.restClient.Delete().
		Path("/threatfeeds/domainnameset/bulk").
		BodyJSON(body).
		ContentType(rest.ContentTypeMultilineJSON).
		Cluster(f.t.clusterID).
		Do(ctx).Into(&res)
	if err != nil {
		return nil, err
	}

	return &res, nil
}

func (f *domainNameSet) List(ctx context.Context, p v1.Params) (*v1.List[v1.DomainNameSetThreatFeed], error) {
	res := v1.List[v1.DomainNameSetThreatFeed]{}
	err := f.t.restClient.Post().
		Path("/threatfeeds/domainnameset").
		Params(p).
		Cluster(f.t.clusterID).
		Do(ctx).
		Into(&res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
