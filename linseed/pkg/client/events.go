// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package client

import (
	"context"
	"encoding/json"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

// EventsInterface has methods related to events.
type EventsInterface interface {
	List(context.Context, v1.Params) (*v1.List[v1.Event], error)
	Create(context.Context, []v1.Event) (*v1.BulkResponse, error)
	UpdateDismissFlag(context.Context, []v1.Event) (*v1.BulkResponse, error)
	Delete(context.Context, []v1.Event) (*v1.BulkResponse, error)
	Statistics(context.Context, v1.EventStatisticsParams) (*v1.EventStatistics, error)
}

// Events implements EventsInterface.
type events struct {
	restClient rest.RESTClient
	clusterID  string
}

// newEvents returns a new EventsInterface bound to the supplied client.
func newEvents(c Client, cluster string) EventsInterface {
	return &events{restClient: c.RESTClient(), clusterID: cluster}
}

// List gets the events for the given input params.
func (f *events) List(ctx context.Context, params v1.Params) (*v1.List[v1.Event], error) {
	events := v1.List[v1.Event]{}
	err := f.restClient.Post().
		Path("/events").
		Params(params).
		Cluster(f.clusterID).
		Do(ctx).
		Into(&events)
	if err != nil {
		return nil, err
	}
	return &events, nil
}

func (f *events) Create(ctx context.Context, events []v1.Event) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range events {
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
		Path("/events/bulk").
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

func (f *events) UpdateDismissFlag(ctx context.Context, events []v1.Event) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range events {
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
	err = f.restClient.Put().
		Path("/events/bulk").
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

func (f *events) Delete(ctx context.Context, events []v1.Event) (*v1.BulkResponse, error) {
	var err error
	body := []byte{}
	for _, e := range events {
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
	err = f.restClient.Delete().
		Path("/events/bulk").
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

func (f *events) Statistics(ctx context.Context, params v1.EventStatisticsParams) (*v1.EventStatistics, error) {
	body, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	resp := v1.EventStatistics{}
	err = f.restClient.Post().
		Path("/events/statistics").
		Cluster(f.clusterID).
		BodyJSON(body).
		ContentType(rest.ContentTypeJSON).
		Do(ctx).
		Into(&resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
