// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package v1

// Listable represents a response on the API that can be listed
// and used for the pagination API
type Listable interface {
	GetAfterKey() map[string]any
}

// List represents a List response on the API. It contains
// the items returned from the request, as well as additional metadata.
type List[T any] struct {
	// Items are the returned objects from the list request.
	Items []T `json:"items"`

	// AfterKey is an opaque object passed from the server if there
	// are additional items to return. If nil, it means the request
	// was fully satisfied. If non-nil, it can be included on a subsequent
	// request to retrieve the next page of items.
	AfterKey map[string]any `json:"after_key,omitempty"`

	// TotalHits is an optional paramater on log responses to indicate the total number of matching hits.
	// This is useful if the number of hits is greater than the number of results
	// requested by the client.
	TotalHits int64 `json:"total_hits,omitempty"`
}

func (l *List[T]) GetAfterKey() map[string]any {
	return l.AfterKey
}
