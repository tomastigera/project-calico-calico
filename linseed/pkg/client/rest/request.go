// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package rest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

const (
	ContentTypeJSON          = "application/json"
	ContentTypeMultilineJSON = "application/x-ndjson"
)

const (
	VersionPath = "/api/v1"
)

// Request is a helper for building a request for the Linseed API.
type Request interface {
	Verb(v string) Request
	Params(p any) Request
	BodyJSON(b any) Request
	Path(p string) Request
	Cluster(c string) Request
	ContentType(t string) Request
	Do(ctx context.Context) *Result
}

func NewRequest(c RESTClient) Request {
	return &request{
		client: c,
	}
}

// request is a helper struct for building an HTTP request.
type request struct {
	client      RESTClient
	contentType string
	verb        string
	params      any
	body        any
	path        string
	clusterID   string
}

// Verb sets the verb this request will use.
func (r *request) Verb(verb string) Request {
	r.verb = verb
	return r
}

// Params sets parameters to pass in the request body.
func (r *request) Params(p any) Request {
	r.params = p
	return r
}

// BodyJSON sets the body
func (r *request) BodyJSON(p any) Request {
	r.body = p
	return r
}

func (r *request) Path(p string) Request {
	r.path = p
	return r
}

// Cluster sets the x-cluster-id header for this request.
func (r *request) Cluster(c string) Request {
	r.clusterID = c
	return r
}

func (r *request) ContentType(c string) Request {
	r.contentType = c
	return r
}

func (r *request) Do(ctx context.Context) *Result {
	if r.body != nil && r.params != nil {
		return &Result{
			err: fmt.Errorf("cannot specify body and params on same request"),
		}
	}

	var err error
	var body []byte
	if r.params != nil {
		body, err = json.Marshal(r.params)
		if err != nil {
			return &Result{
				err: fmt.Errorf("error marshalling request param: %s", err),
			}
		}
	}
	if r.body != nil {
		var ok bool
		body, ok = r.body.([]byte)
		if !ok {
			return &Result{
				err: fmt.Errorf("body must be a slice of bytes"),
			}
		}
	}

	// This is temporary, until we upgrade to go1.19 which has
	// native support for this via url.JoinPath
	JoinPath := func(base string, paths ...string) string {
		p := path.Join(paths...)
		return fmt.Sprintf("%s/%s", strings.TrimRight(base, "/"), strings.TrimLeft(p, "/"))
	}
	url := JoinPath(r.client.BaseURL(), VersionPath, r.path)

	// Build the request.
	req, err := http.NewRequestWithContext(
		ctx,
		r.verb,
		url,
		bytes.NewBuffer(body),
	)
	if err != nil {
		return &Result{
			err: fmt.Errorf("error creating new request: %s", err),
		}
	}

	// Setting close to true to avoid sending a successive request on a connection that is already in mid-termination.
	req.Close = true
	req.Header.Set("x-cluster-id", r.clusterID)
	req.Header.Set("x-tenant-id", r.client.Tenant())

	if r.contentType == "" {
		req.Header.Set("Content-Type", ContentTypeJSON)
	} else {
		req.Header.Set("Content-Type", r.contentType)
	}

	if token, err := r.client.Token(); err != nil {
		return &Result{err: err}
	} else if len(token) > 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))
	}

	// Perform the request.
	response, err := r.client.HTTPClient().Do(req)
	if err != nil {
		return &Result{
			err: fmt.Errorf("error connecting linseed API: %s", err),
		}
	}
	defer func() { _ = response.Body.Close() }()

	// Build the response.
	responseByte, err := io.ReadAll(response.Body)
	return &Result{
		err:        err,
		body:       responseByte,
		statusCode: response.StatusCode,
		path:       r.path,
	}
}

type Result struct {
	err        error
	body       []byte
	statusCode int
	path       string
}

// Into decodes the body of the result into the given structure. obj should be a pointer.
func (r *Result) Into(obj any) error {
	if r.err != nil {
		return r.err
	}
	if len(r.body) == 0 {
		return fmt.Errorf("no body returned from request. status=%d", r.statusCode)
	}

	if r.statusCode == http.StatusNotFound {
		// The path wasn't found. We shouldn't parse the response as JSON.
		return fmt.Errorf("server returned not found for path %s: %s", r.path, string(r.body))
	} else if r.statusCode != http.StatusOK {
		// Attempt to parse the response as a structured error.
		httpError := v1.HTTPError{}
		err := json.Unmarshal(r.body, &httpError)
		if err != nil {
			return fmt.Errorf("client failed to unmarshal error response: %s", err)
		}

		if len(httpError.Msg) == 0 || httpError.Status == 0 {
			// No structured error returned by the server, just error out the full body.
			return fmt.Errorf("client received unstructured error: %s", string(r.body))
		}

		// A structured error returned by the server.
		return fmt.Errorf("[status %d] server error: %s", httpError.Status, httpError.Msg)
	}

	// Got an OK response - unmarshal it into the expected type.
	err := json.Unmarshal(r.body, obj)
	if err != nil {
		logrus.WithField("body", string(r.body)).Errorf("Error unmarshalling response")
		return fmt.Errorf("error unmarshalling response: %s", err)
	}

	return nil
}
