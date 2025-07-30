// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

package authentication

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

// A Fake Authenticator satisfies the Authenticator interface and can be used for unit tests. It will mock/fake
// the calico-apiserver and responds according to your predefined API server responses.
type FakeAuthenticator interface {
	AddErrorAPIServerResponse(authorizationHeader string, apiResponse []byte, statusCode int)
	AddValidApiResponse(authorizationHeader, user string, groups []string)
	Authenticator
}

type fakeAuthenticator struct {
	rt *roundTripper
	authenticator
}

// Holds the results of the api-server for a given input header.
type testResult struct {
	apiResponseJson []byte
	statusCode      int
}

type roundTripper struct {
	users map[string]testResult
}

// RoundTripper to make redirect the authenticator to our custom responses, rather than a real server.
func (f roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != "POST" {
		return &http.Response{
			StatusCode: http.StatusMethodNotAllowed,
			Body:       io.NopCloser(bytes.NewBufferString("Unsupported Method")),
		}, nil
	}
	header := req.Header.Get(AuthorizationHeader)
	if header == "" {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(bytes.NewBufferString("user not authenticated")),
		}, nil
	}
	result, ok := f.users[header]
	if !ok {
		panic(fmt.Sprintf("Configure your fake authenticator for header %s", header))
	}

	return &http.Response{
		StatusCode: result.statusCode,
		Body:       io.NopCloser(bytes.NewReader(result.apiResponseJson)),
	}, nil
}

// Can be used in unit tests. Satisfies the Authenticator interface + some extra methods to setup your tests.
func NewFakeAuthenticator() FakeAuthenticator {
	rt := &roundTripper{
		users: make(map[string]testResult),
	}

	return &fakeAuthenticator{
		rt: rt,
		authenticator: authenticator{
			endpoint: &url.URL{
				Scheme: "http",
				Host:   "127.0.0.1:1234",
				Path:   authenticationURI},
			client: &http.Client{
				Transport: rt,
			},
		},
	}
}

// Add a custom response for an authorization header. You can use this to test various headers that should not be
// authenticated or test the behaviour of the authenticator when the calico-apiserver shows unexpected behaviour.
func (f *fakeAuthenticator) AddErrorAPIServerResponse(authorizationHeader string, apiResponse []byte, statusCode int) {
	f.rt.users[authorizationHeader] = testResult{apiResponseJson: apiResponse, statusCode: statusCode}
}

// Add a user to the fake calico-apiserver. When the authenticator makes a call, it will get back an authentication
// review with the provided username and groups as json.
func (f *fakeAuthenticator) AddValidApiResponse(authorizationHeader, username string, groups []string) {
	authenticationReview := v3.NewAuthenticationReview()
	authenticationReview.Status.Name = username
	authenticationReview.Status.Groups = groups
	buffer, _ := json.Marshal(authenticationReview)
	f.rt.users[authorizationHeader] = testResult{apiResponseJson: buffer, statusCode: http.StatusOK}
}
