// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package kibana

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Client is an interface whose implementations are responsible for communicating with Kibana
type Client interface {
	// Login attempts to login the given user into Kibana using the given username and password, and returns the
	// response from Kibana. If there is no error and the response status is 200 OK then the user is logged in,
	// otherwise the login failed.
	Login(currentURL, username, password string) (*http.Response, error)
}

// client is an implementation of the Client interface
type client struct {
	httpCli *http.Client
	baseURL string
}

// NewClient creates and returns the `client` implementation of the `Client` interface
func NewClient(httpCli *http.Client, baseURL string) Client {
	return &client{
		httpCli: httpCli,
		baseURL: baseURL,
	}
}

// Login attempts to login the given user into Kibana, and returns the response from Kibana. If there is no error
// and the response status is 200 OK then the user is logged in, otherwise the log in failed.
func (cli *client) Login(currentURL, username, password string) (*http.Response, error) {
	j, err := json.Marshal(map[string]any{
		"currentURL":   currentURL,
		"providerName": "basic",
		"providerType": "basic",
		"params": map[string]any{
			"username": username,
			"password": password,
		},
	})
	if err != nil {
		return nil, err
	}

	r, err := http.NewRequest("POST", fmt.Sprintf("%s/tigera-kibana/internal/security/login", cli.baseURL), bytes.NewBuffer(j))
	if err != nil {
		return nil, err
	}

	r.Header.Set("Content-Type", "application/json")
	// Docs detail that this header should be on all POST requests:
	// https://www.elastic.co/guide/en/kibana/master/api.html
	r.Header.Set("kbn-xsrf", "true")

	kibanaResponse, err := cli.httpCli.Do(r)
	if err != nil {
		return nil, err
	} else if kibanaResponse.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kibana login failed with error: %s", kibanaResponse.Status)
	}

	return kibanaResponse, nil
}
