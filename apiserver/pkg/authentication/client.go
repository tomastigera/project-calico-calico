// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package authentication

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	AuthorizationHeader = "Authorization"
	authenticationURI   = "/apis/projectcalico.org/v3/authenticationreviews"
)

// Authenticator authenticates a user based on an authorization header, whether the user uses basic auth or token auth.
type Authenticator interface {
	// If the user can be authenticated, user information is returned. A status code is returned that can be used for a
	// response to an HTTP request.
	Authenticate(token string) (user.Info, int, error)
}

// New creates and returns an implementation of the Authenticator, creating the necessary rest.Config from the path defined
// in the ENV variable KUBECONFIG. If KUBECONFIG is not defined, the default behaviour of clientcmd.BuildConfigFromFlags
// is used.
func New() (Authenticator, error) {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	if err != nil {
		return nil, errors.New("unable to configure an authn client")
	}

	return NewWithConfig(config)
}

// NewWithConfig creates a new Authenticator using the given rest.Config.
//
// Note that rest.Config is used solely to get the cluster URI and a transport for the cluster to create an http client
// that can communicate with the kubernetes API.
func NewWithConfig(config *rest.Config) (Authenticator, error) {
	transport, err := rest.TransportFor(config)
	if err != nil {
		return nil, fmt.Errorf("failed to extract the transport from the rest config: %w", err)
	}

	uri, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host address: %w", err)
	}

	uri.Path = authenticationURI

	return &authenticator{
		client: &http.Client{
			Transport: transport,
		},
		endpoint: uri,
	}, nil
}

type authenticator struct {
	client   *http.Client
	endpoint *url.URL
}

// If the user can be authenticated, user information is returned. A status code is returned that can be used for a
// response to an HTTP request.
func (a *authenticator) Authenticate(authHeader string) (user.Info, int, error) {
	if len(authHeader) == 0 {
		return nil, 401, errors.New("authorization header is missing")
	}

	authenticationReview := v3.NewAuthenticationReview()
	buffer, _ := json.Marshal(authenticationReview)
	reader := bytes.NewReader(buffer)

	req := &http.Request{
		Method: "POST",
		URL:    a.endpoint,
		Header: http.Header{
			AuthorizationHeader: []string{authHeader},
			"Content-Type":      []string{"application/json"},
		},
		Body: io.NopCloser(reader),
	}
	response, err := a.client.Do(req)
	if err != nil {
		log.Error("unexpected error during authentication review", err)
		return nil, 500, errors.New("unexpected error during authentication review")
	}
	defer func() { _ = response.Body.Close() }()
	byteArray, err := io.ReadAll(response.Body)

	stat := response.StatusCode
	if stat == http.StatusForbidden {
		return nil, stat, errors.New("user does not have RBAC permissions for authenticationreviews")
	} else if stat < http.StatusOK || stat >= http.StatusMultipleChoices {
		return nil, stat, errors.New("user cannot be authenticated")
	}

	if err != nil {
		log.Error("unexpected error during authentication review", err)
		return nil, 500, errors.New("unexpected error during authentication review")
	}

	if err = json.Unmarshal(byteArray, &authenticationReview); err != nil {
		log.Error("unexpected response from api-server during authentication review", err)
		return nil, http.StatusInternalServerError, errors.New("unexpected response from api-server during authentication review")
	}

	// We expect a username and at the very least 1 group (system:authenticated)
	if authenticationReview.Status.Name == "" || len(authenticationReview.Status.Groups) == 0 {
		return nil, http.StatusUnauthorized, errors.New("request could not be authenticated")
	}

	return &user.DefaultInfo{
		Name:   authenticationReview.Status.Name,
		UID:    authenticationReview.Status.UID,
		Extra:  authenticationReview.Status.Extra,
		Groups: authenticationReview.Status.Groups,
	}, stat, nil
}

// Convenience method that can be used in the context of doing authn and authz in sequence.
// If the user can be authenticated, it is added to the request context. A status code is returned that can be used
// for a response to an HTTP request.
func AuthenticateRequest(authenticator Authenticator, req *http.Request) (*http.Request, int, error) {
	usr, stat, err := authenticator.Authenticate(req.Header.Get(AuthorizationHeader))

	if err != nil {
		return req, stat, err
	}

	req = req.WithContext(request.WithUser(req.Context(), usr))
	return req, stat, err
}
