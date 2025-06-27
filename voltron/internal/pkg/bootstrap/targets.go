// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"

	log "github.com/sirupsen/logrus"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/transport"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
)

// Target is the format for env variable to set proxy targets
type Target struct {
	// Path is the path portion of the URL based on which we proxy
	Path string `json:"path"`
	// Dest is the destination URL
	Dest string `json:"destination"`
	// TokenPath is where we read the Bearer token from (if non-empty)
	TokenPath string `json:"tokenPath,omitempty"`
	// CABundlePath is where we read the CA bundle from to authenticate the
	// destination (if non-empty)
	CABundlePath string `json:"caBundlePath,omitempty"`
	// PathRegexp, if not nil, checks if Regexp matches the path
	PathRegexp strAsByteSlice `json:"pathRegexp,omitempty"`
	// PathReplace if not nil will be used to replace PathRegexp matches
	PathReplace strAsByteSlice `json:"pathReplace,omitempty"`

	// HostHeader rewrites the host value for the proxied request.
	HostHeader *string `json:"hostHeader,omitempty"`
	// AllowInsecureTLS allows https with insecure tls settings
	AllowInsecureTLS bool `json:"allowInsecureTLS,omitempty"`

	// ClientCertPath and ClientKeyPath can be set for mTLS on the connection
	// from Voltron to the destination.
	ClientCertPath string `json:"clientCertPath"`
	ClientKeyPath  string `json:"clientKeyPath"`

	Unauthenticated bool `json:"unauthenticated,omitempty"`

	Authorizer                  auth.RBACAuthorizer
	AuthorizationAttributesFunc func(request *http.Request) (*authorizationv1.ResourceAttributes, *authorizationv1.NonResourceAttributes, error)
}

func (targets *Targets) UnauthenticatedPaths() []string {
	var paths []string

	for _, target := range *targets {
		if target.Unauthenticated {
			paths = append(paths, target.Path)
		}
	}

	return paths
}

// Targets allows unmarshal the json array
type Targets []Target

// Decode deserializes the list of proxytargets
func (targets *Targets) Decode(envVar string) error {
	err := json.Unmarshal([]byte(envVar), targets)
	if err != nil {
		return err
	}

	return nil
}

type strAsByteSlice []byte

func (b *strAsByteSlice) UnmarshalJSON(j []byte) error {
	// strip the enclosing ""
	*b = j[1 : len(j)-1]
	return nil
}

// ProxyTargets decodes Targets into []proxy.Target
func ProxyTargets(tgts Targets) ([]proxy.Target, error) {
	var ret []proxy.Target

	// pathSet helps keep track of the paths we've seen so we don't have duplicates
	pathSet := make(map[string]bool)

	for _, t := range tgts {
		if t.Path == "" {
			return nil, errors.New("proxy target path cannot be empty")
		} else if pathSet[t.Path] {
			return nil, fmt.Errorf("duplicate proxy target path %s", t.Path)
		}

		pt := proxy.Target{
			Path:             t.Path,
			AllowInsecureTLS: t.AllowInsecureTLS,
		}

		if t.ClientKeyPath != "" && t.ClientCertPath != "" {
			pt.ClientKeyPath = t.ClientKeyPath
			pt.ClientCertPath = t.ClientCertPath
		} else if t.ClientKeyPath != "" || t.ClientCertPath != "" {
			return nil, fmt.Errorf("must specify both ClientKeyPath and ClientCertPath")
		}

		var err error
		pt.Dest, err = url.Parse(t.Dest)
		if err != nil {
			return nil, fmt.Errorf("incorrect URL %q for path %q: %s", t.Dest, t.Path, err)
		}

		if pt.Dest.Scheme == "https" && !t.AllowInsecureTLS && t.CABundlePath == "" {
			return nil, fmt.Errorf("target for path '%s' must specify the ca bundle if AllowInsecureTLS is false when the scheme is https", t.Path)
		}

		if t.TokenPath != "" {
			// Read the token from file to verify the token exists
			_, err := os.ReadFile(t.TokenPath)
			if err != nil {
				return nil, fmt.Errorf("failed reading token from %s: %s", t.TokenPath, err)
			}

			pt.Token = transport.NewCachedFileTokenSource(t.TokenPath)
		}

		if t.CABundlePath != "" {
			pt.CAPem = t.CABundlePath
		}

		if t.PathReplace != nil && t.PathRegexp == nil {
			return nil, fmt.Errorf("PathReplace specified but PathRegexp is not")
		}

		if t.PathRegexp != nil {
			r, err := regexp.Compile(string(t.PathRegexp))
			if err != nil {
				return nil, fmt.Errorf("PathRegexp failed: %s", err)
			}
			pt.PathRegexp = r
		}
		pt.PathReplace = t.PathReplace
		pt.HostHeader = t.HostHeader

		pathSet[pt.Path] = true
		ret = append(ret, pt)
	}

	return ret, nil
}

func AuthorizationDetailsByPath(tgts Targets) map[string]*proxy.AuthorizationDetails {
	authMap := map[string]*proxy.AuthorizationDetails{}
	for _, tgt := range tgts {
		authMap[tgt.Path] = &proxy.AuthorizationDetails{
			Authorizer:     tgt.Authorizer,
			AttributesFunc: tgt.AuthorizationAttributesFunc,
		}
	}
	return authMap
}

func TLSTerminatedRoutesFromFile(path string) ([]Target, error) {
	var targets Targets

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading file from %s: %w", path, err)
	}

	log.Debugf("route contents %s", contents)

	err = json.Unmarshal(contents, &targets)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshalling JSON: %s", err)
	}

	return targets, nil
}

type TLSPassThroughRoute struct {
	// Destination is the destination URL
	Destination string `json:"destination"`

	// Server name to match incoming tunnel traffic to. Matching traffic is proxied to the Destination.
	ServerName string `json:"serverName"`

	// HostHeader rewrites the host value for the proxied request.
	HostHeader *string `json:"hostHeader,omitempty"`
}

func TLSPassThroughRoutesFromFile(path string) ([]TLSPassThroughRoute, error) {
	var routes []TLSPassThroughRoute

	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed reading file from %s: %w", path, err)
	}

	log.Debugf("route contents %s", contents)

	err = json.Unmarshal(contents, &routes)
	if err != nil {
		return nil, fmt.Errorf("failed unmarshalling JSON: %s", err)
	}

	return routes, nil
}
