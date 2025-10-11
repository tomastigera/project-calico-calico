// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package middleware

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

// ZipFiles represents the expected query for the download API
const ZipFiles = "files.zip"

// GET represents the user intent to download packet capture files
const GET = "get"

// DELETE represents the user intent to delete packet capture files
const DELETE = "delete"

// errMalformedRequest is the error message when the API received an invalid request
var errMalformedRequest = fmt.Errorf("request URL is malformed")

// Parse is a middleware handler that parses the request and sets the common attributes
// on its context
func Parse(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		var ns, name, action, err = parse(req.URL)
		if err != nil {
			log.WithError(err).Errorf("Invalid request %s", req.URL)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var clusterID = req.Header.Get(lmak8s.XClusterIDHeader)
		if clusterID == "" {
			clusterID = lmak8s.DefaultCluster
		}

		req = req.WithContext(WithCaptureName(req.Context(), name))
		req = req.WithContext(WithNamespace(req.Context(), ns))
		req = req.WithContext(WithClusterID(req.Context(), clusterID))
		req = req.WithContext(WithActionID(req.Context(), action))
		handlerFunc.ServeHTTP(w, req)
	}
}

func parse(url *url.URL) (string, string, string, error) {
	var tokens = strings.Split(url.Path, "/")
	if len(tokens) < 1 {
		return "", "", "", errMalformedRequest
	}
	switch tokens[1] {
	case "files":

		if len(tokens) != 4 {
			return "", "", "", errMalformedRequest
		}
		return tokens[2], tokens[3], DELETE, nil
	case "download":
		if len(tokens) != 5 {
			return "", "", "", errMalformedRequest
		}
		if tokens[4] != ZipFiles {
			return "", "", "", errMalformedRequest
		}
		return tokens[2], tokens[3], GET, nil
	}

	return "", "", "", errMalformedRequest

}
