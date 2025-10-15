// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.
package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	lmaerror "github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

const (
	DefaultRequestTimeout = 60 * time.Second

	MaxNumResults     = 10000
	MaxResultsPerPage = 1000
)

var (
	ErrInvalidMethod = errors.New("invalid http method")
	ErrParseRequest  = errors.New("error parsing request parameters")
)

func createAndReturnError(err error, errorStr string, code int, featureID lmaerror.FeatureID, w http.ResponseWriter) {
	log.WithError(err).Info(errorStr)

	lmaError := lmaerror.Error{
		Code:    code,
		Message: errorStr,
		Feature: featureID,
	}

	responseJSON, err := json.Marshal(lmaError)
	if err != nil {
		log.WithError(err).Error("Error marshalling response to JSON")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(code)
	_, err = w.Write(responseJSON)
	if err != nil {
		log.WithError(err).Infof("Error writing JSON: %v", responseJSON)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func MaybeParseClusterNameFromRequest(r *http.Request) string {
	clusterName := lmak8s.DefaultCluster
	if r != nil && r.Header != nil {
		xClusterID := r.Header.Get(lmak8s.XClusterIDHeader)
		if xClusterID != "" {
			clusterName = xClusterID
		}
	}
	return clusterName
}

type RequestType interface {
	v1.CommonSearchRequest | v1.FlowLogSearchRequest | EndpointsAggregationRequest | EndpointsNamesRequest
}

// ParseBody extracts query parameters from the request body (JSON.blob) into RequestType.
//
// Will define an http.Error if an error occurs.
func ParseBody[T RequestType](w http.ResponseWriter, r *http.Request) (*T, error) {
	params := new(T)

	// Decode the http request body into the struct.
	if err := httputils.Decode(w, r, params); err != nil {
		var mr *httputils.HttpStatusError
		if errors.As(err, &mr) {
			log.WithError(mr.Err).Error(mr.Msg)
			return nil, mr
		} else {
			log.WithError(mr.Err).Error("error parsing request body.")
			return nil, &httputils.HttpStatusError{
				Status: http.StatusBadRequest,
				Msg:    "failed to parse request body into expected parameters.",
				Err:    err,
			}
		}
	}

	return params, nil
}
