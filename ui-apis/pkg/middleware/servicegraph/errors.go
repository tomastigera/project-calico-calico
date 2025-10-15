// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/projectcalico/calico/lma/pkg/httputils"
)

// Error returned when linseed enumeration truncates data.
var errDataTruncatedError = errors.New("the service graph data is truncated")

func NewCacheTimeoutError(duration time.Duration) error {
	err := errors.New("background query is taking a long time")
	body := struct {
		Duration time.Duration `json:"duration"`
		Reason   string        `json:"reason"`
	}{
		duration,
		err.Error(),
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return &httputils.HttpStatusError{
		Status: http.StatusGatewayTimeout,
		Msg:    string(b),
		Err:    err,
	}
}
