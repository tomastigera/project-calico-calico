// Copyright (c) 2021 Tigera. All rights reserved.
package handler

import (
	"fmt"
	"net/http"
)

// HealthCheck
func HealthCheck() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		_, _ = fmt.Fprintf(w, "UP")
	}
}
