// Copyright (c) 2019,2022 Tigera, Inc. All rights reserved.

package server

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type health struct {
}

// Determine which handler to execute based on HTTP method.
func (h *health) apiHandle(w http.ResponseWriter, r *http.Request) {
	log.Tracef("%s for %s from %s", r.Method, r.URL, r.RemoteAddr)
	switch r.Method {
	case http.MethodGet:
		h.returnJSON(w, "OK")
	default:
		http.NotFound(w, r)
	}
}

func (h *health) returnJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error("Error while encoding data for response")
		// TODO: We need named errors, with predefined
		// error codes and user-friendly error messages here
		http.Error(w, "\"An error occurred\"", 500)
	}
}
