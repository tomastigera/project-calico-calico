// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package handlers

import (
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func GetIgnoreHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Tracef("%s for %s from %s", r.Method, r.URL, r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "All good")
	}
}
