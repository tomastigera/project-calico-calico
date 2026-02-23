// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package http

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func ReturnJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error("Error while encoding data for response")
		http.Error(w, "\"An error occurred\"", 500)
	}
}
