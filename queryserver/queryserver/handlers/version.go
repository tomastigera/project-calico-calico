// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
package handlers

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

type version struct {
	Version   string `json:"version"`
	BuildDate string `json:"buildDate"`
	GitTagRef string `json:"gitTagRef"`
	GitCommit string `json:"gitCommit"`
}

func VersionHandler(w http.ResponseWriter, r *http.Request) {
	log.WithFields(log.Fields{
		"Version":   buildinfo.Version,
		"BuildDate": buildinfo.BuildDate,
		"GitTagRef": buildinfo.GitRevision,
		"GitCommit": buildinfo.GitRevision,
	}).Debug("Handling version request")

	v := version{
		Version:   buildinfo.Version,
		BuildDate: buildinfo.BuildDate,
		GitTagRef: buildinfo.GitRevision,
		GitCommit: buildinfo.GitRevision,
	}

	js, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(js)
	_, _ = w.Write([]byte{'\n'})
}
