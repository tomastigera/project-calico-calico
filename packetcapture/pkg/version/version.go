// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package version

import (
	"encoding/json"
	"net/http"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

type version struct {
	BuildDate    string `json:"buildDate"`
	GitCommit    string `json:"gitCommit"`
	GitTag       string `json:"gitTag"`
	BuildVersion string `json:"buildVersion"`
}

// Handler is an HTTP handler that returns the version in json format
func Handler(w http.ResponseWriter, r *http.Request) {
	v := version{
		BuildDate:    buildinfo.BuildDate,
		GitCommit:    buildinfo.GitRevision,
		GitTag:       buildinfo.Version,
		BuildVersion: buildinfo.Version,
	}

	js, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(js)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = w.Write([]byte{'\n'})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
