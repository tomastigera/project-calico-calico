// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/projectcalico/calico/pkg/buildinfo"
)

type version struct {
	BuildDate string `json:"buildDate"`
	GitCommit string `json:"gitCommit"`
	GitTag    string `json:"gitTag"`
	Version   string `json:"version"`
}

func VersionHandler(w http.ResponseWriter, r *http.Request) {
	v := version{
		BuildDate: buildinfo.BuildDate,
		GitCommit: buildinfo.GitRevision,
		GitTag:    buildinfo.GitRevision,
		Version:   buildinfo.Version,
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
