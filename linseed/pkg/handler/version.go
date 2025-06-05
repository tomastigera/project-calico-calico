// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package handler

import (
	"net/http"

	"github.com/projectcalico/calico/lma/pkg/httputils"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

type version struct {
	BuildDate    string `json:"buildDate"`
	GitCommit    string `json:"gitCommit"`
	GitTag       string `json:"gitTag"`
	BuildVersion string `json:"buildVersion"`
}

// VersionCheck returns the version in json format
func VersionCheck() http.HandlerFunc {
	v := version{
		BuildDate:    buildinfo.BuildDate,
		GitCommit:    buildinfo.GitRevision,
		GitTag:       buildinfo.Version,
		BuildVersion: buildinfo.Version,
	}

	return func(w http.ResponseWriter, req *http.Request) {
		httputils.Encode(w, v)
	}
}
