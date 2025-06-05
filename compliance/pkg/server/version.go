// Copyright (c) 2018 Tigera, Inc. All rights reserved.
package server

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/typha/pkg/buildinfo"
)

// handleVersion implements the version endpoint which returns JSON encapsulated version info.
func (_ *server) handleVersion(response http.ResponseWriter, _ *http.Request) {
	log.WithFields(log.Fields{
		"Version":   buildinfo.GitVersion,
		"BuildDate": buildinfo.BuildDate,
		"GitTagRef": buildinfo.GitRevision,
		"GitCommit": buildinfo.GitRevision,
	}).Debug("Handling version request")

	v := VersionData{
		Version:   buildinfo.GitVersion,
		BuildDate: buildinfo.BuildDate,
		GitTagRef: buildinfo.GitRevision,
		GitCommit: buildinfo.GitRevision,
	}

	writeJSON(response, v, true)
}
