// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package server_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

func TestServer(t *testing.T) {
	log.SetOutput(GinkgoWriter)
	log.SetLevel(log.DebugLevel)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server Suite")
}
