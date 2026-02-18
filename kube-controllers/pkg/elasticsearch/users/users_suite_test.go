// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package users

import (
	"testing"

	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
)

func TestConfig(t *testing.T) {
	gomega.RegisterFailHandler(ginkgo.Fail)
	suiteConfig, reporterConfig := ginkgo.GinkgoConfiguration()
	reporterConfig.JUnitReport = "./report/elasticsearch_users_suite.xml"
	ginkgo.RunSpecs(t, "Elasticsearch Users Suite", suiteConfig, reporterConfig)
}
