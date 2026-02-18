// Copyright (c) 2021 Tigera. All rights reserved.
package server_test

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/prometheus-service/pkg/server"
)

var _ = Describe("Config test", func() {

	It("should set default values on all Config fields if no env config is provided", func() {
		config, err := server.NewConfigFromEnv()

		Expect(err).To(BeNil())
		Expect(config.ListenAddr).To(Equal(":9090"))
		Expect(config.PrometheusEndpoint).To(Equal("http://localhost:9090"))
		Expect(config.PrometheusUrl.Scheme).To(Equal("http"))
		Expect(config.PrometheusUrl.Host).To(Equal("localhost:9090"))
	})

	It("should get env vars set for the corresponding Config fields", func() {
		_ = os.Setenv("LISTEN_ADDR", "localhost:9090")
		_ = os.Setenv("PROMETHEUS_ENDPOINT_URL", "http://calico-node-prometheus.tigera-prometheus.svc.cluster.local:9090")
		defer func() { _ = os.Unsetenv("LISTEN_ADDR") }()
		defer func() { _ = os.Unsetenv("PROMETHEUS_ENDPOINT_URL") }()

		config, err := server.NewConfigFromEnv()

		Expect(err).To(BeNil())
		Expect(config.ListenAddr).To(Equal("localhost:9090"))
		Expect(config.PrometheusEndpoint).To(Equal("http://calico-node-prometheus.tigera-prometheus.svc.cluster.local:9090"))
		Expect(config.PrometheusUrl.Scheme).To(Equal("http"))
		Expect(config.PrometheusUrl.Host).To(Equal("calico-node-prometheus.tigera-prometheus.svc.cluster.local:9090"))
	})
})
