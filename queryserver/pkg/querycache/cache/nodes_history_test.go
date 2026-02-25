// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package cache_test

import (
	_ "embed"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/queryserver/pkg/querycache/cache"
)

var (
	//go:embed testdata/prometheus_node_response.json
	prometheusNodeResponse string
	//go:embed testdata/prometheus_node_no_endpoints_response.json
	prometheusNodeNoEndpointsResponse string
	//go:embed testdata/prometheus_node_no_host_endpoints_response.json
	prometheusNodeNoHostEndpointsResponse string
	//go:embed testdata/prometheus_node_no_workload_endpoints_response.json
	prometheusNodeNoWorkloadEndpointsResponse string
)

var _ = Describe("Querycache node historical cache tests", func() {

	Context("Retrieve historical data from Prometheus", func() {
		It("should retrieve historical data for total nodes count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusNodeResponse))
				Expect(sz).To(Equal(len(prometheusNodeResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodes()
			wg.Wait()
			Expect(n).To(Equal(78))
		})

		It("should retrieve historical data for total nodes with no-endpoints count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusNodeNoEndpointsResponse))
				Expect(sz).To(Equal(len(prometheusNodeNoEndpointsResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodesWithNoEndpoints()
			wg.Wait()
			Expect(n).To(Equal(12))
		})

		It("should retrieve historical data for total nodes with no-host-endpoints count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusNodeNoHostEndpointsResponse))
				Expect(sz).To(Equal(len(prometheusNodeNoHostEndpointsResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodesWithNoHostEndpoints()
			wg.Wait()
			Expect(n).To(Equal(34))
		})

		It("should retrieve historical data for total nodes with no-workload-endpoints count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusNodeNoWorkloadEndpointsResponse))
				Expect(sz).To(Equal(len(prometheusNodeNoWorkloadEndpointsResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodesWithNoWorkloadEndpoints()
			wg.Wait()
			Expect(n).To(Equal(56))
		})

		It("should return 0 total nodes count on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodes()
			wg.Wait()
			Expect(n).To(Equal(0))
		})

		It("should return 0 total nodes with no-endpoints count on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodesWithNoEndpoints()
			wg.Wait()
			Expect(n).To(Equal(0))
		})

		It("should return 0 total nodes with no-host-endpoints count on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodesWithNoHostEndpoints()
			wg.Wait()
			Expect(n).To(Equal(0))
		})

		It("should return 0 total nodes with no-workload-endpoints count on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			nodeCache := cache.NewNodeCacheHistory(promClient, time.Now())
			Expect(nodeCache).NotTo(BeNil())

			n := nodeCache.TotalNodesWithNoWorkloadEndpoints()
			wg.Wait()
			Expect(n).To(Equal(0))
		})
	})

})
