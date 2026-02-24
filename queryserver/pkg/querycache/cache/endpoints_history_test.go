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

	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/cache"
)

var (
	//go:embed testdata/prometheus_host_endpoints_response.json
	prometheusHostEndpointsResponse string
	//go:embed testdata/prometheus_workload_endpoints_response.json
	prometheusWorkloadEndpointsResponse string
)

var _ = Describe("Querycache endpoints historical cache tests", func() {

	Context("Retrieve historical data from Prometheus", func() {
		It("should retrieve historical data for host endpoints count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusHostEndpointsResponse))
				Expect(sz).To(Equal(len(prometheusHostEndpointsResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			endpointCache := cache.NewEndpointsCacheHistory(promClient, time.Now())
			Expect(endpointCache).NotTo(BeNil())

			eps := endpointCache.TotalHostEndpoints()
			wg.Wait()
			Expect(eps.Total).To(Equal(11))
			Expect(eps.NumWithNoLabels).To(Equal(22))
			Expect(eps.NumWithNoPolicies).To(Equal(33))
		})

		It("should retrieve historical data for total nodes with no-endpoints count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusWorkloadEndpointsResponse))
				Expect(sz).To(Equal(len(prometheusWorkloadEndpointsResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			endpointCache := cache.NewEndpointsCacheHistory(promClient, time.Now())
			Expect(endpointCache).NotTo(BeNil())

			epsm := endpointCache.TotalWorkloadEndpointsByNamespace()
			wg.Wait()
			Expect(epsm).To(HaveLen(2))

			Expect(epsm).To(HaveKeyWithValue("kube-system", api.EndpointSummary{
				Total:             5,
				NumFailed:         6,
				NumWithNoLabels:   7,
				NumWithNoPolicies: 8,
			}))
			Expect(epsm).To(HaveKeyWithValue("calico-system", api.EndpointSummary{
				Total:             9,
				NumFailed:         10,
				NumWithNoLabels:   11,
				NumWithNoPolicies: 12,
			}))
		})

		It("should return 0 host endpoints count on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			endpointCache := cache.NewEndpointsCacheHistory(promClient, time.Now())
			Expect(endpointCache).NotTo(BeNil())

			eps := endpointCache.TotalHostEndpoints()
			wg.Wait()
			Expect(eps.Total).To(Equal(0))
			Expect(eps.NumWithNoLabels).To(Equal(0))
			Expect(eps.NumWithNoPolicies).To(Equal(0))
		})

		It("should return empty workload endpoints map on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			endpointCache := cache.NewEndpointsCacheHistory(promClient, time.Now())
			Expect(endpointCache).NotTo(BeNil())

			epsm := endpointCache.TotalWorkloadEndpointsByNamespace()
			wg.Wait()
			Expect(epsm).To(HaveLen(0))
		})
	})

})
