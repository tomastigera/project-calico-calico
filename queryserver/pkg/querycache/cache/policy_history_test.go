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
	//go:embed testdata/prometheus_global_network_policy_response.json
	prometheusGlobalNetworkPolicyResponse string
	//go:embed testdata/prometheus_network_policy_response.json
	prometheusNetworkPolicyResponse string
)

var _ = Describe("Querycache policy historical cache tests", func() {

	Context("Retrieve historical data from Prometheus", func() {
		It("should retrieve historical data for global network policy count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusGlobalNetworkPolicyResponse))
				Expect(sz).To(Equal(len(prometheusGlobalNetworkPolicyResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			policyCache := cache.NewPoliciesCacheHistory(promClient, time.Now())
			Expect(policyCache).NotTo(BeNil())

			pc := policyCache.TotalGlobalNetworkPolicies()
			wg.Wait()
			Expect(pc.Total).To(Equal(11))
			Expect(pc.NumUnmatched).To(Equal(22))
		})

		It("should retrieve historical data for network policy count from Prometheus", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusOK)
				sz, err := w.Write([]byte(prometheusNetworkPolicyResponse))
				Expect(sz).To(Equal(len(prometheusNetworkPolicyResponse)))
				Expect(err).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			policyCache := cache.NewPoliciesCacheHistory(promClient, time.Now())
			Expect(policyCache).NotTo(BeNil())

			pcm := policyCache.TotalNetworkPoliciesByNamespace()
			wg.Wait()
			Expect(pcm).To(HaveLen(2))

			Expect(pcm).To(HaveKeyWithValue("kube-system", api.PolicySummary{
				Total:        3,
				NumUnmatched: 4,
			}))
			Expect(pcm).To(HaveKeyWithValue("calico-system", api.PolicySummary{
				Total:        5,
				NumUnmatched: 6,
			}))
		})

		It("should return 0 global network policy count on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			policyCache := cache.NewPoliciesCacheHistory(promClient, time.Now())
			Expect(policyCache).NotTo(BeNil())

			pc := policyCache.TotalGlobalNetworkPolicies()
			wg.Wait()
			Expect(pc.Total).To(Equal(0))
			Expect(pc.NumUnmatched).To(Equal(0))
		})

		It("should return empty network policies map on error", func() {
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				w.WriteHeader(http.StatusBadRequest)
			}))
			defer ts.Close()

			promClient, err := cache.NewPrometheusClient(ts.URL, "fake-jwt-token")
			Expect(err).NotTo(HaveOccurred())

			policyCache := cache.NewPoliciesCacheHistory(promClient, time.Now())
			Expect(policyCache).NotTo(BeNil())

			pcm := policyCache.TotalNetworkPoliciesByNamespace()
			wg.Wait()
			Expect(pcm).To(HaveLen(0))
		})
	})

})
