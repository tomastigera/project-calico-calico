// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/httputils"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

const (
	// For each request that accesses the backend, there will be 4 requests.
	numQueriesPerReq = 4
)

func CreateMockBackendWithData(rbac RBACFilter, names NameHelper) *MockServiceGraphBackend {
	// Load data.
	var l3 []L3Flow
	var l7 []L7Flow
	var dns []DNSLog
	var events []Event

	content, err := os.ReadFile("testdata/l3.json")
	Expect(err).NotTo(HaveOccurred())
	err = json.Unmarshal(content, &l3)
	Expect(err).NotTo(HaveOccurred())

	content, err = os.ReadFile("testdata/l7.json")
	Expect(err).NotTo(HaveOccurred())
	err = json.Unmarshal(content, &l7)
	Expect(err).NotTo(HaveOccurred())

	content, err = os.ReadFile("testdata/dns.json")
	Expect(err).NotTo(HaveOccurred())
	err = json.Unmarshal(content, &dns)
	Expect(err).NotTo(HaveOccurred())

	content, err = os.ReadFile("testdata/events.json")
	Expect(err).NotTo(HaveOccurred())
	err = json.Unmarshal(content, &events)
	Expect(err).NotTo(HaveOccurred())

	// Labels will be preloaded with value k8s-app = AnyApp and label = any
	labels := []string{"k8s-app == \"AnyApp\"", "label == \"any\""}

	// Will add labels only for services emailservice and shipping service from storefront namespace
	serviceLabels := make(map[v1.NamespacedName]LabelSelectors)
	serviceLabels[v1.NamespacedName{Name: "emailservice", Namespace: "storefront"}] = labels
	serviceLabels[v1.NamespacedName{Name: "shippingservice", Namespace: "storefront"}] = labels

	// Will add label expressions only for replicaset loadgenerator-795cbf498c from storefront namespace
	replicaSetLabels := make(map[v1.NamespacedName]LabelSelectors)
	replicaSetLabels[v1.NamespacedName{Name: "loadgenerator-795cbf498c", Namespace: "storefront"}] = []string{
		"k8s-app in {\"AnyAp\"}", "environment not in {\"prod\"}", "!has(critical)", "has(test)",
	}

	// Create a mock backend.
	return &MockServiceGraphBackend{
		FlowConfig: FlowConfig{
			L3FlowFlushInterval: time.Minute * 5,
			L7FlowFlushInterval: time.Minute * 5,
			DNSLogFlushInterval: time.Minute * 5,
		},
		L3:                l3,
		L7:                l7,
		DNS:               dns,
		Events:            events,
		RBACFilter:        rbac,
		NameHelper:        names,
		ServiceLabels:     serviceLabels,
		ReplicaSetLabels:  replicaSetLabels,
		StatefulSetLabels: make(map[v1.NamespacedName]LabelSelectors),
		DaemonSetLabels:   make(map[v1.NamespacedName]LabelSelectors),
	}
}

var _ = Describe("Service graph cache tests", func() {
	var cache ServiceGraphCache
	var backend *MockServiceGraphBackend
	var fakeClient ctrlclient.WithWatch

	// This is a slow test.
	// Unfortunately we only track down to the second in the cache and so to test the various timeouts we need to
	// have timings around 1s. Sorry! It is just the one test though.

	Context("Service graph cache tests without prefetch", func() {
		BeforeEach(func() {
			cfg := &Config{
				ServiceGraphCacheMaxEntries:        4,
				ServiceGraphCachePolledEntryAgeOut: 4500 * time.Millisecond,
				ServiceGraphCachePollLoopInterval:  1 * time.Second,
				ServiceGraphCachePollQueryInterval: 5 * time.Millisecond,
				ServiceGraphCacheDataSettleTime:    15 * time.Minute,
				ServiceGraphCacheDataPrefetch:      false,
				ServiceGraphCacheFetchL7:           true,
				ServiceGraphCacheFetchDNS:          true,
				ServiceGraphCacheFetchEvents:       true,
			}

			// Create a service graph with a mock backend.
			scheme := kscheme.Scheme
			err := v3.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()
			backend = CreateMockBackendWithData(RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil))
			cache = NewServiceGraphCache(fakeClient, backend, cfg)
		})

		It("handles request timeout", func() {
			By("Blocking the elastic calls")
			// Block the backend.
			backend.SetBlockLinseed()
			now1 := time.Now().UTC()
			tr1 := &lmav1.TimeRange{
				From: now1.Add(-15 * time.Minute),
				To:   now1,
				Now:  &now1,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			By("Requesting data and waiting for the timeout")
			var safeCount int32
			var q1 *ServiceGraphData
			var err1 error
			atomic.AddInt32(&safeCount, 1)
			go func() {
				q1, err1 = cache.GetFilteredServiceGraphData(ctx, &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr1,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }, "3s").Should(BeZero())
			Expect(q1).To(BeNil())
			Expect(err1).To(HaveOccurred())
			Expect(err1).To(BeAssignableToTypeOf(&httputils.HttpStatusError{}))

			herr := err1.(*httputils.HttpStatusError)
			Expect(herr.Status).To(Equal(http.StatusGatewayTimeout))
			msg := struct {
				Duration time.Duration `json:"duration"`
				Reason   string        `json:"reason"`
			}{}
			err := json.Unmarshal([]byte(herr.Msg), &msg)
			Expect(err).NotTo(HaveOccurred())

			Expect(msg.Duration).To(BeNumerically(">=", 1*time.Second))
			Expect(msg.Reason).To(Equal("background query is taking a long time"))
		})

		It("handles data truncation of L3 data", func() {
			backend.L3Err = errDataTruncatedError

			now1 := time.Now().UTC()
			tr1 := &lmav1.TimeRange{
				From: now1.Add(-15 * time.Minute),
				To:   now1,
				Now:  &now1,
			}

			var safeCount int32
			var q1 *ServiceGraphData
			var err1 error
			atomic.AddInt32(&safeCount, 1)
			go func() {
				q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr1,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }, "3s").Should(BeZero())
			Expect(err1).ToNot(HaveOccurred())
			Expect(q1.Truncated).To(BeTrue())
		})

		It("handles data truncation of L7 data", func() {
			backend.L7Err = errDataTruncatedError

			now1 := time.Now().UTC()
			tr1 := &lmav1.TimeRange{
				From: now1.Add(-15 * time.Minute),
				To:   now1,
				Now:  &now1,
			}

			var safeCount int32
			var q1 *ServiceGraphData
			var err1 error
			atomic.AddInt32(&safeCount, 1)
			go func() {
				q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr1,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }, "3s").Should(BeZero())
			Expect(err1).ToNot(HaveOccurred())
			Expect(q1.Truncated).To(BeTrue())
		})

		It("handles data truncation of DNS data", func() {
			backend.DNSErr = errDataTruncatedError

			now1 := time.Now().UTC()
			tr1 := &lmav1.TimeRange{
				From: now1.Add(-15 * time.Minute),
				To:   now1,
				Now:  &now1,
			}

			var safeCount int32
			var q1 *ServiceGraphData
			var err1 error
			atomic.AddInt32(&safeCount, 1)
			go func() {
				q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr1,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }, "3s").Should(BeZero())
			Expect(err1).ToNot(HaveOccurred())
			Expect(q1.Truncated).To(BeTrue())
		})

		It("handles data truncation of Event data", func() {
			backend.EventsErr = errDataTruncatedError

			now1 := time.Now().UTC()
			tr1 := &lmav1.TimeRange{
				From: now1.Add(-15 * time.Minute),
				To:   now1,
				Now:  &now1,
			}

			var safeCount int32
			var q1 *ServiceGraphData
			var err1 error
			atomic.AddInt32(&safeCount, 1)
			go func() {
				q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr1,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }, "3s").Should(BeZero())
			Expect(err1).ToNot(HaveOccurred())
			Expect(q1.Truncated).To(BeTrue())
		})

		It("handles concurrent requests, cache updates and expiration", func() {
			By("Blocking the elastic calls")
			// Block the backend.
			backend.SetBlockLinseed()

			// Create two equivalent relative times (different actual times), and another different time.
			now1 := time.Now().UTC()
			tr1 := &lmav1.TimeRange{
				From: now1.Add(-15 * time.Minute),
				To:   now1,
				Now:  &now1,
			}
			now2 := time.Now().UTC().Add(5 * time.Second)
			tr2 := &lmav1.TimeRange{
				From: now2.Add(-15 * time.Minute),
				To:   now2,
				Now:  &now2,
			}
			now3 := time.Now().UTC().Add(2 * time.Second)
			tr3 := &lmav1.TimeRange{
				From: now3.Add(-15 * time.Minute),
				To:   now3.Add(-10 * time.Minute),
				Now:  &now3,
			}

			By("Triggering three requests (two asking for the same dataset)")
			// Kick off two simultaneous queries.
			var safeCount int32
			var q1, q2, q3 *ServiceGraphData
			var err1, err2, err3 error
			atomic.AddInt32(&safeCount, 3)
			go func() {
				q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr1,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			go func() {
				q2, err2 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr2,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			go func() {
				q3, err3 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr3,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()

			By("Waiting for the correct number of block elastic calls")
			// All requests should be blocked, a single request has 'numQueriesPerReq' concurrent requests, and two out of
			// three of the requests should result in actual queries.
			Eventually(backend.GetNumBlocked).Should(Equal(2 * numQueriesPerReq))

			// Unblock the backend, wait for blocked calls to drop to zero and all async calls to return.
			By("Unblocking elastic and waiting for all three requests to complete.")
			backend.SetUnblockLinseed()
			Eventually(backend.GetNumBlocked).Should(Equal(0))
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }).Should(BeZero())
			Expect(q1).NotTo(BeNil())
			Expect(q2).NotTo(BeNil())
			Expect(q3).NotTo(BeNil())
			Expect(err1).NotTo(HaveOccurred())
			Expect(err2).NotTo(HaveOccurred())
			Expect(err3).NotTo(HaveOccurred())

			// The time range for q1 and q2 should be identical (based on which one triggered the request).
			Expect(q1.TimeIntervals).To(Equal(q2.TimeIntervals))
			Expect(q1.TimeIntervals).NotTo(Equal(q3.TimeIntervals))

			// Data should not be truncated.
			Expect(q1.Truncated).To(BeFalse())

			// The number of calls to get flow config, L3 data, L7 data, DNS logs and events should be 2.
			Expect(backend.GetNumCallsFlowConfig()).To(Equal(2))
			Expect(backend.GetNumCallsL3()).To(Equal(2))
			Expect(backend.GetNumCallsL7()).To(Equal(2))
			Expect(backend.GetNumCallsDNS()).To(Equal(2))
			Expect(backend.GetNumCallsEvents()).To(Equal(2))

			// The number of calls to get RBAC filter and name helper should be 3.
			Expect(backend.GetNumCallsNameHelper()).To(Equal(3))
			Expect(backend.GetNumCallsRBACFilter()).To(Equal(3))

			// Cache should be updated 4 times before timeout.
			By("Waiting for the cache to be updated")
			Eventually(backend.GetNumCallsFlowConfig, "5s").Should(Equal(10))
			Eventually(backend.GetNumCallsL3, "5s").Should(Equal(10))
			Eventually(backend.GetNumCallsL7, "5s").Should(Equal(10))
			Eventually(backend.GetNumCallsDNS, "5s").Should(Equal(10))
			Eventually(backend.GetNumCallsEvents, "5s").Should(Equal(10))

			By("Waiting for the cache entries to age out")
			Eventually(cache.GetCacheSize, "2s").Should(BeZero())
			Expect(backend.GetNumCallsFlowConfig()).To(Equal(10))
			Expect(backend.GetNumCallsL3()).To(Equal(10))
			Expect(backend.GetNumCallsL7()).To(Equal(10))
			Expect(backend.GetNumCallsDNS()).To(Equal(10))
			Expect(backend.GetNumCallsEvents()).To(Equal(10))

			By("Querying a fix time interval")
			trNonRelative := &lmav1.TimeRange{
				From: now3.Add(-10 * time.Hour),
				To:   now3.Add(-5 * time.Hour),
			}
			q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					TimeRange: trNonRelative,
				},
			})
			Expect(q1).NotTo(BeNil())
			Expect(q1.TimeIntervals).To(HaveLen(1))
			Expect(err1).NotTo(HaveOccurred())

			By("Querying a single entry and checking it doesn't age out while being queried.")
			timeRanges := make(map[int64]int)
			for i := 0; i < 10; i++ {
				q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr1,
					},
				})
				Expect(q1).NotTo(BeNil())
				Expect(q1.TimeIntervals).To(HaveLen(1))
				Expect(err1).NotTo(HaveOccurred())
				timeRanges[q1.TimeIntervals[0].From.Unix()]++
				time.Sleep(500 * time.Millisecond)
			}

			// Each time range should have been queried between one and three times - really between 2-3 times, but timing
			// tests can inevitably be flaky so just assume >=1.
			Expect(timeRanges).NotTo(HaveLen(1))
			for _, num := range timeRanges {
				Expect(num).To(BeNumerically(">=", 1), fmt.Sprintf("%v", timeRanges))
				Expect(num).To(BeNumerically("<=", 3), fmt.Sprintf("%v", timeRanges))
			}

			By("Waiting for the cache entry to age out - the non relative entry will not age out")
			Consistently(cache.GetCacheSize, "4s").Should(Equal(2))
			Eventually(cache.GetCacheSize, "2s").Should(Equal(1))

			By("Requesting more than the max number of relative times")
			for i := 0; i < 50; i++ {
				tri := &lmav1.TimeRange{
					From: now3.Add(time.Duration(-i*6) * time.Minute),
					To:   now3.Add(time.Duration(-i*5) * time.Minute),
					Now:  &now3,
				}
				q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tri,
					},
				})
				Expect(q1).NotTo(BeNil())
				Expect(q1.TimeIntervals).To(HaveLen(1))
				Expect(err1).NotTo(HaveOccurred())
			}

			By("Checking the cache size and that the cache fully empties of relative times")
			Consistently(cache.GetCacheSize, "4s").Should(Equal(4))
			Eventually(cache.GetCacheSize, "2s").Should(Equal(0))

			// By checking ForceUpdate actually forces an additional query.
			By("Checking force refresh forces a refresh")
			current := backend.GetNumCallsL3()
			q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					TimeRange: tr1,
				},
			})
			Expect(q1).NotTo(BeNil())
			Expect(q1.TimeIntervals).To(HaveLen(1))
			Expect(err1).NotTo(HaveOccurred())
			Expect(backend.GetNumCallsL3()).To(Equal(current + 1))

			q1, err1 = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					TimeRange:    tr1,
					ForceRefresh: true,
				},
			})
			Expect(q1).NotTo(BeNil())
			Expect(q1.TimeIntervals).To(HaveLen(1))
			Expect(err1).NotTo(HaveOccurred())
			Expect(backend.GetNumCallsL3()).To(Equal(current + 2))

			// By checking ForceUpdate actually forces an additional query.
			By("Checking force refresh doesn't force a refresh if the request is pending by kicking off two simultaneously")
			backend.SetBlockLinseed()
			atomic.AddInt32(&safeCount, 2)
			go func() {
				_, _ = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange:    tr2,
						ForceRefresh: true,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			go func() {
				_, _ = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange:    tr2,
						ForceRefresh: true,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			// We don't know when both goroutines will be blocked waiting, so all we can do it sleep for a bit.
			time.Sleep(100 * time.Millisecond)

			// Now unblock elastic. One of the requests will use the results of the other event though both request have
			// ForceRefresh set to true.
			backend.SetUnblockLinseed()
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }).Should(BeZero())
			Expect(backend.GetNumCallsL3()).To(Equal(current + 3))

			// By checking context can be cancelled by user.
			By("Checking request can be cancelled")
			thisctx, thiscancel := context.WithCancel(context.Background())
			backend.SetBlockLinseed()
			atomic.AddInt32(&safeCount, 1)
			go func() {
				_, _ = cache.GetFilteredServiceGraphData(thisctx, &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr3,
					},
				})
				atomic.AddInt32(&safeCount, -1)
			}()
			Eventually(backend.GetNumBlocked).ShouldNot(BeZero())

			// Cancel the request and it should return without unblocking the request.
			thiscancel()
			Eventually(func() int32 { return atomic.LoadInt32(&safeCount) }).Should(BeZero())
			backend.SetUnblockLinseed()
		})

		It("creates separate cache entries for namespace-scoped requests", func() {
			now := time.Now().UTC()
			tr := &lmav1.TimeRange{
				From: now.Add(-15 * time.Minute),
				To:   now,
				Now:  &now,
			}

			// Make requests with same time range but different namespace focus
			namespaces := []string{"storefront", "default", "kube-system"}

			for _, ns := range namespaces {
				_, err := cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
					ServiceGraphRequest: &v1.ServiceGraphRequest{
						TimeRange: tr,
						Cluster:   "cluster",
						SelectedView: v1.GraphView{
							Focus: []v1.GraphNodeID{v1.GraphNodeID("namespace/" + ns)},
						},
						CacheByFocus: true,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			}

			// Request without namespace focus
			_, err := cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					TimeRange: tr,
					Cluster:   "cluster",
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify 4 separate cache entries (3 namespaced + 1 unfocused)
			Expect(cache.GetCacheSize()).To(Equal(4))
			Expect(backend.GetNumCallsL3()).To(Equal(4))

			// Verify re-requesting same namespace focus reuses cache
			initial := backend.GetNumCallsL3()
			_, err = cache.GetFilteredServiceGraphData(context.Background(), &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					TimeRange: tr,
					Cluster:   "cluster",
					SelectedView: v1.GraphView{
						Focus: []v1.GraphNodeID{"namespace/storefront"},
					},
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(backend.GetNumCallsL3()).To(Equal(initial))
		})
	})

	Context("Service graph cache tests with only L3 data for free tier", func() {
		BeforeEach(func() {
			cfg := &Config{
				ServiceGraphCacheMaxEntries:        5,
				ServiceGraphCachePolledEntryAgeOut: 1 * time.Hour,
				ServiceGraphCachePollLoopInterval:  1 * time.Second,
				ServiceGraphCachePollQueryInterval: 5 * time.Millisecond,
				ServiceGraphCacheDataSettleTime:    15 * time.Minute,
				ServiceGraphCacheDataPrefetch:      true,
				ServiceGraphCacheFetchL7:           false,
				ServiceGraphCacheFetchDNS:          false,
				ServiceGraphCacheFetchEvents:       false,
			}

			// Create a service graph with a mock backend.
			scheme := kscheme.Scheme
			err := v3.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()

			// create a managed clusters
			managedClusterNames := []string{"managed-1"}
			for _, managedClusterName := range managedClusterNames {
				managedCluster := &v3.ManagedCluster{
					ObjectMeta: metav1.ObjectMeta{Name: managedClusterName},
					Spec:       v3.ManagedClusterSpec{},
				}
				err = fakeClient.Create(context.Background(), managedCluster)
				Expect(err).NotTo(HaveOccurred())
			}

			backend = CreateMockBackendWithData(RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil))
			cache = NewServiceGraphCache(fakeClient, backend, cfg)
		})

		It("should prefetch raw data", func() {
			// 1 (cluster) + 1 (managed-1)
			Expect(cache.GetCacheSize()).To(Equal(2))

			Expect(backend.GetNumCallsFlowConfig()).To(Equal(2))
			Expect(backend.GetNumCallsL3()).To(Equal(2))
			Expect(backend.GetNumCallsL7()).To(Equal(0))
			Expect(backend.GetNumCallsDNS()).To(Equal(0))
			Expect(backend.GetNumCallsEvents()).To(Equal(0))

			// default manager UI time range: now-15m->now-0m
			ctx := context.Background()
			now := time.Now().UTC()
			timeRange := &lmav1.TimeRange{
				From: now.Add(-15 * time.Minute),
				To:   now,
				Now:  &now,
			}

			// request "managed-1" data which should be in cache already
			_, err := cache.GetFilteredServiceGraphData(ctx, &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					Cluster:   "managed-1",
					TimeRange: timeRange,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			Eventually(backend.GetNumCallsL3(), "5s").Should(Equal(2))
			Eventually(backend.GetNumCallsL7(), "5s").Should(Equal(0))
			Eventually(backend.GetNumCallsDNS(), "5s").Should(Equal(0))
			Eventually(backend.GetNumCallsEvents(), "5s").Should(Equal(0))
		})
	})

	Context("Service graph cache tests with prefetch", func() {
		BeforeEach(func() {
			cfg := &Config{
				ServiceGraphCacheMaxEntries:        5,
				ServiceGraphCachePolledEntryAgeOut: 1 * time.Hour,
				ServiceGraphCachePollLoopInterval:  1 * time.Second,
				ServiceGraphCachePollQueryInterval: 5 * time.Millisecond,
				ServiceGraphCacheDataSettleTime:    15 * time.Minute,
				ServiceGraphCacheDataPrefetch:      true,
				ServiceGraphCacheFetchL7:           true,
				ServiceGraphCacheFetchDNS:          true,
				ServiceGraphCacheFetchEvents:       true,
			}

			// Create a service graph with a mock backend.
			scheme := kscheme.Scheme
			err := v3.AddToScheme(scheme)
			Expect(err).NotTo(HaveOccurred())
			fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()

			// create some managed clusters
			managedClusterNames := []string{"managed-1", "managed-2"}
			for _, managedClusterName := range managedClusterNames {
				managedCluster := &v3.ManagedCluster{
					ObjectMeta: metav1.ObjectMeta{Name: managedClusterName},
					Spec:       v3.ManagedClusterSpec{},
				}
				err = fakeClient.Create(context.Background(), managedCluster)
				Expect(err).NotTo(HaveOccurred())
			}

			backend = CreateMockBackendWithData(RBACFilterIncludeAll{}, NewMockNameHelper(nil, nil))
			cache = NewServiceGraphCache(fakeClient, backend, cfg)
		})

		It("should prefetch raw data", func() {
			// 1 (cluster) + 2 (managed-1 and managed-2)
			Expect(cache.GetCacheSize()).To(Equal(3))

			Expect(backend.GetNumCallsFlowConfig()).To(Equal(3))
			Expect(backend.GetNumCallsL3()).To(Equal(3))
			Expect(backend.GetNumCallsL7()).To(Equal(3))
			Expect(backend.GetNumCallsDNS()).To(Equal(3))
			Expect(backend.GetNumCallsEvents()).To(Equal(3))

			// default manager UI time range: now-15m->now-0m
			ctx := context.Background()
			now := time.Now().UTC()
			timeRange := &lmav1.TimeRange{
				From: now.Add(-15 * time.Minute),
				To:   now,
				Now:  &now,
			}

			// request "cluster" data which should be in cache already
			_, err := cache.GetFilteredServiceGraphData(ctx, &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					Cluster:   "cluster",
					TimeRange: timeRange,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			Eventually(backend.GetNumCallsL3(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsL7(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsDNS(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsEvents(), "5s").Should(Equal(3))

			// request "managed-1" data which should be in cache already
			_, err = cache.GetFilteredServiceGraphData(ctx, &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					Cluster:   "managed-1",
					TimeRange: timeRange,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			Eventually(backend.GetNumCallsL3(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsL7(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsDNS(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsEvents(), "5s").Should(Equal(3))

			// request "managed-2" data which should be in cache already
			_, err = cache.GetFilteredServiceGraphData(ctx, &RequestData{
				ServiceGraphRequest: &v1.ServiceGraphRequest{
					Cluster:   "managed-2",
					TimeRange: timeRange,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			Eventually(backend.GetNumCallsL3(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsL7(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsDNS(), "5s").Should(Equal(3))
			Eventually(backend.GetNumCallsEvents(), "5s").Should(Equal(3))
		})
	})
})
