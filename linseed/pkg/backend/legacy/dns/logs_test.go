// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package dns_test

import (
	"context"
	"encoding/json"
	gojson "encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	backendutils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// TestCreateDNSLog tests running a real elasticsearch query to create a DNS log.
func TestCreateDNSLog(t *testing.T) {
	RunAllModes(t, "TestCreateDNSLog", func(t *testing.T) {
		cluster1Info := bapi.ClusterInfo{Cluster: cluster1}
		cluster2Info := bapi.ClusterInfo{Cluster: cluster2}
		cluster3Info := bapi.ClusterInfo{Cluster: cluster3}

		ip := net.ParseIP("10.0.1.1")

		reqTime := time.Unix(0, 0)
		// Create a dummy log.
		f := v1.DNSLog{
			StartTime:       reqTime,
			EndTime:         reqTime,
			Type:            v1.DNSLogTypeLog,
			Count:           1,
			ClientName:      "client-name",
			ClientNameAggr:  "client-",
			ClientNamespace: "default",
			ClientIP:        &ip,
			ClientLabels:    uniquelabels.Make(map[string]string{"pickles": "good"}),
			QName:           "qname",
			QType:           v1.DNSType(layers.DNSTypeA),
			QClass:          v1.DNSClass(layers.DNSClassIN),
			RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
			RRSets:          v1.DNSRRSets{},
			Servers: []v1.DNSServer{
				{
					Endpoint: v1.Endpoint{
						Name:           "kube-dns-one",
						AggregatedName: "kube-dns",
						Namespace:      "kube-system",
					},
					IP:     net.ParseIP("10.0.0.10"),
					Labels: uniquelabels.Make(map[string]string{"app": "dns"}),
				},
			},
			Latency: v1.DNSLatency{
				Count: 15,
				Mean:  5 * time.Second,
				Max:   10 * time.Second,
			},
			LatencyCount: 100,
			LatencyMean:  100,
			LatencyMax:   100,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			resp, err := lb.Create(ctx, clusterInfo, []v1.DNSLog{f})
			require.NoError(t, err)
			require.Empty(t, resp.Errors)
			// Refresh.
			err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)
		}

		// List out the log we just created.
		params := v1.DNSLogParams{}
		params.TimeRange = &lmav1.TimeRange{}
		params.TimeRange.From = reqTime.Add(-20 * time.Minute)
		params.TimeRange.To = reqTime.Add(1 * time.Minute)

		t.Run("should query single cluster", func(t *testing.T) {
			clusterInfo := cluster1Info

			listResp, err := lb.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, listResp.Items, 1)

			// Compare the result. Timestamps don't serialize well,
			// so ignore them in the comparison.
			actual := listResp.Items[0]
			require.NotEqual(t, time.Time{}, actual.StartTime)
			require.NotEqual(t, time.Time{}, actual.EndTime)
			actual.StartTime = f.StartTime
			actual.EndTime = f.EndTime
			backendutils.AssertDNSLogIDAndClusterAndReset(t, clusterInfo.Cluster, &actual)
			require.Equal(t, f, actual)

			// If we update the query params to specify matching against the "generated_time"
			// field, we should get no results, because the time right now (>=2023) is years
			// later than reqTime (1970).
			params.TimeRange.Field = lmav1.FieldGeneratedTime
			listResp, err = lb.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, listResp.Items, 0)

			// Now if we keep using "generated_time" and change the time range to cover the time
			// period when this test has been running, we should get back that log again.
			params.TimeRange.To = time.Now().Add(10 * time.Second)
			params.TimeRange.From = params.TimeRange.To.Add(-5 * time.Minute)
			listResp, err = lb.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, listResp.Items, 1)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)
			listResp, err := lb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, &params)
			require.NoError(t, err)
			require.Len(t, listResp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, backendutils.MatchIn(listResp.Items, backendutils.DNSLogClusterEquals(cluster)), "Expected cluster %s in result", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			listResp, err := lb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, backendutils.MatchIn(listResp.Items, backendutils.DNSLogClusterEquals(cluster)), "Expected cluster %s in result", cluster)
			}
		})
	})
}

// TestAggregations tests running a real elasticsearch query to get aggregations.
func TestAggregations(t *testing.T) {
	RunAllModes(t, "should return time-series DNS aggregation results", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
		ip := net.ParseIP("10.0.1.1")

		// Start the test numLogs minutes in the past.
		numLogs := 5
		timeBetweenLogs := 10 * time.Second
		testStart := time.Unix(0, 0)
		now := testStart.Add(time.Duration(numLogs) * time.Minute)

		// Several dummy logs.
		logs := []v1.DNSLog{}
		for i := 1; i < numLogs; i++ {
			start := testStart.Add(time.Duration(i) * time.Second)
			end := start.Add(timeBetweenLogs)
			log := v1.DNSLog{
				StartTime:       start,
				EndTime:         end,
				Type:            v1.DNSLogTypeLog,
				Count:           1,
				ClientName:      "client-name",
				ClientNameAggr:  "client-",
				ClientNamespace: "default",
				ClientIP:        &ip,
				ClientLabels:    uniquelabels.Make(map[string]string{"pickles": "good"}),
				QName:           "qname",
				QType:           v1.DNSType(layers.DNSTypeA),
				QClass:          v1.DNSClass(layers.DNSClassIN),
				RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
				Servers: []v1.DNSServer{
					{
						Endpoint: v1.Endpoint{
							Name:           "kube-dns-one",
							AggregatedName: "kube-dns",
							Namespace:      "kube-system",
							Type:           v1.WEP,
						},
						IP:     net.ParseIP("10.0.0.10"),
						Labels: uniquelabels.Make(map[string]string{"app": "dns"}),
					},
				},
				Latency: v1.DNSLatency{
					Count: 1,
					Mean:  time.Duration(i) * time.Millisecond,
					Max:   time.Duration(2*i) * time.Millisecond,
				},
				LatencyCount: 1,
				LatencyMean:  time.Duration(i) * time.Millisecond,
				LatencyMax:   time.Duration(2*i) * time.Millisecond,
			}
			logs = append(logs, log)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := lb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Empty(t, resp.Errors)

		// Refresh.
		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.DNSAggregationParams{}
		params.TimeRange = &lmav1.TimeRange{}
		params.TimeRange.From = testStart
		params.TimeRange.To = now
		params.NumBuckets = 4

		// Add a simple aggregation to add up the count of logs.
		sumAgg := elastic.NewSumAggregation().Field("count")
		src, err := sumAgg.Source()
		require.NoError(t, err)
		bytes, err := json.Marshal(src)
		require.NoError(t, err)
		params.Aggregations = map[string]gojson.RawMessage{"count": bytes}

		// Use the backend to perform a query.
		aggs, err := lb.Aggregations(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.NotNil(t, aggs)

		ts, ok := aggs.AutoDateHistogram("tb")
		require.True(t, ok)

		// We asked for 4 buckets.
		require.Len(t, ts.Buckets, 4)

		times := []string{
			"1970-01-01T00:00:11.000Z",
			"1970-01-01T00:00:12.000Z",
			"1970-01-01T00:00:13.000Z",
			"1970-01-01T00:00:14.000Z",
		}

		for i, b := range ts.Buckets {
			require.Equal(t, int64(1), b.DocCount, fmt.Sprintf("Bucket %d", i))

			// We asked for a count agg, which should include a single log
			// in each bucket.
			count, ok := b.Sum("count")
			require.True(t, ok, "Bucket missing count agg")
			require.NotNil(t, count.Value)
			require.Equal(t, float64(1), *count.Value)

			// The key should be the timestamp for the bucket.
			require.NotNil(t, b.KeyAsString)
			require.Equal(t, times[i], *b.KeyAsString)
		}
	})

	RunAllModes(t, "should return aggregate DNS stats", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
		ip := net.ParseIP("10.0.1.1")

		// Start the test numLogs minutes in the past.
		numLogs := 5
		timeBetweenLogs := 10 * time.Second
		testStart := time.Unix(0, 0)
		now := testStart.Add(time.Duration(numLogs) * time.Minute)

		// Several dummy logs.
		logs := []v1.DNSLog{}
		for i := 1; i < numLogs; i++ {
			start := testStart.Add(time.Duration(i) * time.Second)
			end := start.Add(timeBetweenLogs)
			log := v1.DNSLog{
				StartTime:       start,
				EndTime:         end,
				Type:            v1.DNSLogTypeLog,
				Count:           1,
				ClientName:      "client-name",
				ClientNameAggr:  "client-",
				ClientNamespace: "default",
				ClientIP:        &ip,
				ClientLabels:    uniquelabels.Make(map[string]string{"pickles": "good"}),
				QName:           "qname",
				QType:           v1.DNSType(layers.DNSTypeA),
				QClass:          v1.DNSClass(layers.DNSClassIN),
				RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
				Servers: []v1.DNSServer{
					{
						Endpoint: v1.Endpoint{
							Name:           "kube-dns-one",
							AggregatedName: "kube-dns",
							Namespace:      "kube-system",
							Type:           v1.WEP,
						},
						IP:     net.ParseIP("10.0.0.10"),
						Labels: uniquelabels.Make(map[string]string{"app": "dns"}),
					},
				},
				Latency: v1.DNSLatency{
					Count: 1,
					Mean:  time.Duration(i) * time.Millisecond,
					Max:   time.Duration(2*i) * time.Millisecond,
				},
				LatencyCount: 1,
				LatencyMean:  time.Duration(i) * time.Millisecond,
				LatencyMax:   time.Duration(2*i) * time.Millisecond,
			}
			logs = append(logs, log)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := lb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Empty(t, resp.Errors)

		// Refresh.
		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.DNSAggregationParams{}
		params.TimeRange = &lmav1.TimeRange{}
		params.TimeRange.From = testStart
		params.TimeRange.To = now
		params.NumBuckets = 0 // Return aggregated stats over the whole time range.

		// Add a simple aggregation to add up the count of logs.
		sumAgg := elastic.NewSumAggregation().Field("count")
		src, err := sumAgg.Source()
		require.NoError(t, err)
		bytes, err := json.Marshal(src)
		require.NoError(t, err)
		params.Aggregations = map[string]gojson.RawMessage{"count": bytes}

		// Use the backend to perform a stats query.
		result, err := lb.Aggregations(ctx, clusterInfo, &params)
		require.NoError(t, err)

		// We should get a sum aggregation with all 4 logs.
		count, ok := result.ValueCount("count")
		require.True(t, ok)
		require.NotNil(t, count.Value)
		require.Equal(t, float64(4), *count.Value)
	})
}

func TestPreserveIDs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should preserve IDs across bulk ingestion requests (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			numLogs := 5
			testStart := time.Unix(0, 0).UTC()

			// Several dummy logs.
			logs := []v1.DNSLog{}
			for i := 1; i <= numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				log := v1.DNSLog{
					StartTime: start,
					EndTime:   start.Add(time.Duration(5) * time.Second),
				}
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := migration.Create(ctx, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Read it back and make sure generated time values are what we expect.
			allOpts := v1.DNSLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: testStart.Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			}
			first, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, first.Items, numLogs)

			bulk, err := migration.Create(ctx, clusterInfo, first.Items)
			require.NoError(t, err)
			require.Empty(t, bulk.Errors)

			second, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, second.Items, numLogs)

			for _, log := range first.Items {
				require.NotEmpty(t, log.ID)
				backendutils.AssertGeneratedTimeAndReset[v1.DNSLog](t, &log)
			}
			for _, log := range second.Items {
				require.NotEmpty(t, log.ID)
				backendutils.AssertGeneratedTimeAndReset[v1.DNSLog](t, &log)
			}

			require.Equal(t, first.Items, second.Items)

			// Refresh before cleaning up data
			err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

		})
	}
}

func TestDNSLogFiltering(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.DNSLogParams

		// Configuration for which logs are expected to match.
		ExpectLog1 bool
		ExpectLog2 bool

		// Whether to perform an equality comparison on the returned
		// logs. Can be useful for tests where stats differ.
		SkipComparison bool
	}

	numExpected := func(tc testCase) int {
		num := 0
		if tc.ExpectLog1 {
			num++
		}
		if tc.ExpectLog2 {
			num++
		}
		return num
	}

	testcases := []testCase{
		{
			Name: "should support selection based on host match",
			Params: v1.DNSLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: `host = "my-host"`,
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support selection based on latency fields match",
			Params: v1.DNSLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: `latency_count = 100 AND latency_mean = 200 AND latency_max = 300`,
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on nested field match",
			Params: v1.DNSLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "\"servers.name\" IN {\"*be-dns-tw*\"}",
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
	}

	ip := net.ParseIP("10.0.1.1")
	reqTime := time.Now().UTC()

	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		for _, testcase := range testcases {
			// Each testcase creates multiple dns logs, and then uses
			// different filtering parameters provided in the params
			// to query one or more dns logs.
			name := fmt.Sprintf("%s (tenant=%s)", testcase.Name, tenant)
			RunAllModes(t, name, func(t *testing.T) {
				clusterInfo1 := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
				clusterInfo2 := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
				clusterInfo3 := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

				// Set the time range for the test. We set this per-test
				// so that the time range captures the windows that the logs
				// are created in.
				tr := &lmav1.TimeRange{}
				tr.From = time.Now().Add(-5 * time.Minute)
				tr.To = time.Now().Add(5 * time.Minute)
				params := testcase.Params
				params.TimeRange = tr

				logs := []v1.DNSLog{
					{
						StartTime:       reqTime,
						EndTime:         reqTime,
						Type:            v1.DNSLogTypeLog,
						Count:           1,
						ClientName:      "client-name",
						ClientNameAggr:  "client-",
						ClientNamespace: "default",
						ClientIP:        &ip,
						ClientLabels:    uniquelabels.Make(map[string]string{"pickles": "good"}),
						QName:           "qname",
						QType:           v1.DNSType(layers.DNSTypeA),
						QClass:          v1.DNSClass(layers.DNSClassIN),
						RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
						RRSets:          v1.DNSRRSets{},
						Servers: []v1.DNSServer{
							{
								Endpoint: v1.Endpoint{
									Name:           "kube-dns-one",
									AggregatedName: "kube-dns",
									Namespace:      "kube-system",
								},
								IP:     net.ParseIP("10.0.0.10"),
								Labels: uniquelabels.Make(map[string]string{"app": "dns"}),
							},
						},
						Latency: v1.DNSLatency{
							Count: 15,
							Mean:  5 * time.Second,
							Max:   10 * time.Second,
						},
						Host: "my-host",
					},
					{
						StartTime:       reqTime,
						EndTime:         reqTime,
						Type:            v1.DNSLogTypeLog,
						Count:           1,
						ClientName:      "client-name",
						ClientNameAggr:  "client-",
						ClientNamespace: "default",
						ClientIP:        &ip,
						ClientLabels:    uniquelabels.Make(map[string]string{"pickles": "good"}),
						QName:           "qname",
						QType:           v1.DNSType(layers.DNSTypeA),
						QClass:          v1.DNSClass(layers.DNSClassIN),
						RCode:           v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
						RRSets:          v1.DNSRRSets{},
						Servers: []v1.DNSServer{
							{
								Endpoint: v1.Endpoint{
									Name:           "kube-dns-two",
									AggregatedName: "kube-dns",
									Namespace:      "kube-system",
								},
								IP:     net.ParseIP("10.0.0.10"),
								Labels: uniquelabels.Make(map[string]string{"app": "dns"}),
							},
						},
						Latency: v1.DNSLatency{
							Count: 15,
							Mean:  5 * time.Second,
							Max:   10 * time.Second,
						},
						LatencyCount: 100,
						LatencyMean:  200,
						LatencyMax:   300,
					},
				}

				for _, clusterInfo := range []bapi.ClusterInfo{clusterInfo1, clusterInfo2, clusterInfo3} {
					response, err := lb.Create(ctx, clusterInfo, logs)
					require.NoError(t, err)
					require.Equal(t, []v1.BulkError(nil), response.Errors)
					require.Equal(t, 0, response.Failed)

					err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
					require.NoError(t, err)
				}

				t.Run("should query single cluster", func(t *testing.T) {
					// Query for dns logs.
					r, err := lb.List(ctx, clusterInfo1, &params)
					require.NoError(t, err)
					require.Len(t, r.Items, numExpected(testcase))
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)

					// Try querying with a different tenant ID and make sure we don't
					// get any dns logs back.
					r2, err := lb.List(ctx, bapi.ClusterInfo{Cluster: cluster1, Tenant: "dummy-tenant"}, &params)
					require.NoError(t, err)
					require.Len(t, r2.Items, 0)

					if !testcase.SkipComparison {
						copyOfLogs := backendutils.AssertDNSLogsIDAndClusterAndReset(t, clusterInfo1.Cluster, r)

						// Assert that the correct logs are returned.
						if testcase.ExpectLog1 {
							require.Contains(t, copyOfLogs, logs[0])
						}
						if testcase.ExpectLog2 {
							require.Contains(t, copyOfLogs, logs[1])
						}
					}
				})

				t.Run("should query multiple clusters", func(t *testing.T) {
					selectedClusters := []string{cluster2, cluster3}
					params.SetClusters(selectedClusters)
					r, err := lb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &params)
					require.NoError(t, err)
					require.Len(t, r.Items, numExpected(testcase)*2) // 2 clusters so double the expected number of logs.
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)

					if !testcase.SkipComparison {
						var copyOfLogs []v1.DNSLog
						for _, item := range r.Items {
							require.Contains(t, selectedClusters, item.Cluster)
							backendutils.AssertDNSLogIDAndClusterAndReset(t, item.Cluster, &item)

							copyOfLogs = append(copyOfLogs, item)
						}

						// Assert that the correct logs are returned.
						if testcase.ExpectLog1 {
							require.Contains(t, copyOfLogs, logs[0])
						}
						if testcase.ExpectLog2 {
							require.Contains(t, copyOfLogs, logs[1])
						}
					}

					if numExpected(testcase) > 0 {
						require.Falsef(t, backendutils.MatchIn(r.Items, backendutils.DNSLogClusterEquals(cluster1)), "found unexpected cluster %s", cluster1)
						for i, cluster := range selectedClusters {
							require.Truef(t, backendutils.MatchIn(r.Items, backendutils.DNSLogClusterEquals(cluster)), "didn't cluster %d: %s", i, cluster)
						}
					}
				})

				t.Run("should query all clusters", func(t *testing.T) {
					params.SetAllClusters(true)
					r, err := lb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &params)
					require.NoError(t, err)
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)

					if !testcase.SkipComparison {
						var copyOfLogs []v1.DNSLog
						for _, item := range r.Items {
							backendutils.AssertDNSLogIDAndClusterAndReset(t, item.Cluster, &item)
							copyOfLogs = append(copyOfLogs, item)
						}

						// Assert that the correct logs are returned.
						if testcase.ExpectLog1 {
							require.Contains(t, copyOfLogs, logs[0])
						}
						if testcase.ExpectLog2 {
							require.Contains(t, copyOfLogs, logs[1])
						}
					}

					if numExpected(testcase) > 0 {
						allClusters := []string{cluster1, cluster2, cluster3}
						for _, item := range r.Items {
							require.Contains(t, allClusters, item.Cluster)
						}
					}
				})
			})
		}
	}
}
