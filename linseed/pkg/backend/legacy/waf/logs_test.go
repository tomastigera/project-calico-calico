// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package waf_test

import (
	"context"
	"encoding/json"
	gojson "encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/waf"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

var (
	client      lmaelastic.Client
	b           bapi.WAFBackend
	migration   bapi.WAFBackend
	ctx         context.Context
	cluster1    string
	cluster2    string
	cluster3    string
	indexGetter bapi.Index
)

// RunAllModes runs the given test function twice, once using the single-index backend, and once using
// the multi-index backend.
func RunAllModes(t *testing.T, name string, testFn func(t *testing.T)) {
	// Run using the multi-index backend.
	t.Run(fmt.Sprintf("%s [legacy]", name), func(t *testing.T) {
		defer setupTest(t, false)()
		testFn(t)
	})

	// Run using the single-index backend.
	t.Run(fmt.Sprintf("%s [singleindex]", name), func(t *testing.T) {
		defer setupTest(t, true)()
		testFn(t)
	})
}

// setupTest runs common logic before each test, and also returns a function to perform teardown
// after each test.
func setupTest(t *testing.T, singleIndex bool) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	// Create an elasticsearch client to use for the test. For this suite, we use a real
	// elasticsearch instance created via "make run-elastic".
	esClient, err := elastic.NewSimpleClient(elastic.SetURL("http://localhost:9200"), elastic.SetInfoLog(logrus.StandardLogger()))

	require.NoError(t, err)
	client = lmaelastic.NewWithClient(esClient)
	cache := templates.NewCachedInitializer(client, 1, 0)

	// Instantiate a backend.
	if singleIndex {
		indexGetter = index.WAFLogIndex()
		b = waf.NewSingleIndexBackend(client, cache, 10000, false)
		migration = waf.NewSingleIndexBackend(client, cache, 10000, true)
	} else {
		b = waf.NewBackend(client, cache, 10000, false)
		migration = waf.NewBackend(client, cache, 10000, true)
		indexGetter = index.WAFLogMultiIndex
	}

	// Create a random cluster name for each test to make sure we don't
	// interfere between tests.
	cluster1 = testutils.RandomClusterName()
	cluster2 = testutils.RandomClusterName()
	cluster3 = testutils.RandomClusterName()

	// Each test should take less than 60 seconds.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)

	// Function contains teardown logic.
	return func() {
		for _, cluster := range []string{cluster1, cluster2, cluster3} {
			err = testutils.CleanupIndices(context.Background(), esClient, singleIndex, indexGetter, bapi.ClusterInfo{Cluster: cluster})
			require.NoError(t, err)
		}

		// Cancel the context
		cancel()
		logCancel()
	}
}

// TestWAFLogBasic tests running a real elasticsearch query to create a kube waf log.
func TestWAFLogBasic(t *testing.T) {
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestCreateWAFLog (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
			cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
			cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

			logTime := time.Now()
			f := v1.WAFLog{
				Timestamp: logTime,
				Source: &v1.WAFEndpoint{
					IP:       "1.2.3.4",
					PortNum:  789,
					Hostname: "source-hostname",
				},
				Destination: &v1.WAFEndpoint{
					IP:       "4.3.2.1",
					PortNum:  987,
					Hostname: "dest-hostname",
				},
				Path:      "/yellow/brick/road",
				Method:    "GET",
				Protocol:  "HTTP/1.1",
				Msg:       "This is a friendly reminder that nobody knows what is going on",
				RequestId: "abaecb62-c7fc-42d2-b7b9-44be7571d216",
				Rules: []v1.WAFRuleHit{
					{
						Id:         "9992",
						Message:    "WAF rules, rule WAF",
						Severity:   "2",
						File:       "JOJO-000.conf",
						Line:       "666",
						Disruptive: false,
					},
					{
						Id:         "9993",
						Message:    "WAF rules, rule, rule WAF",
						Severity:   "4",
						File:       "JOJO-001.conf",
						Line:       "6669",
						Disruptive: true,
					},
				},
			}

			// Create the log in ES.
			for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
				resp, err := b.Create(ctx, clusterInfo, []v1.WAFLog{f})
				require.NoError(t, err)
				require.Equal(t, []v1.BulkError(nil), resp.Errors)
				require.Equal(t, 1, resp.Total)
				require.Equal(t, 0, resp.Failed)
				require.Equal(t, 1, resp.Succeeded)

				// Refresh the index.
				err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
				require.NoError(t, err)
			}

			params := &v1.WAFLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-60 * time.Second),
						To:   time.Now().Add(60 * time.Second),
					},
				},
			}

			t.Run("should query single cluster", func(t *testing.T) {
				clusterInfo := cluster1Info
				results, err := b.List(ctx, clusterInfo, params)
				require.NoError(t, err)
				require.Equal(t, 1, len(results.Items))
				require.Equal(t, results.Items[0].Timestamp.Format(time.RFC3339), logTime.Format(time.RFC3339))

				// Timestamps don't equal on read.
				results.Items[0].Timestamp = f.Timestamp
				testutils.AssertWAFLogClusterAndReset(t, clusterInfo.Cluster, &results.Items[0])
				testutils.AssertGeneratedTimeAndReset(t, &results.Items[0])
				require.Equal(t, f, results.Items[0])

				// Read again using a dummy tenant - we should get nothing.
				results, err = b.List(ctx, bapi.ClusterInfo{Cluster: clusterInfo.Cluster, Tenant: "dummy"}, params)
				require.NoError(t, err)
				require.Equal(t, 0, len(results.Items))
			})

			t.Run("should query multiple clusters", func(t *testing.T) {
				selectedClusters := []string{cluster2, cluster3}
				params.SetClusters(selectedClusters)
				results, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, params)
				require.NoError(t, err)
				require.Equal(t, 2, len(results.Items))
				for _, cluster := range selectedClusters {
					require.Truef(t, testutils.MatchIn(results.Items, testutils.WAFLogClusterEquals(cluster)), "cluster %s not found", cluster)
				}
			})
		})
	}

	RunAllModes(t, "no cluster name given on request", func(t *testing.T) {
		// It should reject requests with no cluster name given.
		clusterInfo := bapi.ClusterInfo{}
		_, err := b.Create(ctx, clusterInfo, []v1.WAFLog{})
		require.Error(t, err)
		require.ErrorContains(t, err, "no cluster ID")

		params := &v1.WAFLogParams{}
		results, err := b.List(ctx, clusterInfo, params)
		require.Error(t, err)
		require.Nil(t, results)
		require.ErrorContains(t, err, "no cluster ID")
	})

	RunAllModes(t, "bad startFrom on request", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
		params := &v1.WAFLogParams{
			QueryParams: v1.QueryParams{
				AfterKey: map[string]any{"startFrom": "badvalue"},
			},
		}
		results, err := b.List(ctx, clusterInfo, params)
		require.Error(t, err)
		require.Nil(t, results)
	})
}

// TestAggregations tests running a real elasticsearch query to get aggregations.
func TestAggregations(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should return time-series WAF log aggregation results (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			numLogs := 5
			timeBetweenLogs := 10 * time.Second
			testStart := time.Unix(0, 0)
			now := testStart.Add(time.Duration(numLogs) * time.Minute)

			// Several dummy logs.
			logs := []v1.WAFLog{}
			start := testStart.Add(1 * time.Second)
			for i := 1; i < numLogs; i++ {
				log := v1.WAFLog{
					Timestamp: start,
					Source: &v1.WAFEndpoint{
						IP:       "1.2.3.4",
						PortNum:  789,
						Hostname: "source-hostname",
					},
					Destination: &v1.WAFEndpoint{
						IP:       "4.3.2.1",
						PortNum:  987,
						Hostname: "dest-hostname",
					},
					Path:      "/yellow/brick/road",
					Method:    "GET",
					Protocol:  "HTTP/1.1",
					Msg:       "This is a friendly reminder that nobody knows what is going on",
					RequestId: "abaecb62-c7fc-42d2-b7b9-44be7571d216",
					Rules: []v1.WAFRuleHit{
						{
							Id:         "9992",
							Message:    "WAF rules, rule WAF",
							Severity:   "2",
							File:       "JOJO-000.conf",
							Line:       "666",
							Disruptive: false,
						},
						{
							Id:         "9993",
							Message:    "WAF rules, rule, rule WAF",
							Severity:   "4",
							File:       "JOJO-001.conf",
							Line:       "6669",
							Disruptive: true,
						},
					},
				}
				start = start.Add(timeBetweenLogs)
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := b.Create(ctx, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			params := v1.WAFLogAggregationParams{}
			params.TimeRange = &lmav1.TimeRange{}
			params.TimeRange.From = testStart
			params.TimeRange.To = now
			params.NumBuckets = 4

			// Add a simple aggregation to add up the total instances of each IP.
			agg := elastic.NewTermsAggregation().Field("source.ip")
			src, err := agg.Source()
			require.NoError(t, err)
			bytes, err := json.Marshal(src)
			require.NoError(t, err)
			params.Aggregations = map[string]gojson.RawMessage{"ips": bytes}

			// Use the backend to perform a query.
			aggs, err := b.Aggregations(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.NotNil(t, aggs)

			ts, ok := aggs.AutoDateHistogram("tb")
			require.True(t, ok)

			// We asked for 4 buckets.
			require.Len(t, ts.Buckets, 4)

			for i, b := range ts.Buckets {
				require.Equal(t, int64(1), b.DocCount, fmt.Sprintf("Bucket %d", i))

				// We asked for a ips agg, which should include a single log
				// in each bucket.
				ips, ok := b.ValueCount("ips")
				require.True(t, ok, "Bucket missing ips agg")
				buckets := string(ips.Aggregations["buckets"])
				require.Equal(t, `[{"key":"1.2.3.4","doc_count":1}]`, buckets)
			}
		})

		RunAllModes(t, fmt.Sprintf("should return aggregate stats (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			// Start the test numLogs minutes in the past.
			numLogs := 5
			timeBetweenLogs := 10 * time.Second
			testStart := time.Unix(0, 0)
			now := testStart.Add(time.Duration(numLogs) * time.Minute)

			// Several dummy logs.
			logs := []v1.WAFLog{}
			start := testStart.Add(1 * time.Second)
			for i := 1; i < numLogs; i++ {
				log := v1.WAFLog{
					Timestamp: start,
					Source: &v1.WAFEndpoint{
						IP:       "1.2.3.4",
						PortNum:  789,
						Hostname: "source-hostname",
					},
					Destination: &v1.WAFEndpoint{
						IP:       "4.3.2.1",
						PortNum:  987,
						Hostname: "dest-hostname",
					},
					Path:      "/yellow/brick/road",
					Method:    "GET",
					Protocol:  "HTTP/1.1",
					Msg:       "This is a friendly reminder that nobody knows what is going on",
					RequestId: "abaecb62-c7fc-42d2-b7b9-44be7571d216",
					Rules: []v1.WAFRuleHit{
						{
							Id:         "9992",
							Message:    "WAF rules, rule WAF",
							Severity:   "2",
							File:       "JOJO-000.conf",
							Line:       "666",
							Disruptive: false,
						},
						{
							Id:         "9993",
							Message:    "WAF rules, rule, rule WAF",
							Severity:   "4",
							File:       "JOJO-001.conf",
							Line:       "6669",
							Disruptive: true,
						},
					},
				}
				start = start.Add(timeBetweenLogs)
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := b.Create(ctx, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			params := v1.WAFLogAggregationParams{}
			params.TimeRange = &lmav1.TimeRange{}
			params.TimeRange.From = testStart
			params.TimeRange.To = now
			params.NumBuckets = 0 // Return aggregated stats over the whole time range.

			// Add a simple aggregation to count the instances of an IP.
			agg := elastic.NewTermsAggregation().Field("source.ip")
			src, err := agg.Source()
			require.NoError(t, err)
			bytes, err := json.Marshal(src)
			require.NoError(t, err)
			params.Aggregations = map[string]gojson.RawMessage{"ips": bytes}

			// Use the backend to perform a stats query.
			result, err := b.Aggregations(ctx, clusterInfo, &params)
			require.NoError(t, err)

			// We should get a sum aggregation with all 4 logs.
			ips, ok := result.ValueCount("ips")
			require.True(t, ok)
			buckets := string(ips.Aggregations["buckets"])
			require.Equal(t, `[{"key":"1.2.3.4","doc_count":4}]`, buckets)
		})
	}
}

func TestSorting(t *testing.T) {
	RunAllModes(t, "should respect sorting", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		t1 := time.Unix(100, 0).UTC()
		t2 := time.Unix(500, 0).UTC()

		log1 := v1.WAFLog{
			Timestamp:   t1,
			Source:      &v1.WAFEndpoint{IP: "1.2.3.4", PortNum: 789, Hostname: "source-hostname"},
			Destination: &v1.WAFEndpoint{IP: "4.3.2.1", PortNum: 987, Hostname: "dest-hostname"},
			Path:        "/yellow/brick/road",
			Method:      "GET",
			Protocol:    "HTTP/1.1",
			Msg:         "This is a friendly reminder that nobody knows what is going on",
			RequestId:   "abaecb62-c7fc-42d2-b7b9-44be7571d216",
			Rules: []v1.WAFRuleHit{
				{Id: "9992", Message: "WAF rules, rule WAF", Severity: "2", File: "JOJO-000.conf", Line: "666", Disruptive: false},
				{Id: "9993", Message: "WAF rules, rule, rule WAF", Severity: "4", File: "JOJO-001.conf", Line: "6669", Disruptive: true},
			},
		}
		log2 := v1.WAFLog{
			Timestamp:   t2,
			Source:      &v1.WAFEndpoint{IP: "1.2.3.4", PortNum: 789, Hostname: "source-hostname"},
			Destination: &v1.WAFEndpoint{IP: "4.3.2.1", PortNum: 987, Hostname: "dest-hostname"},
			Path:        "/red/lobster",
			Method:      "PUT",
			Protocol:    "HTTP/2",
			Msg:         "This is an unreasonable fear of failure",
			Rules: []v1.WAFRuleHit{
				{Id: "9993", Message: "WAF rules waf waf waf", Severity: "1", File: "JOJO-003.conf", Line: "6611", Disruptive: false},
			},
		}

		response, err := b.Create(ctx, clusterInfo, []v1.WAFLog{log1, log2})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Query for logs without sorting.
		params := v1.WAFLogParams{}
		params.Sort = []v1.SearchRequestSortBy{
			{
				Field:      "@timestamp",
				Descending: false,
			},
		}
		r, err := b.List(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)
		for i := range r.Items {
			testutils.AssertWAFLogClusterAndReset(t, clusterInfo.Cluster, &r.Items[i])
			testutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
		}

		// Assert that the logs are returned in the correct order.
		require.Equal(t, log1, r.Items[0])
		require.Equal(t, log2, r.Items[1])

		// Query again, this time sorting in order to get the logs in reverse order.
		params.Sort = []v1.SearchRequestSortBy{
			{
				Field:      "@timestamp",
				Descending: true,
			},
		}
		r, err = b.List(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)
		for i := range r.Items {
			testutils.AssertWAFLogClusterAndReset(t, clusterInfo.Cluster, &r.Items[i])
			testutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
		}
		require.Equal(t, log2, r.Items[0])
		require.Equal(t, log1, r.Items[1])
	})
}

func TestWAFLogFiltering(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.WAFLogParams

		// Configuration for which logs are expected to match.
		ExpectLogIndex int
	}

	testcases := []testCase{
		{
			Name: "should query based on level",
			Params: v1.WAFLogParams{
				Selector: `level="DANGER"`,
			},
			ExpectLogIndex: 1,
		},
		{
			Name: "should query based on rules id",
			Params: v1.WAFLogParams{
				Selector: `"rules.id" = 8`,
			},
			ExpectLogIndex: 0,
		},
		{
			Name: "should support selection based on nested field match",
			Params: v1.WAFLogParams{
				Selector: "\"rules.file\" IN {\"*est-fi*\"}",
			},
			ExpectLogIndex: 0,
		},
	}

	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		for _, testcase := range testcases {
			// Each testcase creates multiple flow logs, and then uses
			// different filtering parameters provided in the params
			// to query one or more flow logs.
			name := fmt.Sprintf("%s (tenant=%s)", testcase.Name, tenant)
			RunAllModes(t, name, func(t *testing.T) {
				clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

				reqTime := time.Now()
				// Create a basic waf logs
				wafLogs := []v1.WAFLog{
					{
						Timestamp: reqTime,
						Msg:       "Strawberry Fields Forever",
						Rules: []v1.WAFRuleHit{
							{
								Id:   "8",
								File: "test-file",
							},
						},
					},
					{
						Timestamp: reqTime,
						Msg:       "High Voltage",
						Level:     "DANGER",
					},
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				resp, err := b.Create(ctx, clusterInfo, wafLogs)
				require.NoError(t, err)
				require.Empty(t, resp.Errors)

				// Refresh.
				err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
				require.NoError(t, err)

				result, err := b.List(ctx, clusterInfo, &testcase.Params)
				require.NoError(t, err)

				require.Len(t, result.Items, 1)
				// Reset the time as it microseconds to not match perfectly
				require.NotEqual(t, "", result.Items[0].Timestamp)
				result.Items[0].Timestamp = reqTime
				testutils.AssertWAFLogClusterAndReset(t, clusterInfo.Cluster, &result.Items[0])
				testutils.AssertGeneratedTimeAndReset(t, &result.Items[0])

				require.Equal(t, wafLogs[testcase.ExpectLogIndex], result.Items[0])
			})
		}
	}
}

func TestRetrieveMostRecentWAFLogs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestRetrieveMostRecentWAFLogs (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Tenant: tenant, Cluster: cluster1}

			now := time.Now().UTC()

			t1 := time.Unix(500, 0).UTC()
			t2 := time.Unix(400, 0).UTC()
			t3 := time.Unix(300, 0).UTC()

			l1 := v1.WAFLog{
				Timestamp: t1,
				Msg:       "Here Comes The Sun",
				Rules: []v1.WAFRuleHit{
					{
						Id: "8",
					},
				},
			}

			l2 := v1.WAFLog{
				Timestamp: t2,
				Msg:       "Hey Jude",
				Rules: []v1.WAFRuleHit{
					{
						Id: "8",
					},
				},
			}

			_, err := b.Create(ctx, clusterInfo, []v1.WAFLog{l1, l2})
			require.NoError(t, err)

			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Query for logs
			params := v1.WAFLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						Field: lmav1.FieldGeneratedTime,
						From:  now.Add(-1 * time.Second).UTC(),
					},
				},
				QuerySortParams: v1.QuerySortParams{
					Sort: []v1.SearchRequestSortBy{
						{
							Field: string(lmav1.FieldGeneratedTime),
						},
					},
				},
			}
			r, err := b.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 2)
			require.Nil(t, r.AfterKey)
			lastGeneratedTime := r.Items[1].GeneratedTime
			for i := range r.Items {
				testutils.AssertWAFLogClusterAndReset(t, cluster1, &r.Items[i])
				testutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
			}

			// Assert that the logs are returned in the correct order.
			require.Equal(t, l1, r.Items[0])
			require.Equal(t, l2, r.Items[1])

			l3 := v1.WAFLog{
				Timestamp: t3,
				Msg:       "Eleanor Rigby",
				Rules: []v1.WAFRuleHit{
					{
						Id: "8",
					},
				},
			}
			_, err = b.Create(ctx, clusterInfo, []v1.WAFLog{l3})
			require.NoError(t, err)

			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Query the last ingested log
			params.QueryParams = v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					Field: lmav1.FieldGeneratedTime,
					From:  lastGeneratedTime.UTC(),
				},
			}

			r, err = b.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 1)
			require.Nil(t, r.AfterKey)
			for i := range r.Items {
				testutils.AssertWAFLogClusterAndReset(t, cluster1, &r.Items[i])
				testutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
			}

			// Assert that the logs are returned in the correct order.
			require.Equal(t, l3, r.Items[0])
		})
	}
}

func TestPreserveIDs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should preserve IDs across bulk ingestion requests (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			numLogs := 5
			testStart := time.Unix(0, 0).UTC()

			// Several dummy logs.
			logs := []v1.WAFLog{}
			for i := 1; i <= numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				log := v1.WAFLog{
					Timestamp: start,
					Msg:       "Here Comes The Sun",
					Rules: []v1.WAFRuleHit{
						{
							Id: "8",
						},
					},
				}
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := migration.Create(ctx, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Read it back and make sure generated time values are what we expect.
			allOpts := v1.WAFLogParams{
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
				testutils.AssertGeneratedTimeAndReset[v1.WAFLog](t, &log)
			}
			for _, log := range second.Items {
				require.NotEmpty(t, log.ID)
				testutils.AssertGeneratedTimeAndReset[v1.WAFLog](t, &log)
			}

			require.Equal(t, first.Items, second.Items)

			// Refresh before cleaning up data
			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

		})
	}
}
