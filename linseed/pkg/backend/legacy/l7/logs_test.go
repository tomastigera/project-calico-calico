// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package l7_test

import (
	"context"
	"encoding/json"
	gojson "encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func TestL7Logs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestCreateL7Log (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			clusterInfo1 := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
			clusterInfo2 := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
			clusterInfo3 := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

			f := v1.L7Log{
				StartTime:            time.Now().Unix(),
				EndTime:              time.Now().Unix(),
				DestType:             "wep",
				DestNamespace:        "kube-system",
				DestNameAggr:         "kube-dns-*",
				DestServiceNamespace: "default",
				DestServiceName:      "kube-dns",
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			for _, clusterInfo := range []bapi.ClusterInfo{clusterInfo1, clusterInfo2, clusterInfo3} {
				response, err := lb.Create(ctx, clusterInfo, []v1.L7Log{f})
				require.NoError(t, err)
				require.Equal(t, response.Failed, 0)
				require.Equal(t, response.Succeeded, 1)
				require.Len(t, response.Errors, 0)

				// Read it back and make sure it matches.
				err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
				require.NoError(t, err)
			}

			params := &v1.L7LogParams{}

			t.Run("should query single cluster", func(t *testing.T) {
				clusterInfo := clusterInfo1
				results, err := lb.List(ctx, clusterInfo, params)
				require.NoError(t, err)
				require.Len(t, results.Items, 1)
				testutils.AssertL7LogClusterAndReset(t, clusterInfo.Cluster, &results.Items[0])
				testutils.AssertGeneratedTimeAndReset(t, &results.Items[0])
				require.Equal(t, f, results.Items[0])
			})

			t.Run("should query multiple clusters", func(t *testing.T) {
				selectedClusters := []string{cluster2, cluster3}
				params.SetClusters(selectedClusters)
				results, err := lb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, params)
				require.NoError(t, err)
				require.Len(t, results.Items, 2)
			})

			t.Run("should query all clusters", func(t *testing.T) {
				params.SetAllClusters(true)
				results, err := lb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, params)
				require.NoError(t, err)
				for _, cluster := range []string{cluster1, cluster2, cluster3} {
					require.Truef(t, testutils.MatchIn(results.Items, testutils.L7LogClusterEquals(cluster)), "Cluster %s not found", cluster)
				}
			})
		})

		RunAllModes(t, "no cluster name given on request", func(t *testing.T) {
			// It should reject requests with no cluster name given.
			clusterInfo := bapi.ClusterInfo{}
			_, err := lb.Create(ctx, clusterInfo, []v1.L7Log{})
			require.Error(t, err)

			params := &v1.L7LogParams{}
			results, err := lb.List(ctx, clusterInfo, params)
			require.Error(t, err)
			require.Nil(t, results)
		})

		RunAllModes(t, "bad startFrom on request", func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
			params := &v1.L7LogParams{
				QueryParams: v1.QueryParams{
					AfterKey: map[string]any{"startFrom": "badvalue"},
				},
			}
			results, err := lb.List(ctx, clusterInfo, params)
			require.Error(t, err)
			require.Nil(t, results)
		})
	}
}

// TestAggregations tests running a real elasticsearch query to get aggregations.
func TestAggregations(t *testing.T) {
	RunAllModes(t, "should return time-series L7 log aggregation results", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Start the test numLogs minutes in the past.
		numLogs := 5
		timeBetweenLogs := 10 * time.Second
		testStart := time.Unix(0, 0)
		now := testStart.Add(time.Duration(numLogs) * time.Minute)

		// Several dummy logs.
		logs := []v1.L7Log{}
		for i := 1; i < numLogs; i++ {
			start := testStart.Add(time.Duration(i) * time.Second)
			end := start.Add(timeBetweenLogs)
			l := v1.L7Log{
				StartTime:            start.Unix(),
				EndTime:              end.Unix(),
				DestType:             "wep",
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestNameAggr:         "kube-dns-*",
				DestServiceNamespace: "default",
				DestServiceName:      "kube-dns",
				ResponseCode:         "200",
				DurationMean:         300,
			}
			logs = append(logs, l)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := lb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Empty(t, resp.Errors)

		// Refresh.
		err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.L7AggregationParams{}
		params.TimeRange = &lmav1.TimeRange{}
		params.TimeRange.From = testStart
		params.TimeRange.To = now
		params.NumBuckets = 4

		// Add a simple aggregation to add up the total duration from the logs.
		sumAgg := elastic.NewSumAggregation().Field("duration_mean")
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

		times := []string{"11", "12", "13", "14"}

		for i, b := range ts.Buckets {
			require.Equal(t, int64(1), b.DocCount, fmt.Sprintf("Bucket %d", i))

			// We asked for a count agg, which should include a single log
			// in each bucket.
			count, ok := b.Sum("count")
			require.True(t, ok, "Bucket missing count agg")
			require.NotNil(t, count.Value)
			require.Equal(t, float64(300), *count.Value)

			// The key should be the timestamp for the bucket.
			require.NotNil(t, b.KeyAsString)
			require.Equal(t, times[i], *b.KeyAsString)
		}
	})

	RunAllModes(t, "should return aggregate stats", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Start the test numLogs minutes in the past.
		numLogs := 5
		timeBetweenLogs := 10 * time.Second
		testStart := time.Unix(0, 0)
		now := testStart.Add(time.Duration(numLogs) * time.Minute)

		// Several dummy logs.
		logs := []v1.L7Log{}
		for i := 1; i < numLogs; i++ {
			start := testStart.Add(time.Duration(i) * time.Second)
			end := start.Add(timeBetweenLogs)
			l := v1.L7Log{
				StartTime:            start.Unix(),
				EndTime:              end.Unix(),
				DestType:             "wep",
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestNameAggr:         "kube-dns-*",
				DestServiceNamespace: "default",
				DestServiceName:      "kube-dns",
				ResponseCode:         "200",
				DurationMean:         300,
			}
			logs = append(logs, l)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := lb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Empty(t, resp.Errors)

		// Refresh.
		err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.L7AggregationParams{}
		params.TimeRange = &lmav1.TimeRange{}
		params.TimeRange.From = testStart
		params.TimeRange.To = now
		params.NumBuckets = 0 // Return aggregated stats over the whole time range.

		// Add a simple aggregation to add up the total duration_mean from the logs.
		sumAgg := elastic.NewSumAggregation().Field("duration_mean")
		src, err := sumAgg.Source()
		require.NoError(t, err)
		bytes, err := json.Marshal(src)
		require.NoError(t, err)
		params.Aggregations = map[string]gojson.RawMessage{"count": bytes}

		// Use the backend to perform a stats query.
		result, err := lb.Aggregations(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.NotNil(t, result)

		// We should get a sum aggregation with all 4 logs.
		count, ok := result.ValueCount("count")
		require.True(t, ok)
		require.NotNil(t, count.Value)
		require.Equal(t, float64(1200), *count.Value)
	})
}

func TestRetrieveMostRecentL7Logs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestRetrieveMostRecentL7Logs (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Tenant: tenant, Cluster: cluster1}

			now := time.Now().UTC()

			t1 := time.Unix(500, 0).UTC()
			t2 := time.Unix(400, 0).UTC()
			t3 := time.Unix(300, 0).UTC()

			l1 := v1.L7Log{
				StartTime:            t1.Unix(),
				EndTime:              t1.Add(1 * time.Second).Unix(),
				DestType:             "wep",
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestNameAggr:         "kube-dns-*",
				DestServiceNamespace: "default",
				DestServiceName:      "kube-dns",
				ResponseCode:         "200",
				DurationMean:         300,
			}

			l2 := v1.L7Log{
				StartTime:            t2.Unix(),
				EndTime:              t2.Add(1 * time.Second).Unix(),
				DestType:             "wep",
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestNameAggr:         "kube-dns-*",
				DestServiceNamespace: "default",
				DestServiceName:      "kube-dns",
				ResponseCode:         "200",
				DurationMean:         300,
			}

			_, err := lb.Create(ctx, clusterInfo, []v1.L7Log{l1, l2})
			require.NoError(t, err)

			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Query for logs
			params := v1.L7LogParams{
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
			r, err := lb.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 2)
			require.Nil(t, r.AfterKey)
			lastGeneratedTime := r.Items[1].GeneratedTime
			for i := range r.Items {
				testutils.AssertL7LogClusterAndReset(t, cluster1, &r.Items[i])
				testutils.AssertGeneratedTimeAndReset(t, &r.Items[i])
			}

			// Assert that the logs are returned in the correct order.
			require.Equal(t, l1, r.Items[0])
			require.Equal(t, l2, r.Items[1])

			l3 := v1.L7Log{
				StartTime:            t3.Unix(),
				EndTime:              t3.Add(1 * time.Second).Unix(),
				DestType:             "wep",
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestNameAggr:         "kube-dns-*",
				DestServiceNamespace: "default",
				DestServiceName:      "kube-dns",
				ResponseCode:         "200",
				DurationMean:         300,
			}
			_, err = lb.Create(ctx, clusterInfo, []v1.L7Log{l3})
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

			r, err = lb.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 1)
			require.Nil(t, r.AfterKey)
			for i := range r.Items {
				testutils.AssertL7LogClusterAndReset(t, cluster1, &r.Items[i])
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
			logs := []v1.L7Log{}
			for i := 1; i <= numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				log := v1.L7Log{
					StartTime: start.Unix(),
					EndTime:   start.Add(time.Duration(5) * time.Second).Unix(),
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
			allOpts := v1.L7LogParams{
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
				testutils.AssertGeneratedTimeAndReset[v1.L7Log](t, &log)
			}
			for _, log := range second.Items {
				require.NotEmpty(t, log.ID)
				testutils.AssertGeneratedTimeAndReset[v1.L7Log](t, &log)
			}

			require.Equal(t, first.Items, second.Items)

			// Refresh before cleaning up data
			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

		})
	}
}
