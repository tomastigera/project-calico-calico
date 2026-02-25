// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// Run runs the given test in all modes.
func RunL7LogTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.L7LogMultiIndex)()
		testFn(t, index.L7LogMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			L7BaseIndexName: index.L7LogIndex().Name(bapi.ClusterInfo{}),
			L7PolicyName:    index.L7LogIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.L7LogIndex())()
		testFn(t, index.L7LogIndex())
	})
}

func TestL7_L7Logs(t *testing.T) {
	RunL7LogTest(t, "should return an empty list if there are no l7 logs", func(t *testing.T, idx bapi.Index) {
		params := v1.L7LogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		logs, err := cli.L7Logs(cluster1).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.L7Log{}, logs.Items)
	})

	RunL7LogTest(t, "should create and list l7 logs", func(t *testing.T, idx bapi.Index) {
		// Create a basic flow log.
		logs := []v1.L7Log{
			{
				EndTime:      time.Now().Unix(), // TODO: Add more fields
				ResponseCode: "200",
			},
		}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.L7Logs(clusterInfo.Cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create l7 log did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.L7LogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1
			resp, err := cli.L7Logs(cluster).List(ctx, &params)
			require.NoError(t, err)
			for i := range resp.Items {
				testutils.AssertL7LogClusterAndReset(t, cluster, &resp.Items[i])
				testutils.AssertGeneratedTimeAndReset(t, &resp.Items[i])
			}
			require.Equal(t, logs, resp.Items)
		})
		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.L7Logs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.L7Logs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.L7LogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.L7Logs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.L7Logs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.L7LogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunL7LogTest(t, "should return an empty aggregations if there are no l7 logs", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		params := v1.L7AggregationParams{
			L7LogParams: v1.L7LogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now(),
					},
				},
			},
			Aggregations: map[string]json.RawMessage{
				"response_code": []byte(`{"filters":{"other_bucket_key":"other","filters":{"1xx":{"prefix":{"response_code":"1"}},"2xx":{"prefix":{"response_code":"2"}},"3xx":{"prefix":{"response_code":"3"}},"4xx":{"prefix":{"response_code":"4"}},"5xx":{"prefix":{"response_code":"5"}}}},"aggs":{"myDurationMeanHistogram":{"date_histogram":{"field":"start_time","fixed_interval":"60s"},"aggs":{"myDurationMeanAvg":{"avg":{"field":"duration_mean"}}}}}}`),
			},
			NumBuckets: 3,
		}

		// Refresh to make sure we have the latest data.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Perform a query.
		aggregations, err := cli.L7Logs(cluster).Aggregations(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 0, numBuckets(aggregations))
	})

	RunL7LogTest(t, "should return aggregations if there are l7 logs", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		// Create 5 logs.
		logTime := time.Now().UTC().Unix()
		totalItems := 10
		for i := range totalItems {
			logs := []v1.L7Log{
				{
					StartTime: logTime,
					EndTime:   logTime + int64(i), // Make sure logs are ordered.
					Host:      fmt.Sprintf("%d", i),
				},
			}

			bulk, err := cli.L7Logs(cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create L7 log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.L7AggregationParams{
			L7LogParams: v1.L7LogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-10 * time.Second),
						To:   time.Now().Add(10 * time.Second),
					},
				},
			},
			Aggregations: map[string]json.RawMessage{
				"response_code": []byte(`{"filters":{"other_bucket_key":"other","filters":{"1xx":{"prefix":{"response_code":"1"}},"2xx":{"prefix":{"response_code":"2"}},"3xx":{"prefix":{"response_code":"3"}},"4xx":{"prefix":{"response_code":"4"}},"5xx":{"prefix":{"response_code":"5"}}}},"aggs":{"myDurationMeanHistogram":{"date_histogram":{"field":"start_time","fixed_interval":"60s"},"aggs":{"myDurationMeanAvg":{"avg":{"field":"duration_mean"}}}}}}`),
			},
			NumBuckets: 2,
		}

		// Perform a query.
		aggregations, err := cli.L7Logs(cluster).Aggregations(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, aggregations)

		// Expect it to have buckets.
		require.Equal(t, 2, numBuckets(aggregations))
	})

	RunL7LogTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 logs.
		logTime := time.Now().UTC().Unix()
		for i := range totalItems {
			logs := []v1.L7Log{
				{
					StartTime: logTime,
					EndTime:   logTime + int64(i), // Make sure logs are ordered.
					Host:      fmt.Sprintf("%d", i),
				},
			}
			bulk, err := cli.L7Logs(cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create L7 log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.L7LogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
			}
			resp, err := cli.L7Logs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertL7LogClusterAndReset(t, cluster, &resp.Items[0])
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, []v1.L7Log{
				{
					StartTime: logTime,
					EndTime:   logTime + int64(i),
					Host:      fmt.Sprintf("%d", i),
				},
			}, resp.Items, fmt.Sprintf("L7 #%d did not match", i))
			require.NotNil(t, resp.AfterKey)
			require.Contains(t, resp.AfterKey, "startFrom")
			require.Equal(t, resp.AfterKey["startFrom"], float64(i+1))
			require.Equal(t, resp.TotalHits, int64(totalItems))

			// Use the afterKey for the next query.
			afterKey = resp.AfterKey
		}

		// If we query once more, we should get the last page, and no afterkey, since
		// we have paged through all the items.
		lastItem := totalItems - 1
		params := v1.L7LogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
		}
		resp, err := cli.L7Logs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
		require.Equal(t, []v1.L7Log{
			{
				StartTime: logTime,
				EndTime:   logTime + int64(lastItem),
				Host:      fmt.Sprintf("%d", lastItem),
				Cluster:   cluster,
			},
		}, resp.Items, fmt.Sprintf("L7 #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunL7LogTest(t, "should support pagination for items >= 10000 for l7 logs", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K logs.
		logTime := time.Now().UTC().Unix()
		var logs []v1.L7Log
		for i := range totalItems {
			logs = append(logs, v1.L7Log{
				StartTime: logTime,
				EndTime:   logTime + int64(i), // Make sure logs are ordered.
				Host:      fmt.Sprintf("%d", i),
			},
			)
		}
		bulk, err := cli.L7Logs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create logs did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.L7LogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.L7Log](&params)
		pages, errors := pager.Stream(ctx, cli.L7Logs(cluster).List)

		receivedItems := 0
		for page := range pages {
			receivedItems = receivedItems + len(page.Items)
		}

		if err, ok := <-errors; ok {
			require.NoError(t, err)
		}

		require.Equal(t, receivedItems, totalItems)
	})
}

func TestFV_L7LogsTenancy(t *testing.T) {
	RunL7LogTest(t, "should support tenancy restriction", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		// Create a basic log. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		logs := []v1.L7Log{
			{
				EndTime:      time.Now().Unix(), // TODO: Add more fields
				ResponseCode: "200",
			},
		}
		bulk, err := tenantCLI.L7Logs(cluster1).Create(ctx, logs)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Try a read as well.
		params := v1.L7LogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}
		resp, err := tenantCLI.L7Logs(cluster1).List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})
}

// numBuckets returns the number of buckets in the aggregation response.
func numBuckets(aggregations elastic.Aggregations) int {
	if aggregations == nil {
		return 0
	}
	tbJSON, ok := aggregations[v1.TimeSeriesBucketName]
	if !ok {
		logrus.Info("[TEST] tb key not found")
		return 0
	}
	var tb map[string]any
	err := json.Unmarshal([]byte(tbJSON), &tb)
	if err != nil {
		logrus.WithError(err).Info("[TEST] failed to unmarshal tb")
		return 0
	}
	buckets, ok := tb["buckets"].([]any)
	if !ok {
		logrus.Info("[TEST] buckets key not found")
		return 0
	}
	return len(buckets)
}
