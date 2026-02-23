// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"testing"
	"time"

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
func RunWAFTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.WAFLogMultiIndex)()
		testFn(t, index.WAFLogMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			WAFBaseIndexName: index.WAFLogIndex().Name(bapi.ClusterInfo{}),
			WAFPolicyName:    index.WAFLogIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.WAFLogIndex())()
		testFn(t, index.WAFLogIndex())
	})
}

func TestFV_WAF(t *testing.T) {
	RunWAFTest(t, "should return an empty list if there are no WAF logs", func(t *testing.T, idx bapi.Index) {
		params := v1.WAFLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		wafLogs, err := cli.WAFLogs(cluster1).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.WAFLog{}, wafLogs.Items)
	})

	RunWAFTest(t, "should create and list waf logs", func(t *testing.T, idx bapi.Index) {
		reqTime := time.Now()
		// Create a basic waf log
		wafLogs := []v1.WAFLog{
			{
				Timestamp: reqTime,
				Msg:       "any message",
			},
		}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.WAFLogs(clusterInfo.Cluster).Create(ctx, wafLogs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create waf logs did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.WAFLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1
			resp, err := cli.WAFLogs(cluster).List(ctx, &params)
			require.NoError(t, err)

			require.Len(t, resp.Items, 1)
			// Reset the time as it microseconds to not match perfectly
			require.NotEqual(t, "", resp.Items[0].Timestamp)
			resp.Items[0].Timestamp = reqTime
			testutils.AssertWAFLogClusterAndReset(t, cluster, &resp.Items[0])
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])

			require.Equal(t, wafLogs, resp.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.WAFLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.WAFLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.WAFLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.WAFLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.WAFLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.WAFLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunWAFTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		clusterInfo := cluster1Info
		cluster := clusterInfo.Cluster
		totalItems := 5

		// Create 5 waf logs.
		logTime := time.Unix(0, 0).UTC()
		for i := range totalItems {
			logs := []v1.WAFLog{
				{
					Timestamp: logTime.Add(time.Duration(i) * time.Second), // Make sure logs are ordered.
					Host:      fmt.Sprintf("%d", i),
				},
			}
			bulk, err := cli.WAFLogs(cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create WAF log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.WAFLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Unix(0, 0).UTC().Add(-5 * time.Second),
						To:   time.Unix(0, 0).UTC().Add(5 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
			}
			resp, err := cli.WAFLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, []v1.WAFLog{
				{
					Timestamp: logTime.Add(time.Duration(i) * time.Second),
					Host:      fmt.Sprintf("%d", i),
					Cluster:   cluster,
				},
			}, resp.Items, fmt.Sprintf("WAF #%d did not match", i))
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
		params := v1.WAFLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(0, 0).UTC().Add(-5 * time.Second),
					To:   time.Unix(0, 0).UTC().Add(5 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
		}
		resp, err := cli.WAFLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
		require.Equal(t, []v1.WAFLog{
			{
				Timestamp: logTime.Add(time.Duration(lastItem) * time.Second),
				Host:      fmt.Sprintf("%d", lastItem),
				Cluster:   cluster,
			},
		}, resp.Items, fmt.Sprintf("WAF #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunWAFTest(t, "should support pagination for items >= 10000 for WAF logs", func(t *testing.T, idx bapi.Index) {
		clusterInfo := cluster1Info
		cluster := clusterInfo.Cluster
		totalItems := 10001
		// Create > 10K threat logs.
		logTime := time.Unix(0, 0).UTC()
		var logs []v1.WAFLog
		for i := range totalItems {
			logs = append(logs, v1.WAFLog{
				Timestamp: logTime.Add(time.Duration(i) * time.Second), // Make sure logs are ordered.
				Host:      fmt.Sprintf("%d", i),
				Cluster:   cluster,
			},
			)
		}
		bulk, err := cli.WAFLogs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create logs did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.WAFLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.WAFLog](&params)
		pages, errors := pager.Stream(ctx, cli.WAFLogs(cluster).List)

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
