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

func RunBGPLogTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.BGPLogMultiIndex)()
		testFn(t, index.BGPLogMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			BGPBaseIndexName: index.BGPLogIndex().Name(bapi.ClusterInfo{}),
			BGPPolicyName:    index.BGPLogIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.BGPLogIndex())()
		testFn(t, index.BGPLogIndex())
	})
}

func TestFV_BGP(t *testing.T) {
	RunBGPLogTest(t, "should return an empty list if there are no BGP logs", func(t *testing.T, idx bapi.Index) {
		params := v1.BGPLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		bgpLogs, err := cli.BGPLogs(cluster1).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.BGPLog{}, bgpLogs.Items)
	})

	RunBGPLogTest(t, "should create and list bgp logs", func(t *testing.T, idx bapi.Index) {
		reqTime := time.Unix(10, 0).UTC()
		// Create a basic bgp log
		bgpLogs := []v1.BGPLog{
			{
				LogTime: reqTime.Format(v1.BGPLogTimeFormat),
			},
		}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.BGPLogs(clusterInfo.Cluster).Create(ctx, bgpLogs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create bgp log did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.BGPLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: reqTime.Add(-5 * time.Second),
					To:   reqTime.Add(5 * time.Second),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1
			resp, err := cli.BGPLogs(cluster).List(ctx, &params)
			require.NoError(t, err)

			require.Len(t, resp.Items, 1)
			testutils.AssertBGPLogClusterAndReset(t, cluster, &resp.Items[0])
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, bgpLogs, resp.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.BGPLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.BGPLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.BGPLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.BGPLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.BGPLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.BGPLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunBGPLogTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 BGP logs.
		logTime := time.Unix(0, 0).UTC()
		for i := range totalItems {
			logs := []v1.BGPLog{
				{
					LogTime: logTime.Add(time.Duration(i) * time.Second).Format(v1.BGPLogTimeFormat),
					Host:    fmt.Sprintf("%d", i),
				},
			}
			bulk, err := cli.BGPLogs(cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create bgp log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.BGPLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: logTime.Add(-5 * time.Second),
						To:   logTime.Add(5 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
			}
			resp, err := cli.BGPLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, []v1.BGPLog{
				{
					LogTime: logTime.Add(time.Duration(i) * time.Second).Format(v1.BGPLogTimeFormat),
					Host:    fmt.Sprintf("%d", i),
					Cluster: cluster,
				},
			}, resp.Items, fmt.Sprintf("BGP #%d did not match", i))
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
		params := v1.BGPLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(5 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
		}
		resp, err := cli.BGPLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
		require.Equal(t, []v1.BGPLog{
			{
				LogTime: logTime.Add(time.Duration(lastItem) * time.Second).Format(v1.BGPLogTimeFormat),
				Host:    fmt.Sprintf("%d", lastItem),
				Cluster: cluster,
			},
		}, resp.Items, fmt.Sprintf("BGP #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunBGPLogTest(t, "should support pagination for items >= 10000 for BGP logs", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K bgp logs.
		logTime := time.Unix(100, 0).UTC()
		var logs []v1.BGPLog
		for i := range totalItems {
			bgpLog := v1.BGPLog{
				LogTime: logTime.Add(time.Duration(i) * time.Second).Format(v1.BGPLogTimeFormat),
				Host:    fmt.Sprintf("%d", i),
			}
			logs = append(logs, bgpLog)
		}
		bulk, err := cli.BGPLogs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create bgp log did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.BGPLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.BGPLog](&params)
		pages, errors := pager.Stream(ctx, cli.BGPLogs(cluster).List)

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

func TestFV_BGPTenancy(t *testing.T) {
	RunBGPLogTest(t, "should support tenancy restriction", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		cluster := cluster1

		// Create a basic log. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		reqTime := time.Unix(10, 0).UTC()
		bgpLogs := []v1.BGPLog{
			{
				LogTime: reqTime.Format(v1.BGPLogTimeFormat),
			},
		}
		bulk, err := tenantCLI.BGPLogs(cluster).Create(ctx, bgpLogs)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Try a read as well.
		params := v1.BGPLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: reqTime.Add(-5 * time.Second),
					To:   reqTime.Add(5 * time.Second),
				},
			},
		}
		resp, err := tenantCLI.BGPLogs(cluster).List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})
}
