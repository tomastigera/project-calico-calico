// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func RunDNSLogTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.DNSLogMultiIndex)()
		testFn(t, index.DNSLogMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			DNSBaseIndexName: index.DNSLogIndex().Name(bapi.ClusterInfo{}),
			DNSPolicyName:    index.DNSLogIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.DNSLogIndex())()
		testFn(t, index.DNSLogIndex())
	})
}

func TestDNS_DNSLogs(t *testing.T) {
	RunDNSLogTest(t, "should return an empty list if there are no dns logs", func(t *testing.T, idx bapi.Index) {
		params := v1.DNSLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		logs, err := cli.DNSLogs(cluster1).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.DNSLog{}, logs.Items)
	})

	RunDNSLogTest(t, "should create and list dns logs", func(t *testing.T, idx bapi.Index) {
		// Create a basic flow log.
		logs := []v1.DNSLog{
			{
				EndTime: time.Now().UTC(), // TODO: Add more fields
				QName:   "service.namespace.svc.cluster.local",
				QClass:  v1.DNSClass(layers.DNSClassIN),
				QType:   v1.DNSType(layers.DNSTypeAAAA),
				RCode:   v1.DNSResponseCode(layers.DNSResponseCodeNXDomain),
				RRSets:  v1.DNSRRSets{},
			},
		}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.DNSLogs(clusterInfo.Cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create dns log did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.DNSLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1
			resp, err := cli.DNSLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			for i := range resp.Items {
				testutils.AssertDNSLogIDAndClusterAndReset(t, cluster, &resp.Items[i])
			}
			require.Equal(t, logs, resp.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.DNSLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.DNSLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.DNSLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.DNSLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.DNSLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.DNSLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

	})

	RunDNSLogTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 dns logs.
		logTime := time.Unix(0, 0).UTC()
		for i := range totalItems {
			logs := []v1.DNSLog{
				{
					StartTime: logTime,
					EndTime:   logTime.Add(time.Duration(i) * time.Second), // Make sure logs are ordered.
					Host:      fmt.Sprintf("%d", i),
				},
			}
			bulk, err := cli.DNSLogs(cluster).Create(ctx, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create dns log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.DNSLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: logTime.Add(-5 * time.Second),
						To:   logTime.Add(5 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
			}
			resp, err := cli.DNSLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertDNSLogIDAndClusterAndReset(t, cluster, &resp.Items[0])
			require.Equal(t, []v1.DNSLog{
				{
					StartTime: logTime,
					EndTime:   logTime.Add(time.Duration(i) * time.Second),
					Host:      fmt.Sprintf("%d", i),
					RCode:     v1.DNSResponseCode(0),
					RRSets:    v1.DNSRRSets{},
				},
			}, resp.Items, fmt.Sprintf("DNS #%d did not match", i))
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
		params := v1.DNSLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(5 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
		}
		resp, err := cli.DNSLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertDNSLogIDAndClusterAndReset(t, cluster, &resp.Items[0])
		require.Equal(t, []v1.DNSLog{
			{
				StartTime: logTime,
				EndTime:   logTime.Add(time.Duration(lastItem) * time.Second),
				Host:      fmt.Sprintf("%d", lastItem),
				RCode:     v1.DNSResponseCode(0),
				RRSets:    v1.DNSRRSets{},
			},
		}, resp.Items, fmt.Sprintf("DNS #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunDNSLogTest(t, "should support pagination for items >= 10000 for dns", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K dns logs.
		logTime := time.Unix(100, 0).UTC()
		var logs []v1.DNSLog
		for i := range totalItems {
			logs = append(logs, v1.DNSLog{
				StartTime: logTime,
				EndTime:   logTime.Add(time.Duration(i) * time.Second), // Make sure logs are ordered.
				Host:      fmt.Sprintf("%d", i),
			})
		}
		bulk, err := cli.DNSLogs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create dns log did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.DNSLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.DNSLog](&params)
		pages, errors := pager.Stream(ctx, cli.DNSLogs(cluster).List)

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

func TestFV_DNSLogTenancy(t *testing.T) {
	RunDNSLogTest(t, "should support tenancy restriction", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		cluster := cluster1

		// Create a basic log. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		logs := []v1.DNSLog{
			{
				EndTime: time.Now().UTC(),
				QName:   "service.namespace.svc.cluster.local",
				QClass:  v1.DNSClass(layers.DNSClassIN),
				QType:   v1.DNSType(layers.DNSTypeAAAA),
				RCode:   v1.DNSResponseCode(layers.DNSResponseCodeNXDomain),
				RRSets:  v1.DNSRRSets{},
			},
		}
		bulk, err := tenantCLI.DNSLogs(cluster).Create(ctx, logs)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Try a read as well.
		params := v1.DNSLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}
		resp, err := tenantCLI.DNSLogs(cluster).List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})
}
