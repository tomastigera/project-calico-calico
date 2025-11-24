// Copyright (c) 2023 Tigera, Inc. All rights reserved.

//go:build fvtests

package fv_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	backendtestutils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func TestFV_L3FlowsCount(t *testing.T) {
	RunFlowLogTest(t, "should return correct count for basic L3 flows", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info

		// Create flow logs that aggregate into 2 L3 flows

		// L3 flow 1: default -> kube-system:kube-dns:53
		flow1Logs := []v1.FlowLog{
			{
				EndTime:              time.Now().Unix(),
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestServiceName:      "kube-dns",
				DestServiceNamespace: "kube-system",
				DestServicePortNum:   testutils.Int64Ptr(53),
				DestPort:             testutils.Int64Ptr(53),
				Protocol:             "udp",
				SourceType:           "wep",
				DestType:             "wep",
				Reporter:             "src",
				Action:               "allowed",
			},
			// Another log with same aggregation key
			{
				EndTime:              time.Now().Unix(),
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestServiceName:      "kube-dns",
				DestServiceNamespace: "kube-system",
				DestServicePortNum:   testutils.Int64Ptr(53),
				DestPort:             testutils.Int64Ptr(53),
				Protocol:             "udp",
				SourceType:           "wep",
				DestType:             "wep",
				Reporter:             "src",
				Action:               "allowed",
			},
		}

		// L3 flow 2: production -> database:postgres:5432
		flow2Logs := []v1.FlowLog{
			{
				EndTime:              time.Now().Unix(),
				SourceNamespace:      "production",
				DestNamespace:        "database",
				DestServiceName:      "postgres",
				DestServiceNamespace: "database",
				DestServicePortNum:   testutils.Int64Ptr(5432),
				DestPort:             testutils.Int64Ptr(5432),
				Protocol:             "tcp",
				SourceType:           "wep",
				DestType:             "wep",
				Reporter:             "src",
				Action:               "allowed",
			},
		}

		// Create logs
		bulk, err := cli.FlowLogs(cluster).Create(ctx, append(flow1Logs, flow2Logs...))
		require.NoError(t, err)
		require.Equal(t, 3, bulk.Succeeded)

		// Refresh elasticsearch
		err = backendtestutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Count L3 flows
		params := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
				},
			},
		}

		resp, err := cli.L3Flows(cluster).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)
		require.Equal(t, int64(2), *resp.GlobalCount)
		require.False(t, resp.GlobalCountTruncated)
		require.NotNil(t, resp.NamespacedCounts)
		// Validate specific namespace counts
		// Flow 1: default -> kube-system
		// Flow 2: production -> database
		require.Equal(t, int64(1), resp.NamespacedCounts["default"], "default namespace count")
		require.Equal(t, int64(1), resp.NamespacedCounts["kube-system"], "kube-system namespace count")
		require.Equal(t, int64(1), resp.NamespacedCounts["production"], "production namespace count")
		require.Equal(t, int64(1), resp.NamespacedCounts["database"], "database namespace count")
		require.Equal(t, 4, len(resp.NamespacedCounts), "should have exactly 4 namespaces")
	})

	RunFlowLogTest(t, "should count L3 flows across multiple clusters", func(t *testing.T, idx bapi.Index) {
		// Create flow logs in cluster1, cluster2, cluster3
		// Each set of logs aggregates to 1 L3 flow per cluster

		for i, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			logs := []v1.FlowLog{
				{
					EndTime:              time.Now().Unix(),
					SourceNamespace:      "default",
					DestNamespace:        "kube-system",
					DestServiceName:      "kube-dns",
					DestServiceNamespace: "kube-system",
					DestServicePortNum:   testutils.Int64Ptr(53),
					DestPort:             testutils.Int64Ptr(53),
					Protocol:             "udp",
					SourceType:           "wep",
					DestType:             "wep",
					Reporter:             "src",
					Action:               "allowed",
				},
			}

			bulk, err := cli.FlowLogs(clusterInfo.Cluster).Create(ctx, logs)
			require.NoError(t, err, "cluster %d", i)
			require.Equal(t, 1, bulk.Succeeded)

			err = backendtestutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		params := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
				},
			},
		}

		// Count single cluster
		resp, err := cli.L3Flows(cluster1).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)
		require.Equal(t, int64(1), *resp.GlobalCount)
		require.False(t, resp.GlobalCountTruncated)
		require.NotNil(t, resp.NamespacedCounts)
		require.Equal(t, int64(1), resp.NamespacedCounts["default"], "single cluster: default count")
		require.Equal(t, int64(1), resp.NamespacedCounts["kube-system"], "single cluster: kube-system count")
		require.Equal(t, 2, len(resp.NamespacedCounts), "single cluster: should have 2 namespaces")

		// Count multiple clusters (2 and 3)
		params.SetClusters([]string{cluster2, cluster3})
		resp, err = multiClusterQueryClient.L3Flows(v1.QueryMultipleClusters).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)
		require.Equal(t, int64(2), *resp.GlobalCount) // 1 from cluster2 + 1 from cluster3
		require.False(t, resp.GlobalCountTruncated)
		require.NotNil(t, resp.NamespacedCounts)
		require.Equal(t, int64(2), resp.NamespacedCounts["default"], "multi-cluster: default count (cluster2+3)")
		require.Equal(t, int64(2), resp.NamespacedCounts["kube-system"], "multi-cluster: kube-system count (cluster2+3)")
		require.Equal(t, 2, len(resp.NamespacedCounts), "multi-cluster: should have 2 namespaces")

		// Count all clusters
		params.SetAllClusters(true)
		resp, err = multiClusterQueryClient.L3Flows(v1.QueryMultipleClusters).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)
		require.Equal(t, int64(3), *resp.GlobalCount) // 1 + 1 + 1
		require.False(t, resp.GlobalCountTruncated)
		require.NotNil(t, resp.NamespacedCounts)
		require.Equal(t, int64(3), resp.NamespacedCounts["default"], "all clusters: default count")
		require.Equal(t, int64(3), resp.NamespacedCounts["kube-system"], "all clusters: kube-system count")
		require.Equal(t, 2, len(resp.NamespacedCounts), "all clusters: should have 2 namespaces")
	})

	RunFlowLogTest(t, "should enforce tenant boundaries on L3 flow count", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info

		// Create tenant-b Linseed instance
		tenantBArgs := DefaultLinseedArgs()
		tenantBArgs.TenantID = "tenant-b"
		tenantBArgs.Port = tenantBArgs.Port + 1
		tenantBArgs.MetricsPort = 0
		tenantBArgs.HealthPort = 0
		lb := RunLinseed(t, tenantBArgs)
		defer lb.Stop()

		// Create client for tenant-b
		tenantBCLI, err := NewLinseedClient(tenantBArgs, TokenPath)
		require.NoError(t, err)

		// Create flow logs in tenant-a (aggregates to 1 L3 flow)
		logs := []v1.FlowLog{
			{
				EndTime:              time.Now().Unix(),
				SourceNamespace:      "default",
				DestNamespace:        "kube-system",
				DestServiceName:      "kube-dns",
				DestServiceNamespace: "kube-system",
				DestServicePortNum:   testutils.Int64Ptr(53),
				DestPort:             testutils.Int64Ptr(53),
				Protocol:             "udp",
				SourceType:           "wep",
				DestType:             "wep",
				Reporter:             "src",
				Action:               "allowed",
			},
		}

		bulk, err := cli.FlowLogs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, 1, bulk.Succeeded)

		err = backendtestutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
				},
			},
		}

		// Tenant-b should get count of 0
		resp, err := tenantBCLI.L3Flows(cluster).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)
		require.Equal(t, int64(0), *resp.GlobalCount)
		require.False(t, resp.GlobalCountTruncated)
		require.NotNil(t, resp.NamespacedCounts, "tenant-b: NamespacedCounts should not be nil")
		require.Empty(t, resp.NamespacedCounts, "tenant-b: NamespacedCounts should be empty")

		// Tenant-a should get count of 1
		resp, err = cli.L3Flows(cluster).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)
		require.Equal(t, int64(1), *resp.GlobalCount)
		require.False(t, resp.GlobalCountTruncated)
		require.NotNil(t, resp.NamespacedCounts)
		require.Equal(t, int64(1), resp.NamespacedCounts["default"], "tenant-a: default count")
		require.Equal(t, int64(1), resp.NamespacedCounts["kube-system"], "tenant-a: kube-system count")
		require.Equal(t, 2, len(resp.NamespacedCounts), "tenant-a: should have 2 namespaces")
	})

	RunFlowLogTest(t, "should respect MaxGlobalCount parameter", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info

		// Create 10 different L3 flows
		var allLogs []v1.FlowLog
		for i := 0; i < 10; i++ {
			log := v1.FlowLog{
				EndTime:              time.Now().Unix(),
				SourceNamespace:      fmt.Sprintf("namespace-%d", i),
				DestNamespace:        "kube-system",
				DestServiceName:      "service",
				DestServiceNamespace: "kube-system",
				DestServicePortNum:   testutils.Int64Ptr(int64(8000 + i)), // Different port = different L3 flow
				DestPort:             testutils.Int64Ptr(int64(8000 + i)),
				Protocol:             "tcp",
				SourceType:           "wep",
				DestType:             "wep",
				Reporter:             "src",
				Action:               "allowed",
			}
			allLogs = append(allLogs, log)
		}

		bulk, err := cli.FlowLogs(cluster).Create(ctx, allLogs)
		require.NoError(t, err)
		require.Equal(t, 10, bulk.Succeeded)

		err = backendtestutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Count with MaxGlobalCount=5, MaxPageSize=2
		maxCount := int64(5)
		params := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
					MaxPageSize: 2,
				},
			},
			MaxGlobalCount: &maxCount,
		}

		resp, err := cli.L3Flows(cluster).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)

		// Expect the GlobalCount to be truncated to 6, given the page size.
		require.Equal(t, *resp.GlobalCount, int64(6))

		// Should be marked as truncated
		require.True(t, resp.GlobalCountTruncated)

		// NamespacedCounts should be nil when truncated
		require.Nil(t, resp.NamespacedCounts)
	})

	RunFlowLogTest(t, "should return count of 0 when no L3 flows exist", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1

		// Don't create any flow logs, just count
		params := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Second),
						To:   time.Now().Add(5 * time.Second),
					},
				},
			},
		}

		resp, err := cli.L3Flows(cluster).Count(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp.GlobalCount)
		require.Equal(t, int64(0), *resp.GlobalCount)
		require.False(t, resp.GlobalCountTruncated)
		require.NotNil(t, resp.NamespacedCounts)
		require.Empty(t, resp.NamespacedCounts)
	})
}
