// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/apis/audit"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func RunAuditEETest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.AuditLogEEMultiIndex)()
		testFn(t, index.AuditLogEEMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			AuditBaseIndexName: index.AuditLogIndex().Name(bapi.ClusterInfo{}),
			AuditPolicyName:    index.AuditLogIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.AuditLogIndex())()
		testFn(t, index.AuditLogIndex())
	})
}

func RunAuditKubeTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.AuditLogKubeMultiIndex)()
		testFn(t, index.AuditLogKubeMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			AuditBaseIndexName: index.AuditLogIndex().Name(bapi.ClusterInfo{}),
			AuditPolicyName:    index.AuditLogIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.AuditLogIndex())()
		testFn(t, index.AuditLogIndex())
	})
}

func TestFV_AuditEE(t *testing.T) {
	RunAuditEETest(t, "should return an empty list if there are no EE audits", func(t *testing.T, idx bapi.Index) {
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
			Type: v1.AuditLogTypeEE,
		}

		// Perform a query.
		audits, err := cli.AuditLogs(cluster1).List(ctx, &params)

		require.NoError(t, err)
		require.Equal(t, []v1.AuditLog{}, audits.Items)
	})

	RunAuditEETest(t, "should create and list EE audits", func(t *testing.T, idx bapi.Index) {
		reqTime := time.Now()
		// Create a basic audit log
		audits := []v1.AuditLog{{Event: audit.Event{
			AuditID:                  "any-ee-id",
			RequestReceivedTimestamp: metav1.NewMicroTime(reqTime),
		}}}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.AuditLogs(clusterInfo.Cluster).Create(ctx, v1.AuditLogTypeEE, audits)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create audit did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: reqTime.Add(-5 * time.Second),
					To:   reqTime.Add(5 * time.Second),
				},
			},
			Type: v1.AuditLogTypeEE,
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1

			resp, err := cli.AuditLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 1)

			// Reset the time as it microseconds to not match perfectly
			require.NotEqual(t, "", resp.Items[0].RequestReceivedTimestamp)
			resp.Items[0].RequestReceivedTimestamp = metav1.NewMicroTime(reqTime)
			testutils.AssertAuditLogClusterAndReset(t, cluster, &resp.Items[0])
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])

			require.Equal(t, audits, resp.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)

			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.AuditLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.AuditLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunAuditKubeTest(t, "should return an empty list if there are no Kube audits", func(t *testing.T, idx bapi.Index) {
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
			Type: v1.AuditLogTypeKube,
		}

		// Perform a query.
		audits, err := cli.AuditLogs(cluster1).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.AuditLog{}, audits.Items)
	})

	RunAuditKubeTest(t, "should create and list Kube audits", func(t *testing.T, idx bapi.Index) {
		// Create a basic audit log.
		reqTime := time.Now()
		audits := []v1.AuditLog{{Event: audit.Event{
			AuditID:                  "any-kube-id",
			RequestReceivedTimestamp: metav1.NewMicroTime(reqTime),
		}}}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.AuditLogs(clusterInfo.Cluster).Create(ctx, v1.AuditLogTypeKube, audits)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create audit did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: reqTime.Add(-5 * time.Second),
					To:   reqTime.Add(5 * time.Second),
				},
			},
			Type: v1.AuditLogTypeKube,
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1

			resp, err := cli.AuditLogs(cluster).List(ctx, &params)
			require.NoError(t, err)

			require.Len(t, resp.Items, 1)
			// Reset the time as it microseconds to not match perfectly
			require.NotEqual(t, "", resp.Items[0].RequestReceivedTimestamp)
			resp.Items[0].RequestReceivedTimestamp = metav1.NewMicroTime(reqTime)
			testutils.AssertAuditLogClusterAndReset(t, cluster, &resp.Items[0])
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])

			require.Equal(t, audits, resp.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)

			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.AuditLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.AuditLogs(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.AuditLogClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunAuditEETest(t, "should support pagination for items >= 10000 for EE Audit", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K audit logs.
		logTime := time.Unix(100, 0).UTC()
		var logs []v1.AuditLog
		for i := range totalItems {
			auditLog := v1.AuditLog{
				Event: audit.Event{
					RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(i) * time.Second)),
					AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", i)),
				},
			}
			logs = append(logs, auditLog)
		}
		bulk, err := cli.AuditLogs(cluster).Create(ctx, v1.AuditLogTypeEE, logs)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create EE audit log did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
			Type: v1.AuditLogTypeEE,
		}

		pager := client.NewListPager[v1.AuditLog](&params)
		pages, errors := pager.Stream(ctx, cli.AuditLogs(cluster).List)

		receivedItems := 0
		for page := range pages {
			receivedItems = receivedItems + len(page.Items)
		}

		if err, ok := <-errors; ok {
			require.NoError(t, err)
		}

		require.Equal(t, receivedItems, totalItems)
	})

	RunAuditKubeTest(t, "should support pagination for items >= 10000 for Kube Audit", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K audit logs.
		logTime := time.Unix(100, 0).UTC()
		var logs []v1.AuditLog
		for i := range totalItems {
			auditLog := v1.AuditLog{
				Event: audit.Event{
					RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(i) * time.Second)),
					AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", i)),
				},
			}
			logs = append(logs, auditLog)
		}
		bulk, err := cli.AuditLogs(cluster).Create(ctx, v1.AuditLogTypeKube, logs)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create Kube audit log did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
			Type: v1.AuditLogTypeKube,
		}

		pager := client.NewListPager[v1.AuditLog](&params)
		pages, errors := pager.Stream(ctx, cli.AuditLogs(cluster).List)

		receivedItems := 0
		for page := range pages {
			receivedItems = receivedItems + len(page.Items)
		}

		if err, ok := <-errors; ok {
			require.NoError(t, err)
		}

		require.Equal(t, receivedItems, totalItems)
	})

	RunAuditEETest(t, "should support pagination for EE Audit", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5
		// Create 5 audit logs.
		logTime := time.Unix(100, 0).UTC()
		for i := range totalItems {
			logs := []v1.AuditLog{
				{
					Event: audit.Event{
						RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(i) * time.Second)),
						AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", i)),
					},
				},
			}
			bulk, err := cli.AuditLogs(cluster).Create(ctx, v1.AuditLogTypeEE, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create EE audit log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.AuditLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: logTime.Add(-5 * time.Second),
						To:   logTime.Add(5 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
				Type: v1.AuditLogTypeEE,
			}
			resp, err := cli.AuditLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, []v1.AuditLog{
				{
					Event: audit.Event{
						RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(i) * time.Second)),
						AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", i)),
					},
					Cluster: cluster,
				},
			}, auditLogsWithUTCTime(resp), fmt.Sprintf("Audit Log EE #%d did not match", i))
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
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(5 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
			Type: v1.AuditLogTypeEE,
		}
		resp, err := cli.AuditLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
		require.Equal(t, []v1.AuditLog{
			{
				Event: audit.Event{
					RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(lastItem) * time.Second)),
					AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", lastItem)),
				},
				Cluster: cluster,
			},
		}, auditLogsWithUTCTime(resp), fmt.Sprintf("Audit Log EE #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunAuditKubeTest(t, "should support pagination for Kube Audit", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 audit logs.
		logTime := time.Unix(100, 0).UTC()
		for i := range totalItems {
			logs := []v1.AuditLog{
				{
					Event: audit.Event{
						RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(i) * time.Second)),
						AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", i)),
					},
				},
			}
			bulk, err := cli.AuditLogs(cluster).Create(ctx, v1.AuditLogTypeKube, logs)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create KUBE audit log did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.AuditLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: logTime.Add(-5 * time.Second),
						To:   logTime.Add(5 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
				Type: v1.AuditLogTypeKube,
			}
			resp, err := cli.AuditLogs(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, []v1.AuditLog{
				{
					Event: audit.Event{
						RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(i) * time.Second)),
						AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", i)),
					},
					Cluster: cluster,
				},
			}, auditLogsWithUTCTime(resp), fmt.Sprintf("Audit Log Kube #%d did not match", i))
			require.NotNil(t, resp.AfterKey)
			require.Contains(t, resp.AfterKey, "startFrom")
			require.Equal(t, resp.AfterKey["startFrom"], float64(i+1))
			require.Equal(t, resp.TotalHits, int64(5))

			// Use the afterKey for the next query.
			afterKey = resp.AfterKey
		}

		// If we query once more, we should get the last page, and no afterkey, since
		// we have paged through all the items.
		lastItem := totalItems - 1
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(5 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
			Type: v1.AuditLogTypeKube,
		}
		resp, err := cli.AuditLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
		require.Equal(t, []v1.AuditLog{
			{
				Event: audit.Event{
					RequestReceivedTimestamp: metav1.NewMicroTime(logTime.UTC().Add(time.Duration(lastItem) * time.Second)),
					AuditID:                  types.UID(fmt.Sprintf("some-uuid-%d", lastItem)),
				},
				Cluster: cluster,
			},
		}, auditLogsWithUTCTime(resp), fmt.Sprintf("Audit Log Kube #%d did not match", lastItem))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})
}

func TestFV_AuditLogsTenancy(t *testing.T) {
	RunAuditKubeTest(t, "should support tenancy restriction", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		cluster := cluster1
		clusterInfo := cluster1Info

		// Create a basic log. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		reqTime := time.Now()
		audits := []v1.AuditLog{{Event: audit.Event{
			AuditID:                  "any-kube-id",
			RequestReceivedTimestamp: metav1.NewMicroTime(reqTime),
		}}}
		bulk, err := tenantCLI.AuditLogs(cluster).Create(ctx, v1.AuditLogTypeKube, audits)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Read it back.
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: reqTime.Add(-5 * time.Second),
					To:   reqTime.Add(5 * time.Second),
				},
			},
			Type: v1.AuditLogTypeKube,
		}
		resp, err := tenantCLI.AuditLogs(cluster).List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})
}

func auditLogsWithUTCTime(resp *v1.List[v1.AuditLog]) []v1.AuditLog {
	for idx, audit := range resp.Items {
		utcTime := audit.RequestReceivedTimestamp.UTC()
		resp.Items[idx].RequestReceivedTimestamp = metav1.NewMicroTime(utcTime)
	}
	return resp.Items
}
