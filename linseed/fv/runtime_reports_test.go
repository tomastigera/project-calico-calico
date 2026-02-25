// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
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

var (
	anotherCluster     string
	anotherClusterInfo bapi.ClusterInfo
)

func RunRuntimeReportTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.RuntimeReportMultiIndex)()
		defer runtimeReportsSetupAndTeardown(t, args, index.RuntimeReportMultiIndex)()
		testFn(t, index.RuntimeReportMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			RuntimeReportsBaseIndexName: index.RuntimeReportsIndex().Name(bapi.ClusterInfo{}),
			RuntimeReportsPolicyName:    index.RuntimeReportsIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.RuntimeReportsIndex())()
		defer runtimeReportsSetupAndTeardown(t, args, index.RuntimeReportsIndex())()
		testFn(t, index.RuntimeReportsIndex())
	})
}

// runtimeReportsSetupAndTeardown performs additional setup and teardown for runtime reports tests.
func runtimeReportsSetupAndTeardown(t *testing.T, args *RunLinseedArgs, idx bapi.Index) func() {
	anotherCluster = testutils.RandomClusterName()
	anotherClusterInfo = bapi.ClusterInfo{Cluster: anotherCluster, Tenant: args.TenantID}

	return func() {
		err := testutils.CleanupIndices(context.Background(), esClient, idx.IsSingleIndex(), idx, bapi.ClusterInfo{Cluster: anotherCluster})
		require.NoError(t, err)
	}
}

func TestFV_RuntimeReports(t *testing.T) {
	RunRuntimeReportTest(t, "should return an empty list if there are no runtime reports", func(t *testing.T, idx bapi.Index) {
		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		runtimeReports, err := cli.RuntimeReports(cluster1).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.RuntimeReport{}, runtimeReports.Items)
	})

	RunRuntimeReportTest(t, "should create and list runtime reports using generated time", func(t *testing.T, idx bapi.Index) {
		startTime := time.Unix(1, 0).UTC()
		endTime := time.Unix(1, 0).UTC()
		generatedTime := time.Unix(2, 2).UTC()
		// Create a basic runtime report
		report := v1.Report{
			// Note, Linseed will overwrite GeneratedTime with the current time when
			// Create is called.
			GeneratedTime: &generatedTime,
			StartTime:     startTime,
			EndTime:       endTime,
			Host:          "any-host",
			Count:         1,
			Type:          "ProcessStart",
			ConfigName:    "malware-protection",
			Pod: v1.PodInfo{
				Name:          "app",
				NameAggr:      "app-*",
				Namespace:     "default",
				ContainerName: "app",
			},
			File: v1.File{
				Path:     "/usr/sbin/runc",
				HostPath: "/run/docker/runtime-runc/moby/48f10a5eb9a245e6890433205053ba4e72c8e3bab5c13c2920dc32fadd7290cd/runc.rB3K51",
			},
			ProcessStart: v1.ProcessStart{
				Invocation: "runc --root /var/run/docker/runtime-runc/moby",
				Hashes: v1.ProcessHashes{
					MD5:    "MD5",
					SHA1:   "SHA1",
					SHA256: "SHA256",
				},
			},
			FileAccess: v1.FileAccess{},
		}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.RuntimeReports(clusterInfo.Cluster).Create(ctx, []v1.Report{report})
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create runtime reports did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(anotherClusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: generatedTime,
					To:   time.Now(),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1
			resp, err := cli.RuntimeReports(cluster).List(ctx, &params)
			require.NoError(t, err)

			require.Len(t, resp.Items, 1)
			testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, cluster, resp)
			report.GeneratedTime = resp.Items[0].Report.GeneratedTime
			require.Equal(t, []v1.RuntimeReport{{Tenant: "tenant-a", Cluster: cluster, Report: report}}, resp.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.RuntimeReports(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.RuntimeReports(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.RuntimeReportClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.RuntimeReports(v1.QueryMultipleClusters).List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.RuntimeReports(v1.QueryMultipleClusters).List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.RuntimeReportClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

	})

	RunRuntimeReportTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 runtime reports.
		referenceTime := time.Unix(1, 0).UTC()
		for i := range totalItems {
			reports := []v1.Report{
				{
					Host: fmt.Sprintf("%d", i),
				},
			}
			bulk, err := cli.RuntimeReports(cluster).Create(ctx, reports)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create runtime report did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(anotherClusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.RuntimeReportParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: referenceTime,
						To:   time.Now(),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
			}
			resp, err := cli.RuntimeReports(cluster).List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, cluster, resp)
			require.EqualValues(t, []v1.RuntimeReport{
				{
					Cluster: cluster,
					Tenant:  "tenant-a",
					Report: v1.Report{
						GeneratedTime: resp.Items[0].Report.GeneratedTime,
						Host:          fmt.Sprintf("%d", i),
					},
				},
			}, resp.Items, fmt.Sprintf("RuntimeReport #%d did not match", i))
			require.NotNil(t, resp.AfterKey)
			require.Contains(t, resp.AfterKey, "startFrom")
			require.Equal(t, resp.AfterKey["startFrom"], float64(i+1))

			// Use the afterKey for the next query.
			afterKey = resp.AfterKey
		}

		// If we query once more, we should get the last page, and no afterkey, since
		// we have paged through all the items.
		lastItem := totalItems - 1
		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: referenceTime,
					To:   time.Now(),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
		}
		resp, err := cli.RuntimeReports(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, cluster, resp)
		require.EqualValues(t, []v1.RuntimeReport{
			{
				Cluster: cluster,
				Tenant:  "tenant-a",
				Report: v1.Report{
					Host: fmt.Sprintf("%d", lastItem),
				},
			},
		}, resp.Items, fmt.Sprintf("RuntimeReport #%d did not match", lastItem))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunRuntimeReportTest(t, "should support pagination for items >= 10000 for runtime reports", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K runtime reports.
		referenceTime := time.Now().UTC()
		var reports []v1.Report
		for i := range totalItems {
			reports = append(reports, v1.Report{
				Host: fmt.Sprintf("%d", i),
			},
			)
		}
		bulk, err := cli.RuntimeReports(cluster).Create(ctx, reports)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Total, "create reports did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(anotherClusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: referenceTime,
					To:   time.Now(),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.RuntimeReport](&params)
		pages, errors := pager.Stream(ctx, cli.RuntimeReports(cluster).List)

		receivedItems := 0
		for page := range pages {
			receivedItems = receivedItems + len(page.Items)
		}

		if err, ok := <-errors; ok {
			require.NoError(t, err)
		}

		require.Equal(t, totalItems, receivedItems)
	})

	RunRuntimeReportTest(t, "should read data for multiple clusters", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		startTime := time.Unix(1, 0).UTC()
		endTime := time.Unix(1, 0).UTC()

		// Create a basic runtime report
		runtimeReport := v1.Report{
			StartTime:  startTime,
			EndTime:    endTime,
			Host:       "any-host",
			Count:      1,
			Type:       "ProcessStart",
			ConfigName: "malware-protection",
			Pod: v1.PodInfo{
				Name:          "app",
				NameAggr:      "app-*",
				Namespace:     "default",
				ContainerName: "app",
			},
			File: v1.File{
				Path:     "/usr/sbin/runc",
				HostPath: "/run/docker/runtime-runc/moby/48f10a5eb9a245e6890433205053ba4e72c8e3bab5c13c2920dc32fadd7290cd/runc.rB3K51",
			},
			ProcessStart: v1.ProcessStart{
				Invocation: "runc --root /var/run/docker/runtime-runc/moby",
				Hashes: v1.ProcessHashes{
					MD5:    "MD5",
					SHA1:   "SHA1",
					SHA256: "SHA256",
				},
			},
			FileAccess: v1.FileAccess{},
		}
		bulk, err := cli.RuntimeReports(cluster).Create(ctx, []v1.Report{runtimeReport})
		require.NoError(t, err)
		require.Equal(t, bulk.Succeeded, 1, "create runtime reports did not succeed")

		bulk, err = cli.RuntimeReports(anotherCluster).Create(ctx, []v1.Report{runtimeReport})
		require.NoError(t, err)
		require.Equal(t, bulk.Succeeded, 1, "create runtime reports did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(anotherClusterInfo))
		require.NoError(t, err)

		// Read it back.
		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   time.Now(),
				},
			},
		}
		respCluster, err := cli.RuntimeReports(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Len(t, respCluster.Items, 1)

		// Validate that the received reports come from a single clusters
		for _, item := range respCluster.Items {
			// Validate that the source is populated
			require.NotEmpty(t, item.Cluster)
			require.Equal(t, item.Cluster, cluster)
			testutils.AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t, cluster, &item)
			require.Equal(t, runtimeReport, item.Report)
		}

		respAnotherCluster, err := cli.RuntimeReports(anotherCluster).List(ctx, &params)
		require.NoError(t, err)
		require.Len(t, respAnotherCluster.Items, 1)

		// Validate that the received reports come from a single clusters
		for _, item := range respAnotherCluster.Items {
			// Validate that the source is populated
			require.NotEmpty(t, item.Cluster)
			require.Equal(t, item.Cluster, anotherCluster)
			testutils.AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t, anotherCluster, &item)
			require.Equal(t, runtimeReport, item.Report)
		}
	})

	RunRuntimeReportTest(t, "supports query with selector", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		startTime := time.Unix(1, 0).UTC()
		endTime := time.Unix(1, 0).UTC()

		// Create a basic runtime report
		runtimeReport1 := v1.Report{
			StartTime:  startTime,
			EndTime:    endTime,
			Host:       "any-host",
			Count:      1,
			Type:       "ProcessStart",
			ConfigName: "malware-protection",
			Pod: v1.PodInfo{
				Name:          "app1",
				NameAggr:      "app-*",
				Namespace:     "default",
				ContainerName: "app",
			},
			File: v1.File{
				Path:     "/usr/sbin/runc",
				HostPath: "/run/docker/runtime-runc/moby/48f10a5eb9a245e6890433205053ba4e72c8e3bab5c13c2920dc32fadd7290cd/runc.rB3K51",
			},
			ProcessStart: v1.ProcessStart{
				Invocation: "runc --root /var/run/docker/runtime-runc/moby",
				Hashes: v1.ProcessHashes{
					MD5:    "MD5",
					SHA1:   "SHA1",
					SHA256: "SHA256",
				},
			},
			FileAccess: v1.FileAccess{},
		}
		runtimeReport2 := runtimeReport1
		runtimeReport2.Pod.Name = "app2"
		bulk, err := cli.RuntimeReports(cluster).Create(ctx, []v1.Report{runtimeReport1, runtimeReport2})
		require.NoError(t, err)
		require.Equal(t, bulk.Succeeded, 2, "create runtime reports did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Use a selector to read back only the first report.
		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   time.Now(),
				},
			},
			Selector: "'pod.name' = 'app1'",
		}
		resp, err := cli.RuntimeReports(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)

		// Validate that we got the first report
		for _, item := range resp.Items {
			testutils.AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t, cluster, &item)
			require.Equal(t, runtimeReport1, item.Report)
		}

		// Repeat with a selector to get only the second report.
		params.Selector = "'pod.name' = 'app2'"
		resp, err = cli.RuntimeReports(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)

		// Validate that we got the second report
		for _, item := range resp.Items {
			testutils.AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t, cluster, &item)
			require.Equal(t, runtimeReport2, item.Report)
		}

		// Validate that we can't use a selector with a disallowed field.
		params.Selector = "'tenant_id' = 'super-secret'"
		_, err = cli.RuntimeReports(cluster).List(ctx, &params)
		require.ErrorContains(t, err, "tenant_id")
	})
}

func TestFV_RuntimeReportTenancy(t *testing.T) {
	RunRuntimeReportTest(t, "should support tenancy restriction", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		// Create a basic entry. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		startTime := time.Unix(1, 0).UTC()
		endTime := time.Unix(1, 0).UTC()

		// Create a basic runtime report
		report := v1.Report{
			StartTime:  startTime,
			EndTime:    endTime,
			Host:       "any-host",
			Count:      1,
			Type:       "ProcessStart",
			ConfigName: "malware-protection",
			Pod: v1.PodInfo{
				Name:          "app",
				NameAggr:      "app-*",
				Namespace:     "default",
				ContainerName: "app",
			},
			File: v1.File{
				Path:     "/usr/sbin/runc",
				HostPath: "/run/docker/runtime-runc/moby/48f10a5eb9a245e6890433205053ba4e72c8e3bab5c13c2920dc32fadd7290cd/runc.rB3K51",
			},
			ProcessStart: v1.ProcessStart{
				Invocation: "runc --root /var/run/docker/runtime-runc/moby",
				Hashes: v1.ProcessHashes{
					MD5:    "MD5",
					SHA1:   "SHA1",
					SHA256: "SHA256",
				},
			},
			FileAccess: v1.FileAccess{},
		}
		bulk, err := tenantCLI.RuntimeReports(cluster1).Create(ctx, []v1.Report{report})
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Try a read as well.
		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   time.Now(),
				},
			},
		}
		resp, err := tenantCLI.RuntimeReports(cluster1).List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})
}
