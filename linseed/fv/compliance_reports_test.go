// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

func RunComplianceReportTest(t *testing.T, name string, testFn func(*testing.T, bapi.Index)) {
	t.Run(fmt.Sprintf("%s [MultiIndex]", name), func(t *testing.T) {
		args := DefaultLinseedArgs()
		defer setupAndTeardown(t, args, nil, index.ComplianceReportMultiIndex)()
		testFn(t, index.ComplianceReportMultiIndex)
	})

	t.Run(fmt.Sprintf("%s [SingleIndex]", name), func(t *testing.T) {
		confArgs := &RunConfigureElasticArgs{
			ComplianceReportsBaseIndexName: index.ComplianceReportsIndex().Name(bapi.ClusterInfo{}),
			ComplianceReportsPolicyName:    index.ComplianceReportsIndex().ILMPolicyName(),
		}
		args := DefaultLinseedArgs()
		args.Backend = config.BackendTypeSingleIndex
		defer setupAndTeardown(t, args, confArgs, index.ComplianceReportsIndex())()
		testFn(t, index.ComplianceReportsIndex())
	})
}

func TestFV_ComplianceReports(t *testing.T) {
	RunComplianceReportTest(t, "should return an empty list if there are no reports", func(t *testing.T, idx bapi.Index) {
		params := v1.ReportDataParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now(),
				},
			},
		}

		// Perform a query.
		reports, err := cli.Compliance(cluster1).ReportData().List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, []v1.ReportData{}, reports.Items)
	})

	RunComplianceReportTest(t, "should create and list reports", func(t *testing.T, idx bapi.Index) {
		// Create a basic report.
		v3r := apiv3.ReportData{
			ReportName:     "test-report",
			ReportTypeName: "my-report-type",
			StartTime:      metav1.Time{Time: time.Unix(1, 0)},
			EndTime:        metav1.Time{Time: time.Unix(2, 0)},
			GenerationTime: metav1.Time{Time: time.Unix(3, 0)},
		}
		report := v1.ReportData{ReportData: &v3r}
		reports := []v1.ReportData{report}
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			bulk, err := cli.Compliance(clusterInfo.Cluster).ReportData().Create(ctx, reports)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create did not succeed")

			// Refresh elasticsearch so that results appear.
			err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Read it back.
		params := v1.ReportDataParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(0, 0),
					To:   time.Unix(4, 0),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			cluster := cluster1
			resp, err := cli.Compliance(cluster).ReportData().List(ctx, &params)
			require.NoError(t, err)

			// The ID should be set.
			require.Len(t, resp.Items, 1)
			testutils.AssertReportDataIDAndClusterAndReset(t, report.UID(), cluster, &resp.Items[0])
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, reports, resp.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			params.SetClusters(selectedClusters)

			_, err := cli.Compliance(v1.QueryMultipleClusters).ReportData().List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.Compliance(v1.QueryMultipleClusters).ReportData().List(ctx, &params)
			require.NoError(t, err)
			require.Len(t, resp.Items, 2)
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.ReportDataClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			params.SetAllClusters(true)
			_, err := cli.Compliance(v1.QueryMultipleClusters).ReportData().List(ctx, &params)
			require.ErrorContains(t, err, "Unauthorized")

			resp, err := multiClusterQueryClient.Compliance(v1.QueryMultipleClusters).ReportData().List(ctx, &params)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(resp.Items, testutils.ReportDataClusterEquals(cluster)), "expected result for cluster %s", cluster)
			}
		})
	})

	RunComplianceReportTest(t, "should support pagination", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 5

		// Create 5 Snapshots.
		logTime := time.Unix(100, 0).UTC()
		for i := range totalItems {
			reports := []v1.ReportData{
				{
					ReportData: &apiv3.ReportData{
						ReportName:     fmt.Sprintf("test-report-%d", i),
						ReportTypeName: "my-report-type",
						StartTime:      metav1.Time{Time: logTime.Add(time.Duration(i) * time.Second).UTC()},
						EndTime:        metav1.Time{Time: logTime.Add(time.Duration(i+1) * time.Second).UTC()},
						GenerationTime: metav1.Time{Time: logTime.Add(time.Duration(i+2) * time.Second).UTC()},
					},
				},
			}
			bulk, err := cli.Compliance(cluster).ReportData().Create(ctx, reports)
			require.NoError(t, err)
			require.Equal(t, bulk.Succeeded, 1, "create reports did not succeed")
		}

		// Refresh elasticsearch so that results appear.
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Iterate through the first 4 pages and check they are correct.
		var afterKey map[string]any
		for i := 0; i < totalItems-1; i++ {
			params := v1.ReportDataParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: logTime.Add(-20 * time.Second),
						To:   logTime.Add(20 * time.Second),
					},
					MaxPageSize: 1,
					AfterKey:    afterKey,
				},
			}
			resp, err := cli.Compliance(cluster).ReportData().List(ctx, &params)
			require.NoError(t, err)
			require.Equal(t, 1, len(resp.Items))
			testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
			require.Equal(t, []v1.ReportData{
				{
					ReportData: &apiv3.ReportData{
						ReportName:     fmt.Sprintf("test-report-%d", i),
						ReportTypeName: "my-report-type",
						StartTime:      metav1.Time{Time: logTime.Add(time.Duration(i) * time.Second).UTC()},
						EndTime:        metav1.Time{Time: logTime.Add(time.Duration(i+1) * time.Second).UTC()},
						GenerationTime: metav1.Time{Time: logTime.Add(time.Duration(i+2) * time.Second).UTC()},
					},
					Cluster: cluster,
				},
			}, reportsWithUTCTime(resp), fmt.Sprintf("Reports #%d did not match", i))
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
		params := v1.ReportDataParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-20 * time.Second),
					To:   logTime.Add(20 * time.Second),
				},
				MaxPageSize: 1,
				AfterKey:    afterKey,
			},
		}
		resp, err := cli.Compliance(cluster).ReportData().List(ctx, &params)
		require.NoError(t, err)
		require.Equal(t, 1, len(resp.Items))
		testutils.AssertGeneratedTimeAndReset(t, &resp.Items[0])
		require.Equal(t, []v1.ReportData{
			{
				ReportData: &apiv3.ReportData{
					ReportName:     fmt.Sprintf("test-report-%d", lastItem),
					ReportTypeName: "my-report-type",
					StartTime:      metav1.Time{Time: logTime.Add(time.Duration(lastItem) * time.Second).UTC()},
					EndTime:        metav1.Time{Time: logTime.Add(time.Duration(lastItem+1) * time.Second).UTC()},
					GenerationTime: metav1.Time{Time: logTime.Add(time.Duration(lastItem+2) * time.Second).UTC()},
				},
				Cluster: cluster,
			},
		}, reportsWithUTCTime(resp), fmt.Sprintf("Reports #%d did not match", lastItem))
		require.Equal(t, resp.TotalHits, int64(totalItems))

		// Once we reach the end of the data, we should not receive
		// an afterKey
		require.Nil(t, resp.AfterKey)
	})

	RunComplianceReportTest(t, "should support pagination for items >= 10000 for Reports", func(t *testing.T, idx bapi.Index) {
		cluster := cluster1
		clusterInfo := cluster1Info
		totalItems := 10001
		// Create > 10K reports.
		logTime := time.Unix(100, 0).UTC()
		var reports []v1.ReportData
		for i := range totalItems {
			reports = append(reports,
				v1.ReportData{
					ReportData: &apiv3.ReportData{
						ReportName:     fmt.Sprintf("test-report-%d", i),
						ReportTypeName: "my-report-type",
						StartTime:      metav1.Time{Time: logTime.Add(time.Duration(i) * time.Second).UTC()},
						EndTime:        metav1.Time{Time: logTime.Add(time.Duration(i+1) * time.Second).UTC()},
						GenerationTime: metav1.Time{Time: logTime.Add(time.Duration(i+2) * time.Second).UTC()},
					},
				},
			)
		}
		bulk, err := cli.Compliance(cluster).ReportData().Create(ctx, reports)
		require.NoError(t, err)
		require.Equal(t, totalItems, bulk.Succeeded, "create reports did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Stream through all the items.
		params := v1.ReportDataParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: logTime.Add(-5 * time.Second),
					To:   logTime.Add(time.Duration(totalItems) * time.Second),
				},
				MaxPageSize: 1000,
			},
		}

		pager := client.NewListPager[v1.ReportData](&params)
		pages, errors := pager.Stream(ctx, cli.Compliance(cluster).ReportData().List)

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

func TestFV_ComplianceReportsTenancy(t *testing.T) {
	RunComplianceReportTest(t, "should support tenancy restriction", func(t *testing.T, idx bapi.Index) {
		// Instantiate a client for an unexpected tenant.
		args := DefaultLinseedArgs()
		args.TenantID = "bad-tenant"
		tenantCLI, err := NewLinseedClient(args, TokenPath)
		require.NoError(t, err)

		cluster := cluster1

		// Create a basic log. We expect this to fail, since we're using
		// an unexpected tenant ID on the request.
		v3r := apiv3.ReportData{
			ReportName:     "test-report",
			ReportTypeName: "my-report-type",
			StartTime:      metav1.Time{Time: time.Unix(1, 0)},
			EndTime:        metav1.Time{Time: time.Unix(2, 0)},
			GenerationTime: metav1.Time{Time: time.Unix(3, 0)},
		}
		report := v1.ReportData{ReportData: &v3r}
		reports := []v1.ReportData{report}
		bulk, err := tenantCLI.Compliance(cluster).ReportData().Create(ctx, reports)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, bulk)

		// Try a read as well.
		params := v1.ReportDataParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(0, 0),
					To:   time.Unix(4, 0),
				},
			},
		}
		resp, err := tenantCLI.Compliance(cluster).ReportData().List(ctx, &params)
		require.ErrorContains(t, err, "Bad tenant identifier")
		require.Nil(t, resp)
	})
}

func reportsWithUTCTime(resp *v1.List[v1.ReportData]) []v1.ReportData {
	for idx, report := range resp.Items {
		utcStartTime := report.StartTime.UTC()
		utcEndTime := report.EndTime.UTC()
		utcGenTime := report.GenerationTime.UTC()
		resp.Items[idx].StartTime = metav1.Time{Time: utcStartTime}
		resp.Items[idx].EndTime = metav1.Time{Time: utcEndTime}
		resp.Items[idx].GenerationTime = metav1.Time{Time: utcGenTime}
		resp.Items[idx].ID = ""
	}
	return resp.Items
}
