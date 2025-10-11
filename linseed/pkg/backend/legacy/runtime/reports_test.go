// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package runtime_test

import (
	"context"
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
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/runtime"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

var (
	client        lmaelastic.Client
	b             bapi.RuntimeBackend
	migration     bapi.RuntimeBackend
	ctx           context.Context
	cluster1      string
	cluster2      string
	cluster3      string
	tenant        string
	anotherTenant string
	indexGetter   bapi.Index
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
		indexGetter = index.RuntimeReportsIndex()
		b = runtime.NewSingleIndexBackend(client, cache, 10000, false)
		migration = runtime.NewSingleIndexBackend(client, cache, 10000, true)
	} else {
		b = runtime.NewBackend(client, cache, 10000, false)
		migration = runtime.NewBackend(client, cache, 10000, true)
		indexGetter = index.RuntimeReportMultiIndex
	}

	// Create a random cluster name for each test to make sure we don't
	// interfere between tests.
	cluster1 = testutils.RandomClusterName()
	cluster2 = testutils.RandomClusterName()
	cluster3 = testutils.RandomClusterName()
	tenant = testutils.RandomTenantName()
	anotherTenant = testutils.RandomTenantName()

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

// TestCreateRuntimeReport tests running a real elasticsearch query to create a runtime report.
func TestCreateRuntimeReport(t *testing.T) {
	RunAllModes(t, "TestCreateRuntimeReport", func(t *testing.T) {
		cluster1Info := bapi.ClusterInfo{Cluster: cluster1}
		cluster2Info := bapi.ClusterInfo{Cluster: cluster2}
		cluster3Info := bapi.ClusterInfo{Cluster: cluster3}

		startTime := time.Unix(1, 0).UTC()
		endTime := time.Unix(2, 0).UTC()
		generatedTime := time.Unix(3, 0).UTC()
		f := v1.Report{
			// Note, GeneratedTime not specified; Linseed will populate it.
			StartTime:  startTime,
			EndTime:    endTime,
			Host:       "host",
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
					MD5:    "",
					SHA1:   "",
					SHA256: "SHA256",
				},
			},
			FileAccess: v1.FileAccess{},
		}

		// Create the runtime report in ES.
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			resp, err := b.Create(ctx, clusterInfo, []v1.Report{f})
			require.NoError(t, err)
			require.Equal(t, []v1.BulkError(nil), resp.Errors)
			require.Equal(t, 1, resp.Total)
			require.Equal(t, 0, resp.Failed)
			require.Equal(t, 1, resp.Succeeded)

			// Refresh the index.
			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)
		}

		// Query using normal time range.
		opts := &v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: generatedTime,
					To:   time.Now(),
				},
			},
		}

		t.Run("should query single cluster", func(t *testing.T) {
			clusterInfo := cluster1Info
			results, err := b.List(ctx, clusterInfo, opts)
			require.NoError(t, err)
			require.Equal(t, 1, len(results.Items))
			testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, clusterInfo.Cluster, results)
			require.Equal(t, []v1.RuntimeReport{{Tenant: "", Cluster: clusterInfo.Cluster, Report: f}}, results.Items)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			selectedClusters := []string{cluster2, cluster3}
			opts.SetClusters(selectedClusters)
			results, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, opts)
			require.NoError(t, err)
			require.Equal(t, 2, len(results.Items))
			for _, cluster := range selectedClusters {
				require.Truef(t, testutils.MatchIn(results.Items, testutils.RuntimeReportClusterEquals(cluster)), "Cluster %s not found in results", cluster)
			}
		})

		t.Run("should query all clusters", func(t *testing.T) {
			opts.SetAllClusters(true)
			results, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, opts)
			require.NoError(t, err)
			for _, cluster := range []string{cluster1, cluster2, cluster3} {
				require.Truef(t, testutils.MatchIn(results.Items, testutils.RuntimeReportClusterEquals(cluster)), "Cluster %s not found in results", cluster)
			}
		})
	})
}

// TestCreateRuntimeReport tests running a real elasticsearch query to create a runtime report.
func TestCreateRuntimeReportForMultipleTenants(t *testing.T) {
	RunAllModes(t, "TestCreateRuntimeReportForMultipleTenants", func(t *testing.T) {
		startTime := time.Unix(1, 0).UTC()
		endTime := time.Unix(2, 0).UTC()
		generatedTime := time.Unix(3, 0).UTC()
		f := v1.Report{
			// Note, GeneratedTime not specified; Linseed will populate it.
			StartTime:  startTime,
			EndTime:    endTime,
			Host:       "host",
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
					MD5:    "",
					SHA1:   "",
					SHA256: "SHA256",
				},
			},
			FileAccess: v1.FileAccess{},
		}

		// Create the runtime report in ES.
		clusterInfoA := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
		resp, err := b.Create(ctx, clusterInfoA, []v1.Report{f})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), resp.Errors)
		require.Equal(t, 1, resp.Total)
		require.Equal(t, 0, resp.Failed)
		require.Equal(t, 1, resp.Succeeded)

		clusterInfoB := bapi.ClusterInfo{Cluster: cluster1, Tenant: anotherTenant}
		resp, err = b.Create(ctx, clusterInfoB, []v1.Report{f})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), resp.Errors)
		require.Equal(t, 1, resp.Total)
		require.Equal(t, 0, resp.Failed)
		require.Equal(t, 1, resp.Succeeded)

		// Refresh the index.
		err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfoA))
		require.NoError(t, err)
		err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfoB))
		require.NoError(t, err)

		// Read data and verify for tenant A
		results, err := b.List(ctx, clusterInfoA, &v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: generatedTime,
					To:   time.Now(),
				},
			},
		})
		require.NoError(t, err)
		require.Equal(t, 1, len(results.Items))
		testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, clusterInfoA.Cluster, results)
		require.Equal(t, []v1.RuntimeReport{{Tenant: tenant, Cluster: cluster1, Report: f}}, results.Items)

		// Read data and verify for tenant B
		results, err = b.List(ctx, clusterInfoB, &v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: generatedTime,
					To:   time.Now(),
				},
			},
		})
		require.NoError(t, err)
		require.Equal(t, 1, len(results.Items))
		testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, clusterInfoB.Cluster, results)
		require.Equal(t, []v1.RuntimeReport{{Tenant: anotherTenant, Cluster: cluster1, Report: f}}, results.Items)
	})
}

func TestRuntimeSelection(t *testing.T) {
	timeA := time.Unix(9564, 0).UTC()
	timeB := timeA.Add(time.Minute)
	reports := []v1.Report{
		{
			StartTime: timeA,
			EndTime:   timeB,
			Host:      "host",
			Count:     2,
			Type:      "ProcessStart",
			Pod: v1.PodInfo{
				Name:          "drax",
				NameAggr:      "drax-*",
				Namespace:     "moonraker",
				ContainerName: "diamond",
			},
			File: v1.File{
				Path:     "/usr/sbin/runc",
				HostPath: "/run/docker/runtime-runc/moby/48f10a5eb9a245e6890433205053ba4e72c8e3bab5c13c2920dc32fadd7290cd/runc.rB3K51",
			},
			ProcessStart: v1.ProcessStart{
				Invocation: "runc --root /var/run/docker/runtime-runc/moby",
				Hashes: v1.ProcessHashes{
					MD5:    "",
					SHA1:   "",
					SHA256: "SHA256",
				},
			},
		},
		{
			StartTime: timeA,
			EndTime:   timeB,
			Host:      "host",
			Count:     10,
			Type:      "ProcessStart",
			Pod: v1.PodInfo{
				Name:          "goldfinger",
				NameAggr:      "goldfinger-*",
				Namespace:     "fortknox",
				ContainerName: "gold",
			},
			File: v1.File{
				Path:     "/usr/sbin/laser",
				HostPath: "/run/docker/runtime-runc/moby/48f10a5eb9a245e6890433205053ba4e72c8e3bab5c13c2920dc32fadd7290cd/laser.rB3K51",
			},
			ProcessStart: v1.ProcessStart{
				Invocation: "runc --root /var/run/docker/runtime-runc/laser",
				Hashes: v1.ProcessHashes{
					MD5:    "",
					SHA1:   "",
					SHA256: "Laser-SHA256",
				},
			},
		},
		{
			StartTime: timeA,
			EndTime:   timeB,
			Host:      "host",
			Count:     1,
			Type:      "ProcessStart",
			Pod: v1.PodInfo{
				Name:          "blofeld",
				NameAggr:      "blofeld-*",
				Namespace:     "spectre",
				ContainerName: "fur",
			},
			File: v1.File{
				Path:     "/usr/sbin/ski",
				HostPath: "/run/docker/runtime-runc/moby/48f10a5eb9a245e6890433205053ba4e72c8e3bab5c13c2920dc32fadd7290cd/ski.rB3K51",
			},
			ProcessStart: v1.ProcessStart{
				Invocation: "runc --root /var/run/docker/runtime-runc/ski",
				Hashes: v1.ProcessHashes{
					MD5:    "",
					SHA1:   "",
					SHA256: "Ski-SHA256",
				},
			},
		},
	}

	testSelection := func(t *testing.T, selector string, expectedReports []v1.Report) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Create the event in ES.
		resp, err := b.Create(ctx, clusterInfo, reports)
		require.NoError(t, err)
		require.Equal(t, 0, len(resp.Errors))
		require.Equal(t, len(reports), resp.Total)
		require.Equal(t, 0, resp.Failed)
		require.Equal(t, len(reports), resp.Succeeded)

		// Refresh the index.
		err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		r, e := b.List(ctx, clusterInfo, &v1.RuntimeReportParams{
			Selector: selector,
		})
		require.NoError(t, e)
		require.Equal(t, len(expectedReports), len(r.Items))
		for i := range expectedReports {
			item := r.Items[i]
			testutils.AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t, cluster1, &item)
			require.Equal(t, expectedReports[i], item.Report)
		}
	}

	tests := []struct {
		selector        string
		expectedReports []v1.Report
	}{
		{"'pod.name'=\"goldfinger\"", []v1.Report{reports[1]}},
		{"'pod.name' IN {\"goldfinger\",\"blofeld\"}", []v1.Report{reports[1], reports[2]}},
		{"count > 5", []v1.Report{reports[1]}},
		{"count <= 2", []v1.Report{reports[0], reports[2]}},
		{"type = FutureFeature", []v1.Report{}},
		{"type = ProcessStart", []v1.Report{reports[0], reports[1], reports[2]}},
		{"'pod.namespace'='moonraker'", []v1.Report{reports[0]}},
		{"'pod.name_aggr' != 'blofeld-*'", []v1.Report{reports[0], reports[1]}},
		{"'pod.container_name' NOTIN {gold}", []v1.Report{reports[0], reports[2]}},
		{"'pod.ready' = false", []v1.Report{reports[0], reports[1], reports[2]}},
		{"'pod.ready' = true", []v1.Report{}},
		{"'file.path' IN {'*laser*'}", []v1.Report{reports[1]}},
		{"'file.host_path' IN {'*laser*'}", []v1.Report{reports[1]}},
		{"'process_start.invocation' NOTIN {'*laser*'}", []v1.Report{reports[0], reports[2]}},
		{"'process_start.hashes.md5' != \"\"", []v1.Report{}},
		{"'process_start.hashes.sha256' IN {\"*Laser*\"}", []v1.Report{reports[1]}},
		{"host = host", []v1.Report{reports[0], reports[1], reports[2]}},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("TestReportSelection: %s", tt.selector)
		RunAllModes(t, name, func(t *testing.T) {
			testSelection(t, tt.selector, tt.expectedReports)
		})
	}
}

func TestRetrieveMostRecentRuntimeReports(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestRetrieveMostRecentRuntimeReports (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Tenant: tenant, Cluster: cluster1}

			now := time.Now().UTC()

			t1 := time.Unix(500, 0).UTC()
			t2 := time.Unix(400, 0).UTC()
			t3 := time.Unix(300, 0).UTC()

			l1 := v1.Report{
				StartTime: t1,
				EndTime:   t1.Add(time.Duration(5) * time.Second),
			}

			l2 := v1.Report{
				StartTime: t2,
				EndTime:   t2.Add(time.Duration(5) * time.Second),
			}

			_, err := migration.Create(ctx, clusterInfo, []v1.Report{l1, l2})
			require.NoError(t, err)

			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Query for logs
			params := v1.RuntimeReportParams{
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
			r, err := migration.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 2)
			lastGeneratedTime := r.Items[1].Report.GeneratedTime
			testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, cluster1, r)

			// Assert that the logs are returned in the correct order.
			require.Equal(t, l1, r.Items[0].Report)
			require.Equal(t, l2, r.Items[1].Report)

			l3 := v1.Report{
				StartTime: t3,
				EndTime:   t3.Add(time.Duration(5) * time.Second),
			}
			_, err = migration.Create(ctx, clusterInfo, []v1.Report{l3})
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

			r, err = migration.List(ctx, clusterInfo, &params)
			require.NoError(t, err)
			require.Len(t, r.Items, 1)
			testutils.AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t, cluster1, r)

			// Assert that the logs are returned in the correct order.
			require.Equal(t, l3, r.Items[0].Report)
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
			logs := []v1.Report{}
			for i := 1; i <= numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				log := v1.Report{
					StartTime: start,
					EndTime:   start.Add(time.Duration(5) * time.Second),
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
			allOpts := v1.RuntimeReportParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						Field: "generated_time",
						From:  testStart.Add(-5 * time.Second),
						To:    time.Now().Add(5 * time.Minute),
					},
				},
			}
			first, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, first.Items, numLogs)

			bulk, err := migration.Create(ctx, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, bulk.Errors)

			second, err := migration.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, second.Items, numLogs)

			for _, log := range first.Items {
				testutils.AssertGeneratedTimeAndReset[v1.Report](t, &log.Report)
			}
			for _, log := range second.Items {
				testutils.AssertGeneratedTimeAndReset[v1.Report](t, &log.Report)
			}

			require.Equal(t, first.Items, second.Items)

			// Refresh before cleaning up data
			err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

		})
	}
}
