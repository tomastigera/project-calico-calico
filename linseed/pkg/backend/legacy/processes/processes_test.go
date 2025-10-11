// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package processes_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/flows"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/processes"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

var (
	client      lmaelastic.Client
	cache       bapi.IndexInitializer
	pb          bapi.ProcessBackend
	flb         bapi.FlowLogBackend
	ctx         context.Context
	cluster1    string
	cluster2    string
	cluster3    string
	indexGetter bapi.Index
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
	cache = templates.NewCachedInitializer(client, 1, 0)

	// Create backends to use.
	if singleIndex {
		indexGetter = index.FlowLogIndex()
		pb = processes.NewSingleIndexBackend(client)
		flb = flows.NewSingleIndexFlowLogBackend(client, cache, 10000, false)
	} else {
		pb = processes.NewBackend(client)
		flb = flows.NewFlowLogBackend(client, cache, 10000, false)
		indexGetter = index.FlowLogMultiIndex
	}

	// Create a random cluster name for each test to make sure we don't
	// interfere between tests.
	cluster1 = testutils.RandomClusterName()
	cluster2 = testutils.RandomClusterName()
	cluster3 = testutils.RandomClusterName()

	// Set a timeout for each test.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)

	// Function contains teardown logic.
	return func() {
		// Cancel the context.
		cancel()

		// Clean up data from the test.
		for _, cluster := range []string{cluster1, cluster2, cluster3} {
			err = testutils.CleanupIndices(context.Background(), esClient, singleIndex, indexGetter, bapi.ClusterInfo{Cluster: cluster})
			require.NoError(t, err)
		}

		// Cancel logging
		logCancel()
	}
}

// TestListProcesses tests running a real elasticsearch query to list processes.
func TestListProcesses(t *testing.T) {
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestListProcesses (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
			cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
			cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

			// Put some data into ES so we can query it.
			// Build the same flow, reported by the source and the dest.
			bld := testutils.NewFlowLogBuilder()
			bld.WithType("wep").
				WithSourceNamespace("default").
				WithDestNamespace("kube-system").
				WithDestName("kube-dns-*").
				WithProtocol("udp").
				WithSourceName("my-deployment-*").
				WithSourceIP("192.168.1.1").
				WithRandomFlowStats().WithRandomPacketStats().
				WithReporter("src").WithAction("allow").
				WithProcessName("/bin/curl")
			srcLog, err := bld.Build()
			require.NoError(t, err)
			bld.WithReporter("dst")
			dstLog, err := bld.Build()
			require.NoError(t, err)

			// Creating the flow logs may fail due to conflicts with other tests modifying the same index.
			// Since go test runs packages in parallel, we need to retry a few times to avoid flakiness.
			// We could avoid this by creating a new ES instance per-test or per-package, but that would
			// slow down the test and use more resources. This is a reasonable compromise, and what clients will need to do anyway.
			for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
				attempts := 0
				response, err := flb.Create(ctx, clusterInfo, []v1.FlowLog{*srcLog, *dstLog})
				for err != nil && attempts < 5 {
					logrus.WithError(err).Info("[TEST] Retrying flow log creation due to error")
					attempts++
					response, err = flb.Create(ctx, clusterInfo, []v1.FlowLog{*srcLog, *dstLog})
				}
				require.NoError(t, err)
				require.Equal(t, []v1.BulkError(nil), response.Errors)
				require.Equal(t, 0, response.Failed)

				err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
				require.NoError(t, err)
			}

			// Set time range so that we capture all of the populated logs.
			opts := v1.ProcessParams{}
			opts.TimeRange = &lmav1.TimeRange{}
			opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
			opts.TimeRange.To = time.Now().Add(5 * time.Minute)

			t.Run("should query single cluster", func(t *testing.T) {
				clusterInfo := cluster1Info
				// Query for process info. There should be a single entry from the populated data.
				r, err := pb.List(ctx, clusterInfo, &opts)
				require.NoError(t, err)
				require.Len(t, r.Items, 1)
				require.Nil(t, r.AfterKey)
				require.Empty(t, err)

				// Assert that the process data is populated correctly.
				expected := v1.ProcessInfo{
					Cluster:  clusterInfo.Cluster,
					Name:     "/bin/curl",
					Endpoint: "my-deployment-*",
					Count:    1,
				}
				require.Equal(t, expected, r.Items[0])

				// Query for process info using a different tenant ID. There should be no results.
				otherInfo := bapi.ClusterInfo{Cluster: clusterInfo.Cluster, Tenant: "other-tenant"}
				r, err = pb.List(ctx, otherInfo, &opts)

				// The actual behavior here varies slightly between the single-index and multi-index due to
				// the way ES handles these requests. This is because for multi-index, the ES request targets
				// an index that doesn't exist. In single-index, the request targets an index that does exist but doesn't
				// match any documents.
				if indexGetter.IsSingleIndex() {
					require.NoError(t, err)
					require.Len(t, r.Items, 0)
				} else {
					require.Error(t, err)
					require.Nil(t, r)
				}
			})

			t.Run("should query multiple clusters", func(t *testing.T) {
				selectedClusters := []string{cluster2, cluster3}
				opts.SetClusters(selectedClusters)
				r, err := pb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, &opts)
				require.NoError(t, err)
				require.Len(t, r.Items, 2)
				for _, cluster := range selectedClusters {
					require.Truef(t, testutils.MatchIn(r.Items, testutils.ProcessInfoClusterEquals(cluster)), "cluster %s should be in the results", cluster)
				}
			})

			t.Run("should query all clusters", func(t *testing.T) {
				opts.SetAllClusters(true)
				r, err := pb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, &opts)
				require.NoError(t, err)
				for _, cluster := range []string{cluster1, cluster2, cluster3} {
					require.Truef(t, testutils.MatchIn(r.Items, testutils.ProcessInfoClusterEquals(cluster)), "cluster %s should be in the results", cluster)
				}
			})
		})
	}
}

//go:embed testdata/flow_search_response.json
var flowSearchResponse []byte

func TestParseESResponse(t *testing.T) {
	resp := elastic.SearchResult{}
	err := json.Unmarshal(flowSearchResponse, &resp)
	require.NoError(t, err)

	// Use the process backend to convert the ES results.
	converter := pb.(processes.BucketConverter)
	procs, err := converter.ConvertElasticResult(logrus.NewEntry(logrus.StandardLogger()), &resp)
	require.NoError(t, err)
	require.Len(t, procs, 9)

	// Sort the result slice so that test assertions aren't tied to conversion algorithm.
	sort.Slice(procs, func(i, j int) bool {
		return procs[i].Name < procs[j].Name
	})

	require.Equal(t, procs[0].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[0].Name, "/app/cartservice")
	require.Equal(t, procs[0].Endpoint, "cartservice-74f56fd4b-*")
	require.Equal(t, procs[0].Count, 3)
	require.Equal(t, procs[1].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[1].Name, "/src/checkoutservice")
	require.Equal(t, procs[1].Endpoint, "checkoutservice-69c8ff664b-*")
	require.Equal(t, procs[1].Count, 4)
	require.Equal(t, procs[2].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[2].Name, "/src/server")
	require.Equal(t, procs[2].Endpoint, "frontend-99684f7f8-*")
	require.Equal(t, procs[2].Count, 3)
	require.Equal(t, procs[3].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[3].Name, "/usr/local/bin/locust")
	require.Equal(t, procs[3].Endpoint, "loadgenerator-555fbdc87d-*")
	require.Equal(t, procs[3].Count, 1)
	require.Equal(t, procs[4].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[4].Name, "/usr/local/bin/python")
	require.Equal(t, procs[4].Endpoint, "loadgenerator-555fbdc87d-*")
	require.Equal(t, procs[4].Count, 2)
	require.Equal(t, procs[5].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[5].Name, "/usr/local/bin/python")
	require.Equal(t, procs[5].Endpoint, "recommendationservice-5f8c456796-*")
	require.Equal(t, procs[5].Count, 2)
	require.Equal(t, procs[6].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[6].Name, "/usr/local/openjdk-8/bin/java")
	require.Equal(t, procs[6].Endpoint, "adservice-77d5cd745d-*")
	require.Equal(t, procs[6].Count, 3)
	require.Equal(t, procs[7].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[7].Name, "python")
	require.Equal(t, procs[7].Endpoint, "recommendationservice-5f8c456796-*")
	require.Equal(t, procs[7].Count, 2)
	require.Equal(t, procs[8].Cluster, "cluster-ushdjisc")
	require.Equal(t, procs[8].Name, "wget")
	require.Equal(t, procs[8].Endpoint, "loadgenerator-555fbdc87d-*")
	require.Equal(t, procs[8].Count, 1)
}
