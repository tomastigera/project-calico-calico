// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package l7_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	kapiv1 "k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/l7"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

var (
	client      lmaelastic.Client
	cache       bapi.IndexInitializer
	b           bapi.L7FlowBackend
	lb          bapi.L7LogBackend
	migration   bapi.L7LogBackend
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
		indexGetter = index.L7LogIndex()
		b = l7.NewSingleIndexL7FlowBackend(client)
		lb = l7.NewSingleIndexL7LogBackend(client, cache, 10000, false)
		migration = l7.NewSingleIndexL7LogBackend(client, cache, 10000, true)
	} else {
		b = l7.NewL7FlowBackend(client)
		lb = l7.NewL7LogBackend(client, cache, 10000, false)
		migration = l7.NewL7LogBackend(client, cache, 10000, true)
		indexGetter = index.L7LogMultiIndex
	}

	// Create a random cluster name for each test to make sure we don't
	// interfere between tests.
	cluster1 = testutils.RandomClusterName()
	cluster2 = testutils.RandomClusterName()
	cluster3 = testutils.RandomClusterName()

	// Each test should take less than 5 seconds.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)

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

// TestL7FlowsMainline tests running a real elasticsearch query to list L7 flows.
func TestL7FlowsMainline(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{testutils.RandomTenantName(), ""} {
		name := fmt.Sprintf("TestListL7Flows (tenant=%s)", tenant)
		RunAllModes(t, name, func(t *testing.T) {
			cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
			cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
			cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

			// Put some data into ES so we can query it.
			expected1 := populateL7FlowData(t, ctx, client, cluster1Info, expectedL7Flow, l7Log)
			populateL7FlowData(t, ctx, client, cluster2Info, expectedL7Flow, l7Log)
			populateL7FlowData(t, ctx, client, cluster3Info, expectedL7Flow, l7Log)

			// Set time range so that we capture all of the populated flow logs.
			opts := v1.L7FlowParams{}
			opts.TimeRange = &lmav1.TimeRange{}
			opts.TimeRange.From = time.Now().Add(-5 * time.Second)
			opts.TimeRange.To = time.Now().Add(5 * time.Second)

			t.Run("should query single cluster", func(t *testing.T) {
				// Query for flows. There should be a single flow from the populated data.
				r, err := b.List(ctx, cluster1Info, &opts)
				require.NoError(t, err)
				require.Len(t, r.Items, 1)

				// Assert that the flow data is populated correctly.
				require.Equal(t, expected1, r.Items[0])
			})

			t.Run("should query multiple clusters", func(t *testing.T) {
				selectedClusters := []string{cluster2, cluster3}
				opts.SetClusters(selectedClusters)
				r, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &opts)
				require.NoError(t, err)
				require.Len(t, r.Items, 2)

				for _, cluster := range selectedClusters {
					require.Truef(t, testutils.MatchIn(r.Items, testutils.L7FlowClusterEquals(cluster)), "Expected cluster %s in result", cluster)
				}
			})

			t.Run("should query all clusters", func(t *testing.T) {
				opts.SetAllClusters(true)
				r, err := b.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &opts)
				require.NoError(t, err)
				for _, cluster := range []string{cluster1, cluster2, cluster3} {
					require.Truef(t, testutils.MatchIn(r.Items, testutils.L7FlowClusterEquals(cluster)), "Expected cluster %s in result", cluster)
				}
			})

			t.Run("other tenant", func(t *testing.T) {
				// Create some data for a different tenant.
				otherTenantInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: "suspicious-tenant"}
				otherL7Log := func(i int) v1.L7Log {
					// Modify the base log to make it unique so we can distinguish between the two logs and
					// thus check that the right data is returned for each call.
					l := l7Log(i)
					l.SourceType = "sus"
					return l
				}
				otherTenantExpected2 := populateL7FlowData(t, ctx, client, otherTenantInfo, expectedL7Flow, otherL7Log)
				otherTenantExpected2.Key.Source.Type = "sus"

				// Attempt to access using another tenant but with the same options as above. This should return that tenant's flow,
				// but other tenant's flow - even though the options otherwise match the data we inserted for the first tenant.
				r, err := b.List(ctx, otherTenantInfo, &opts)
				require.NoError(t, err)
				require.Len(t, r.Items, 1)
				require.Equal(t, otherTenantExpected2, r.Items[0])
				require.NotEqual(t, expected1, r.Items[0])
			})
		})
	}

	RunAllModes(t, "no cluster name given on request", func(t *testing.T) {
		// It should reject requests with no cluster name given.
		clusterInfo := bapi.ClusterInfo{}
		params := &v1.L7FlowParams{}
		results, err := b.List(ctx, clusterInfo, params)
		require.Error(t, err)
		require.Nil(t, results)
	})

	RunAllModes(t, "empty response code stored", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Put some data into ES so we can query it.
		expected := populateL7FlowData(t, ctx, client, clusterInfo, expectedL7FlowNoResponseCode, l7LogEmptyResponseCode)

		// Set time range so that we capture all of the populated flow logs.
		opts := v1.L7FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Second)
		opts.TimeRange.To = time.Now().Add(5 * time.Second)

		// Query for flows. There should be a single flow from the populated data.
		r, err := b.List(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 1)

		// Assert that the flow data is populated correctly.
		require.Equal(t, expected, r.Items[0])
	})
}

type (
	l7FlowGenerator func() v1.L7Flow
	l7LogGenerator  func(i int) v1.L7Log
)

// populateFlowData writes a series of flow logs to elasticsearch, and returns the L7 flow that we
// should expect to exist as a result. This can be used to assert round-tripping and aggregation against ES is working correctly.
func populateL7FlowData(t *testing.T, ctx context.Context, client lmaelastic.Client, clusterInfo bapi.ClusterInfo, flowGenerator l7FlowGenerator, generator l7LogGenerator) v1.L7Flow {
	// The expected flow log - we'll populate fields as we go.
	expected := flowGenerator()
	expected.Key.Cluster = clusterInfo.Cluster

	// Used to track the total DurationMean across all L7 logs we create.
	var durationMeanTotal int64 = 0

	numFlows := 10

	batch := []v1.L7Log{}
	for i := range numFlows {
		f := generator(i)

		// Increment fields on the expected flow based on the flow log that was
		// just added.
		expected.Stats.BytesIn += f.BytesIn
		expected.Stats.BytesOut += f.BytesOut
		expected.LogCount += f.Count
		durationMeanTotal += f.DurationMean

		// Add it to the batch.
		batch = append(batch, f)
	}

	// MinDuration is the smallest recorded value for DurationMean
	// amongst L7 logs used to generate this flow. Since DurationMean for each log
	// is calculated based on the loop variable, we know this must be 0.
	expected.Stats.MinDuration = 0

	// MaxDuration is the largest recorded value for DurationMax
	// amongst L7 logs used to generate this flow. DurationMax for each log
	// is calculated based on the loop variable.
	expected.Stats.MaxDuration = int64((numFlows - 1) * 2)

	// MeanDuration is the average value for DurationMean among L7 logs used to generate
	// this flow.
	expected.Stats.MeanDuration = durationMeanTotal / int64(numFlows)

	// Create the batch all at once.
	response, err := lb.Create(ctx, clusterInfo, batch)
	require.NoError(t, err)
	require.Equal(t, response.Failed, 0)

	// Refresh the index so that data is readily available for the test. Otherwise, we need to wait
	// for the refresh interval to occur.
	err = testutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
	require.NoError(t, err)

	return expected
}

func l7Log(i int) v1.L7Log {
	f := v1.L7Log{
		StartTime: time.Now().Unix(),
		EndTime:   time.Now().Unix(),

		ResponseCode: "200",
		URL:          "http://example.com",
		UserAgent:    "test-user",
		Method:       "GET",
		Latency:      5,

		SourceType:      "wep",
		SourceNamespace: "default",
		SourceNameAggr:  "my-deployment",
		SourcePortNum:   1234,

		DestType:             "wep",
		DestNamespace:        "kube-system",
		DestNameAggr:         "kube-dns-*",
		DestServiceNamespace: "kube-system",
		DestServiceName:      "kube-dns",
		DestServicePortName:  "dns",
		DestPortNum:          53,
		DestServicePort:      53,

		DurationMax:  int64(2 * i),
		DurationMean: int64(i),
		BytesIn:      64,
		BytesOut:     128,
		Count:        int64(i),
	}
	return f
}

func l7LogEmptyResponseCode(i int) v1.L7Log {
	f := l7Log(i)
	f.ResponseCode = ""
	return f
}

func expectedL7FlowNoResponseCode() v1.L7Flow {
	expected := v1.L7Flow{}
	expected.Key = v1.L7FlowKey{
		Protocol: "tcp",
		Source: v1.Endpoint{
			Namespace:      "default",
			Type:           "wep",
			AggregatedName: "my-deployment",
		},
		Destination: v1.Endpoint{
			Namespace:      "kube-system",
			Type:           "wep",
			AggregatedName: "kube-dns-*",
			Port:           53,
		},
		DestinationService: v1.ServicePort{
			Service: kapiv1.NamespacedName{
				Name:      "kube-dns",
				Namespace: "kube-system",
			},
			PortName: "dns",
			Port:     53,
		},
	}
	expected.Stats = &v1.L7Stats{}
	return expected
}

func expectedL7Flow() v1.L7Flow {
	expected := expectedL7FlowNoResponseCode()
	expected.Code = 200

	return expected
}
