// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package flows_test

import (
	"context"
	_ "embed"
	gojson "encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/flows"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	backendutils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

var (
	client      lmaelastic.Client
	cache       bapi.IndexInitializer
	fb          bapi.FlowBackend
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
		fb = flows.NewSingleIndexFlowBackend(client)
		flb = flows.NewSingleIndexFlowLogBackend(client, cache, 10000, false)
	} else {
		fb = flows.NewFlowBackend(client)
		flb = flows.NewFlowLogBackend(client, cache, 10000, false)
		indexGetter = index.FlowLogMultiIndex
	}

	// Create a random cluster name for each test to make sure we don't
	// interfere between tests.
	cluster1 = backendutils.RandomClusterName()
	cluster2 = backendutils.RandomClusterName()
	cluster3 = backendutils.RandomClusterName()

	// Set a timeout for each test.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)

	// Function contains teardown logic.
	return func() {
		// Cancel the context.
		cancel()

		// Cleanup any data that might left over from a previous run.
		for _, cluster := range []string{cluster1, cluster2, cluster3} {
			err = backendutils.CleanupIndices(context.Background(), esClient, singleIndex, indexGetter, bapi.ClusterInfo{Cluster: cluster})
		}
		require.NoError(t, err)

		// Cancel logging
		logCancel()
	}
}

// TestListFlows tests running a real elasticsearch query to list flows.
func TestListFlows(t *testing.T) {
	RunAllModes(t, "TestListFlows", func(t *testing.T) {
		cluster1Info := bapi.ClusterInfo{Cluster: cluster1}
		cluster2Info := bapi.ClusterInfo{Cluster: cluster2}
		cluster3Info := bapi.ClusterInfo{Cluster: cluster3}

		// Put some data into ES so we can query it.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none").
			WithPolicies("0|calico-system|np:calico-system/calico-system.apiserver-access|allow|1").
			WithEnforcedPolicies("0|calico-system|np:calico-system/calico-system.apiserver-access|allow|1").
			WithPendingPolicies("0|calico-system|np:calico-system/calico-system.apiserver-access|allow|1").
			WithTransitPolicies("0|calico-system|np:calico-system/calico-system.apiserver-access|allow|1").
			WithProcessName("/usr/bin/curl")
		expected1 := populateFlowData(t, ctx, bld.Copy(), client, cluster1Info)
		expected2 := populateFlowData(t, ctx, bld.Copy(), client, cluster2Info)
		expected3 := populateFlowData(t, ctx, bld.Copy(), client, cluster3Info)

		// Set time range so that we capture all of the populated flow logs.
		opts := v1.L3FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		t.Run("should query single cluster", func(t *testing.T) {
			// Query for flows. There should be a single flow from the populated data.
			r, err := fb.List(ctx, cluster1Info, &opts)
			require.NoError(t, err)
			require.Len(t, r.Items, 1)
			require.Nil(t, r.AfterKey)

			// Assert that the flow data is populated correctly.
			require.Equal(t, expected1, r.Items[0])
		})

		t.Run("should query all clusters", func(t *testing.T) {
			opts.SetAllClusters(true)
			r, err := fb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, &opts)
			require.NoError(t, err)
			require.Nil(t, r.AfterKey)
			require.Contains(t, r.Items, expected1)
			require.Contains(t, r.Items, expected2)
			require.Contains(t, r.Items, expected3)
		})

		t.Run("should query multiple clusters", func(t *testing.T) {
			opts.SetClusters([]string{cluster2, cluster3})
			r, err := fb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters}, &opts)
			require.NoError(t, err)
			require.Len(t, r.Items, 2)
			require.Nil(t, r.AfterKey)
			require.Contains(t, r.Items, expected2)
			require.Contains(t, r.Items, expected3)
		})
	})
}

// TestMultipleFlows tests that we return multiple flows properly.
func TestMultipleFlows(t *testing.T) {
	RunAllModes(t, "TestMultipleFlows", func(t *testing.T) {
		// Both flows use the same cluster information.
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Template for flow #1.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("34.15.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none")
		exp1 := populateFlowData(t, ctx, bld, client, clusterInfo)

		// Template for flow #2.
		bld2 := backendutils.NewFlowLogBuilder()
		bld2.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none")
		exp2 := populateFlowData(t, ctx, bld2, client, clusterInfo)

		// Set time range so that we capture all of the populated flow logs.
		opts := v1.L3FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		// Query for flows. There should be two flows from the populated data.
		r, err := fb.List(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)

		// Assert that the flow data is populated correctly.
		require.Equal(t, exp1, r.Items[1])
		require.Equal(t, exp2, r.Items[0])
	})
}

// TestSourceIPAndDestIPFlows tests that we return multiple flows properly with source IP and
// destination IP
func TestSourceIPAndDestIPFlows(t *testing.T) {
	RunAllModes(t, "TestMultipleFlows", func(t *testing.T) {
		// Both flows use the same cluster information.
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Flow logs batch #1.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("34.15.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none")
		_ = populateFlowData(t, ctx, bld, client, clusterInfo)

		// Flow logs batch #2.
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("192.168.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none")
		_ = populateFlowData(t, ctx, bld, client, clusterInfo)

		// Flow logs batch #3.
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.9").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("192.168.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none")
		_ = populateFlowData(t, ctx, bld, client, clusterInfo)

		// Build a flow log based on the 3 batches
		exp1 := bld.ExpectedFlow(t, clusterInfo)

		// Template for flow logs batch #4.
		bld2 := backendutils.NewFlowLogBuilder()
		bld2.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none")
		exp2 := populateFlowData(t, ctx, bld2, client, clusterInfo)

		// Set time range so that we capture all the populated flow logs.
		opts := v1.L3FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		// Query for flows. There should be two flows from the populated data.
		r, err := fb.List(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)

		fmt.Printf("exp1 item0: %t\n", reflect.DeepEqual(*exp1, r.Items[0]))
		fmt.Printf("exp1 item1: %t\n", reflect.DeepEqual(*exp1, r.Items[1]))
		fmt.Printf("exp2 item0: %t\n", reflect.DeepEqual(exp2, r.Items[0]))
		fmt.Printf("exp2 item1: %t\n", reflect.DeepEqual(exp2, r.Items[1]))
		// Assert that the flow data is populated correctly.
		require.Equal(t, exp2, r.Items[0])
		require.Equal(t, *exp1, r.Items[1])
	})
}

// TestFlowMultiplePolicies tests a flow that traverses multiple policies and ultimately
// hits the default profile allow rule.
func TestFlowMultiplePolicies(t *testing.T) {
	RunAllModes(t, "TestFlowMultiplePolicies", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Put some data into ES so we can query it.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("tcp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none").
			// Add in a couple of policies, as well as the default profile hit.
			WithPolicy("0|calico-system|kube-system/calico-system.cluster-dns|pass|1").
			WithPolicy("1|__PROFILE__|pro:kns.kube-system|allow|0").
			WithEnforcedPolicy("0|calico-system|kube-system/calico-system.cluster-dns|pass|1").
			WithEnforcedPolicy("1|__PROFILE__|pro:kns.kube-system|allow|0").
			WithPendingPolicy("0|calico-system|kube-system/calico-system.cluster-dns|pass|1").
			WithPendingPolicy("1|__PROFILE__|pro:kns.kube-system|allow|0").
			WithTransitPolicy("0|calico-system|kube-system/calico-system.cluster-dns|pass|1").
			WithTransitPolicy("1|__PROFILE__|pro:kns.kube-system|allow|0")

		expected := populateFlowData(t, ctx, bld, client, clusterInfo)

		// Add in the expected policies.
		expected.Policies = []v1.Policy{
			{
				Tier:      "calico-system",
				Kind:      "NetworkPolicy",
				Name:      "calico-system.cluster-dns",
				Namespace: "kube-system",
				Action:    "pass",
				Count:     expected.LogStats.FlowLogCount,
				RuleID:    testutils.IntPtr(1),
			},
			{
				Tier:      "__PROFILE__",
				Kind:      "Profile",
				Name:      "kns.kube-system",
				Namespace: "",
				Action:    "allow",
				Count:     expected.LogStats.FlowLogCount,
				RuleID:    testutils.IntPtr(0),
				IsProfile: true,
			},
		}

		// Set time range so that we capture all of the populated flow logs.
		opts := v1.L3FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		// Query for flows. There should be a single flow from the populated data.
		r, err := fb.List(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 1)
		require.Nil(t, r.AfterKey)

		// Assert that the flow data is populated correctly.
		require.Equal(t, expected, r.Items[0])
	})
}

func TestFlowFiltering(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.L3FlowParams

		// Configuration for which flows are expected to match.
		ExpectFlow1 bool
		ExpectFlow2 bool

		// Number of logs to create
		NumLogs int

		// Whether to perform an equality comparison on the returned
		// flows. Can be useful for tests where stats differ.
		SkipComparison bool
	}

	numExpected := func(tc testCase) int {
		num := 0
		if tc.ExpectFlow1 {
			num++
		}
		if tc.ExpectFlow2 {
			num++
		}
		return num
	}

	testcases := []testCase{
		{
			Name: "should query a flow based on source type",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				SourceTypes: []v1.EndpointType{v1.WEP},
			},
			ExpectFlow1: true,
			ExpectFlow2: false, // Flow 2 is type hep, so won't match.
		},
		{
			Name: "should query a flow based on multiple destination types",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				SourceTypes: []v1.EndpointType{v1.WEP, v1.HEP},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on destination type",
			Params: v1.L3FlowParams{
				QueryParams:      v1.QueryParams{},
				DestinationTypes: []v1.EndpointType{v1.WEP},
			},
			ExpectFlow1: true,
			ExpectFlow2: false, // Flow 2 is type hep, so won't match.
		},
		{
			Name: "should query a flow based on multiple destination types",
			Params: v1.L3FlowParams{
				QueryParams:      v1.QueryParams{},
				DestinationTypes: []v1.EndpointType{v1.WEP, v1.HEP},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on source namespace",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default"},
					},
				},
			},
			ExpectFlow1: false, // Flow 1 has source namespace tigera-operator
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on multiple source namespaces",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default", "tigera-operator"},
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on destination namespace",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeDest,
						Namespaces: []string{"kube-system"},
					},
				},
			},
			ExpectFlow1: false, // Flow 1 has dest namespace openshift-system
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on multiple destination namespace",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeDest,
						Namespaces: []string{"kube-system", "openshift-dns"},
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on namespace MatchTypeAny",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeAny,
						Namespaces: []string{"kube-system"},
					},
				},
			},
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on source label equal selector",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				SourceSelectors: []v1.LabelSelector{
					{
						Key:      "bread",
						Operator: "=",
						Values:   []string{"rye"},
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false, // Flow 2 doesn't have the label
		},
		{
			Name: "should query a flow based on dest label equal selector",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				DestinationSelectors: []v1.LabelSelector{
					{
						Key:      "dest_iteration",
						Operator: "=",
						Values:   []string{"0"},
					},
				},
			},
			// Both flows have this label set on destination.
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on dest label selector matching none",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				DestinationSelectors: []v1.LabelSelector{
					{
						Key:      "cranberry",
						Operator: "=",
						Values:   []string{"sauce"},
					},
				},
			},
			// neither flow has this label set on destination.
			ExpectFlow1: false,
			ExpectFlow2: false,
		},
		{
			Name: "should query a flow based on multiple source labels",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				SourceSelectors: []v1.LabelSelector{
					{
						Key:      "bread",
						Operator: "=",
						Values:   []string{"rye"},
					},
					{
						Key:      "cheese",
						Operator: "=",
						Values:   []string{"cheddar"},
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false, // Missing both labels
		},
		{
			Name: "should query a flow based on multiple destination values for a single label",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				DestinationSelectors: []v1.LabelSelector{
					{
						Key:      "dest_iteration",
						Operator: "=",
						Values:   []string{"0", "1"},
					},
				},
			},

			// Both have this label.
			ExpectFlow1: true,
			ExpectFlow2: true,
			NumLogs:     2,
		},
		{
			Name: "should query a flow based on multiple destination values for a single label not comprehensive",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				DestinationSelectors: []v1.LabelSelector{
					{
						Key:      "dest_iteration",
						Operator: "=",
						Values:   []string{"0", "1"},
					},
				},
			},

			// Both have this label.
			ExpectFlow1: true,
			ExpectFlow2: true,
			NumLogs:     4,

			// Skip comparison on this one, since the returned flows don't match the expected ones
			// due to the filtering and the simplicity of our test modeling of flow logs.
			SkipComparison: true,
		},
		{
			Name: "should query a flow based on action",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				Actions:     []v1.FlowAction{v1.FlowActionAllow},
			},

			ExpectFlow1: true, // Only the first flow allows.
			ExpectFlow2: false,
		},
		{
			Name: "should query a flow based on multiple actions",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				Actions:     []v1.FlowAction{v1.FlowActionAllow, v1.FlowActionDeny},
			},

			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on source name aggr",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NameAggrMatches: []v1.NameMatch{
					{
						Type:  v1.MatchTypeSource,
						Names: []string{"tigera-operator-*"},
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query a flow based on dest name aggr",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NameAggrMatches: []v1.NameMatch{
					{
						Type:  v1.MatchTypeDest,
						Names: []string{"kube-dns-*"},
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query a flow based on any name aggr",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NameAggrMatches: []v1.NameMatch{
					{
						Type:  v1.MatchTypeAny,
						Names: []string{"kube-dns-*"},
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on unprotected flows",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows in all namespaces.
						Tier:   "__PROFILE__",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on unprotected flows within a namespace",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeAny,
						Namespaces: []string{"openshift-dns"},
					},
				},
				PolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows from the openshift-dns namespace.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on a specific policy hit tier",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},

			// Both flows have a policy hit in this tier.
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit tier and action",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier:   "default",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			// Both flows have a policy hit in this tier, but only the second
			// is allowed by the tier.
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name and namespace",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Name:      testutils.StringPtr("calico-system.cluster-dns"),
						Namespace: testutils.StringPtr("kube-system"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name - match both global and namespace policies when both tier and namespace are not provided",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Name: testutils.StringPtr("calico-system.cluster-dns"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			// This test should match both flows, but does so by fully-specifying all
			// query parameters.
			Name: "should query both flows with a complex multi-part query",
			Params: v1.L3FlowParams{
				QueryParams:      v1.QueryParams{},
				Actions:          []v1.FlowAction{v1.FlowActionAllow, v1.FlowActionDeny},
				SourceTypes:      []v1.EndpointType{v1.WEP, v1.HEP},
				DestinationTypes: []v1.EndpointType{v1.WEP, v1.HEP},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeDest,
						Namespaces: []string{"kube-system", "openshift-dns"},
					},
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default", "tigera-operator"},
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			// This test uses a complex query that ultimately only matches on of the flows
			// beacause it doesn't include flow1's destination namespace.
			Name: "should query a flow with a complex multi-part query",
			Params: v1.L3FlowParams{
				QueryParams:      v1.QueryParams{},
				Actions:          []v1.FlowAction{v1.FlowActionAllow, v1.FlowActionDeny},
				SourceTypes:      []v1.EndpointType{v1.WEP, v1.HEP},
				DestinationTypes: []v1.EndpointType{v1.WEP, v1.HEP},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeDest,
						Namespaces: []string{"openshift-dns"},
					},
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default", "tigera-operator"},
					},
				},
				PolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with a kubernetes policy hit",
			Params: v1.L3FlowParams{
				PolicyMatches: []v1.PolicyMatch{
					{
						Type:      "knp",
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with a staged policy hit",
			Params: v1.L3FlowParams{
				PolicyMatches: []v1.PolicyMatch{
					{
						Staged: ptr.To(true),
						Tier:   "calico-system",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with namespaced policy hit",
			Params: v1.L3FlowParams{
				PolicyMatches: []v1.PolicyMatch{
					{
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with global policy hit",
			Params: v1.L3FlowParams{
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier: "default",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should return flows with a global policy hit",
			Params: v1.L3FlowParams{
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should return flows with a global policy hit in the enforced policies",
			Params: v1.L3FlowParams{
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},
			ExpectFlow1: false,
			ExpectFlow2: true,
		},

		{
			Name: "should query based on unprotected flows in the enforced policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows in all namespaces.
						Tier:   "__PROFILE__",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on unprotected flows within a namespace in the enforced policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeAny,
						Namespaces: []string{"openshift-dns"},
					},
				},
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows from the openshift-dns namespace.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on a specific policy hit tier in the enforced policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},

			// Only flow 2 has a policy hit in this tier.
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit tier and action in the enforced policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Tier:   "default",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			// Both flows have a policy hit in this tier, but only the second
			// is allowed by the tier.
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name and namespace in the enforced policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Name:      testutils.StringPtr("calico-system.cluster-dns"),
						Namespace: testutils.StringPtr("kube-system"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name - match both global and namespace policies when both tier and namespace are not provided in the enforced policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Name: testutils.StringPtr("calico-system.cluster-dns"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			// This test uses a complex query that ultimately only matches on of the flows
			// beacause it doesn't include flow1's destination namespace.
			Name: "should query a flow with a complex multi-part query with enforced policies",
			Params: v1.L3FlowParams{
				QueryParams:      v1.QueryParams{},
				Actions:          []v1.FlowAction{v1.FlowActionAllow, v1.FlowActionDeny},
				SourceTypes:      []v1.EndpointType{v1.WEP, v1.HEP},
				DestinationTypes: []v1.EndpointType{v1.WEP, v1.HEP},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeDest,
						Namespaces: []string{"openshift-dns"},
					},
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default", "tigera-operator"},
					},
				},
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with a kubernetes policy hit in the enforced policies",
			Params: v1.L3FlowParams{
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Type:      "knp",
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should not return flows with a staged policy hit in the enforced policies",
			Params: v1.L3FlowParams{
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Staged: ptr.To(true),
						Tier:   "calico-system",
					},
				},
			},
			ExpectFlow1: false,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with namespaced policy hit in enforced policies",
			Params: v1.L3FlowParams{
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with global policy hit in enforced policies",
			Params: v1.L3FlowParams{
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "default",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should return flows with a global policy hit in enforced policies",
			Params: v1.L3FlowParams{
				EnforcedPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on unprotected flows from pending policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows in all namespaces.
						Tier:   "__PROFILE__",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on unprotected flows within a namespace and pending policies ",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeAny,
						Namespaces: []string{"openshift-dns"},
					},
				},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows from the openshift-dns namespace.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on a specific policy hit tier in pending policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},

			// Both flows have a policy hit in this tier.
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit tier and action in pending policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Tier:   "default",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			// Both flows have a policy hit in this tier, but only the second
			// is allowed by the tier.
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name and namespace in pending policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Name:      testutils.StringPtr("calico-system.cluster-dns"),
						Namespace: testutils.StringPtr("kube-system"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name in pending policies - match both global and namespace policies when both tier and namespace are not provided",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Name: testutils.StringPtr("calico-system.cluster-dns"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			// This test uses a complex query that ultimately only matches on of the flows
			// beacause it doesn't include flow1's destination namespace.
			Name: "should query a flow with a complex multi-part query and pending policy match",
			Params: v1.L3FlowParams{
				QueryParams:      v1.QueryParams{},
				Actions:          []v1.FlowAction{v1.FlowActionAllow, v1.FlowActionDeny},
				SourceTypes:      []v1.EndpointType{v1.WEP, v1.HEP},
				DestinationTypes: []v1.EndpointType{v1.WEP, v1.HEP},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeDest,
						Namespaces: []string{"openshift-dns"},
					},
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default", "tigera-operator"},
					},
				},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with a kubernetes policy hit in pending policies",
			Params: v1.L3FlowParams{
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Type:      "knp",
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with a staged policy hit in pending policies",
			Params: v1.L3FlowParams{
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Staged: ptr.To(true),
						Tier:   "calico-system",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with namespaced policy hit in pending policies",
			Params: v1.L3FlowParams{
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with global policy hit in pending policies",
			Params: v1.L3FlowParams{
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "default",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should return flows with a global policy hit in pending policies",
			Params: v1.L3FlowParams{
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on unprotected flows from transit policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows in all namespaces.
						Tier:   "__PROFILE__",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on unprotected flows within a namespace and transit policies ",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeAny,
						Namespaces: []string{"openshift-dns"},
					},
				},
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows from the openshift-dns namespace.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query based on a specific policy hit tier in transit policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},

			// Both flows have a policy hit in this tier.
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit tier and action in transit policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Tier:   "default",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			// Both flows have a policy hit in this tier, but only the second
			// is allowed by the tier.
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name and namespace in transit policies",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Name:      testutils.StringPtr("calico-system.cluster-dns"),
						Namespace: testutils.StringPtr("kube-system"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should query based on a specific policy hit name in transit policies - match both global and namespace policies when both tier and namespace are not provided",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Name: testutils.StringPtr("calico-system.cluster-dns"),
					},
				},
			},

			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			// This test uses a complex query that ultimately only matches on of the flows
			// beacause it doesn't include flow1's destination namespace.
			Name: "should query a flow with a complex multi-part query and transit policy match",
			Params: v1.L3FlowParams{
				QueryParams:      v1.QueryParams{},
				Actions:          []v1.FlowAction{v1.FlowActionAllow, v1.FlowActionDeny},
				SourceTypes:      []v1.EndpointType{v1.WEP, v1.HEP},
				DestinationTypes: []v1.EndpointType{v1.WEP, v1.HEP},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeDest,
						Namespaces: []string{"openshift-dns"},
					},
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default", "tigera-operator"},
					},
				},
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit.
						Tier:   "__PROFILE__",
						Name:   testutils.StringPtr("kns.openshift-dns"),
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},

			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with a kubernetes policy hit in transit policies",
			Params: v1.L3FlowParams{
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Type:      "knp",
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should not return flows with a staged k8s policy hit in transit policies",
			Params: v1.L3FlowParams{
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Staged:    ptr.To(true),
						Type:      "knp",
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
		{
			Name: "should return flows with a staged policy hit in transit policies",
			Params: v1.L3FlowParams{
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Staged: ptr.To(true),
						Tier:   "calico-system",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with namespaced policy hit in transit policies",
			Params: v1.L3FlowParams{
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Namespace: testutils.StringPtr("default"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with global policy hit in transit policies",
			Params: v1.L3FlowParams{
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "default",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should return flows with a global policy hit in transit policies",
			Params: v1.L3FlowParams{
				TransitPolicyMatches: []v1.PolicyMatch{
					{
						Tier: "calico-system",
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: true,
		},
		{
			Name: "should return flows with an admin network policy hit",
			Params: v1.L3FlowParams{
				PolicyMatches: []v1.PolicyMatch{
					{
						Type: v1.KANP,
						Name: testutils.StringPtr("test-kanp"),
					},
				},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should return flows with a baseline admin network policy hit",
			Params: v1.L3FlowParams{
				PolicyMatches: []v1.PolicyMatch{
					{
						Type: v1.KBANP,
						Name: testutils.StringPtr("test-kbanp"),
					},
				},
			},
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
	}

	for _, testcase := range testcases {
		// Each testcase creates multiple flows, and then uses
		// different filtering parameters provided in the L3FlowParams
		// to query one or more flows.
		RunAllModes(t, testcase.Name, func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

			// Set the time range for the test. We set this per-test
			// so that the time range captures the windows that the logs
			// are created in.
			tr := &lmav1.TimeRange{}
			tr.From = time.Now().Add(-5 * time.Minute)
			tr.To = time.Now().Add(5 * time.Minute)
			testcase.Params.TimeRange = tr

			numLogs := testcase.NumLogs
			if numLogs == 0 {
				numLogs = 1
			}

			// Template for flow #1.
			bld := backendutils.NewFlowLogBuilder()
			bld.WithType("wep").
				WithSourceNamespace("tigera-operator").
				WithDestNamespace("openshift-dns").
				WithDestName("openshift-dns-*").
				WithDestIP("10.0.0.10").
				WithDestService("openshift-dns", 53).
				WithDestPort(1053).
				WithSourcePort(1010).
				WithProtocol("udp").
				WithSourceName("tigera-operator-*").
				WithSourceIP("34.15.66.3").
				WithRandomFlowStats().WithRandomPacketStats().
				WithReporter("src,fwd").WithAction("allow").
				WithSourceLabels("bread=rye", "cheese=cheddar", "wine=none").
				// Pass followed by a profile allow.
				WithPolicy("0|calico-system|sgnp:cluster-dns|pass|1").
				WithPolicy("1|custom-tier|np:default/custom-tier.test-policy|pass|2").
				WithPolicy("2|default|knp:default/test-k8s-policy|pass|2").
				WithPolicy("3|default|gnp:default.test-global-policy|pass|1").
				WithPolicy("4|__PROFILE__|pro:kns.openshift-dns|allow|0").
				WithPolicy("5|adminnetworkpolicy|kanp:test-kanp|pass|1").
				WithEnforcedPolicy("0|custom-tier|np:default/custom-tier.test-policy|pass|2").
				WithEnforcedPolicy("1|default|knp:default/test-k8s-policy|pass|2").
				WithEnforcedPolicy("2|default|gnp:default.test-global-policy|pass|1").
				WithEnforcedPolicy("3|__PROFILE__|pro:kns.openshift-dns|allow|0").
				WithEnforcedPolicy("4|adminnetworkpolicy|kanp:test-kanp|pass|1").
				WithPendingPolicy("0|calico-system|sgnp:cluster-dns|pass|1").
				WithPendingPolicy("1|custom-tier|np:default/custom-tier.test-policy|pass|2").
				WithPendingPolicy("2|default|knp:default/test-k8s-policy|pass|2").
				WithPendingPolicy("3|default|gnp:default.test-global-policy|pass|1").
				WithPendingPolicy("4|__PROFILE__|pro:kns.openshift-dns|allow|0").
				WithPendingPolicy("5|adminnetworkpolicy|kanp:test-kanp|pass|1").
				WithTransitPolicy("0|calico-system|sgnp:cluster-dns|pass|1").
				WithTransitPolicy("1|custom-tier|np:default/custom-tier.test-policy|pass|2").
				WithTransitPolicy("2|default|knp:default/test-k8s-policy|pass|2").
				WithTransitPolicy("3|default|gnp:default.test-global-policy|pass|1").
				WithTransitPolicy("4|__PROFILE__|pro:kns.openshift-dns|allow|0").
				WithTransitPolicy("5|adminnetworkpolicy|kanp:test-kanp|pass|1").
				WithDestDomains("www.tigera.io", "www.calico.com", "www.kubernetes.io", "www.docker.com")
			exp1 := populateFlowDataN(t, ctx, bld, client, clusterInfo, numLogs)

			// Template for flow #2.
			bld2 := backendutils.NewFlowLogBuilder()
			bld2.WithType("hep").
				WithSourceNamespace("default").
				WithDestNamespace("kube-system").
				WithDestName("kube-dns-*").
				WithDestIP("10.0.0.10").
				WithDestService("kube-dns", 53).
				WithDestPort(53).
				WithSourcePort(5656).
				WithProtocol("udp").
				WithSourceName("my-deployment-*").
				WithSourceIP("192.168.1.1").
				WithRandomFlowStats().WithRandomPacketStats().
				WithReporter("src,fwd").WithAction("deny").
				WithSourceLabels("cheese=brie").
				// Explicit allow.
				WithPolicy("0|calico-system|gnp:calico-system.do-nothing|pass|1").
				WithPolicy("1|calico-system|np:kube-system/calico-system.cluster-dns|pass|1").
				WithPolicy("2|calico-system|gnp:calico-system.cluster-dns|pass|1").
				WithPolicy("3|custom-tier|gnp:custom-tier.cluster-dns|pass|1").
				WithPolicy("4|default|np:test-namespace/default.cluster-dns|pass|1").
				WithPolicy("5|default|gnp:default.cluster-dns|allow|1").
				WithPolicy("6|baselineadminnetworkpolicy|kbanp:test-kbanp|pass|1").
				WithPolicy("7|default|sknp:default/test-sk8s-policy|deny|2").
				WithEnforcedPolicy("0|calico-system|gnp:calico-system.do-nothing|pass|1").
				WithEnforcedPolicy("1|calico-system|np:kube-system/calico-system.cluster-dns|pass|1").
				WithEnforcedPolicy("2|calico-system|gnp:calico-system.cluster-dns|pass|1").
				WithEnforcedPolicy("3|custom-tier|gnp:custom-tier.cluster-dns|pass|1").
				WithEnforcedPolicy("4|default|np:test-namespace/default.cluster-dns|pass|1").
				WithEnforcedPolicy("5|default|gnp:default.cluster-dns|allow|1").
				WithEnforcedPolicy("6|baselineadminnetworkpolicy|kbanp:test-kbanp|pass|1").
				WithEnforcedPolicy("7|default|sknp:default/test-sk8s-policy|deny|2").
				WithPendingPolicy("0|calico-system|gnp:calico-system.do-nothing|pass|1").
				WithPendingPolicy("1|calico-system|np:kube-system/calico-system.cluster-dns|pass|1").
				WithPendingPolicy("2|calico-system|gnp:calico-system.cluster-dns|pass|1").
				WithPendingPolicy("3|custom-tier|gnp:custom-tier.cluster-dns|pass|1").
				WithPendingPolicy("4|default|np:test-namespace/default.cluster-dns|pass|1").
				WithPendingPolicy("5|default|gnp:default.cluster-dns|allow|1").
				WithPendingPolicy("6|baselineadminnetworkpolicy|kbanp:test-kbanp|pass|1").
				WithPendingPolicy("7|default|sknp:default/test-sk8s-policy|deny|2").
				WithTransitPolicy("0|calico-system|gnp:calico-system.do-nothing|pass|1").
				WithTransitPolicy("1|calico-system|np:kube-system/calico-system.cluster-dns|pass|1").
				WithTransitPolicy("2|calico-system|gnp:calico-system.cluster-dns|pass|1").
				WithTransitPolicy("3|custom-tier|gnp:custom-tier.cluster-dns|pass|1").
				WithTransitPolicy("4|default|np:test-namespace/default.cluster-dns|pass|1").
				WithTransitPolicy("5|default|gnp:default.cluster-dns|allow|1").
				WithTransitPolicy("6|baselineadminnetworkpolicy|kbanp:test-kbanp|pass|1").
				WithTransitPolicy("7|default|sknp:default/test-sk8s-policy|deny|2").
				WithDestDomains("www.tigera.io", "www.calico.com", "www.kubernetes.io", "www.docker.com")

			exp2 := populateFlowDataN(t, ctx, bld2, client, clusterInfo, numLogs)

			// Query for flows.
			r, err := fb.List(ctx, clusterInfo, &testcase.Params)

			require.NoError(t, err)
			require.Len(t, r.Items, numExpected(testcase))
			require.Nil(t, r.AfterKey)

			if testcase.SkipComparison {
				return
			}

			// Assert that the correct flows are returned.
			if testcase.ExpectFlow1 {
				require.Contains(t, r.Items, exp1, msg(r.Items, exp1))
			}
			if testcase.ExpectFlow2 {
				require.Contains(t, r.Items, exp2, msg(r.Items, exp2))
			}
		})
	}
}

// TestMixedModernLegacyFlows tests that when both modern and legacy policy strings
// are present in flows, that they are both properly interpreted when querying flows. It creates two flow logs -
// one with modern policy strings and one with the equivalent legacy policy strings - and then makes a Linseed query,
// expecting that both logs are aggregated into a single flow in the response.
func TestMixedModernLegacyFlows(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.L3FlowParams
	}

	testcases := []testCase{
		{
			Name: "should query based on unprotected flows",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						// Match the first flow's profile hit. This match returns all "unprotected"
						// flows in all namespaces.
						Tier:   "__PROFILE__",
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},
		},
		{
			Name: "should query based on a specific policy hit tier",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier: "tier",
					},
				},
			},
		},
		{
			Name: "should query based on a staged global network policy",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier:   "calico-system",
						Staged: ptr.To(true),
					},
				},
			},
		},
		{
			Name: "should query based on a namespaced staged network policy",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Namespace: testutils.StringPtr("namespace"),
						Staged:    ptr.To(true),
						Tier:      "tier",
					},
				},
			},
		},
		{
			Name: "should query based on a staged network policy name",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Name:   testutils.StringPtr("calico-system.staged-cluster-dns"),
						Staged: ptr.To(true),
					},
				},
			},
		},
		{
			Name: "should query based on a network policy name",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Name:      testutils.StringPtr("tier.cluster-dns"),
						Namespace: testutils.StringPtr("namespace"),
					},
				},
			},
		},
	}

	for _, testcase := range testcases {
		// Each testcase creates multiple flows, and then uses
		// different filtering parameters provided in the L3FlowParams
		// to query one or more flows.
		RunAllModes(t, testcase.Name, func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

			// Set the time range for the test. We set this per-test
			// so that the time range captures the windows that the logs
			// are created in.
			tr := &lmav1.TimeRange{}
			tr.From = time.Now().Add(-5 * time.Minute)
			tr.To = time.Now().Add(5 * time.Minute)
			testcase.Params.TimeRange = tr

			// Policy mappings, mapping modern policy strings to their legacy equivalents.
			pols := map[string]string{
				// GlobalNetworkPolicy
				"0|calico-system|gnp:calico-system.cluster-dns|pass|1": "0|calico-system|calico-system.cluster-dns|pass|1",

				// NetworkPolicy
				"1|tier|np:namespace/tier.cluster-dns|pass|1": "1|tier|namespace/tier.cluster-dns|pass|1",

				// StagedGlobalNetworkPolicy
				"2|calico-system|sgnp:calico-system.staged-cluster-dns|pass|1": "2|calico-system|calico-system.staged:staged-cluster-dns|pass|1",

				// StagedNetworkPolicy
				"3|tier|snp:namespace/tier.staged-cluster-dns|pass|1": "3|tier|namespace/tier.staged:staged-cluster-dns|pass|1",

				// Profile
				"4|__PROFILE__|pro:kns.openshift-dns|allow|0": "4|__PROFILE__|__PROFILE__.kns.openshift-dns|allow|0",
			}

			// Template for flow #1.
			modernBld := backendutils.NewFlowLogBuilder()
			modernBld.WithRandomFlowStats().WithRandomPacketStats().WithDestPort(80)
			legacyBld := backendutils.NewFlowLogBuilder()
			legacyBld.WithRandomFlowStats().WithRandomPacketStats().WithDestPort(80)

			for modern, legacy := range pols {
				modernBld.WithPolicy(modern)
				legacyBld.WithPolicy(legacy)
			}

			exp1 := populateFlowDataN(t, ctx, modernBld, client, clusterInfo, 1)
			exp2 := populateFlowDataN(t, ctx, legacyBld, client, clusterInfo, 1)

			// Query for flows.
			r, err := fb.List(ctx, clusterInfo, &testcase.Params)

			// We expect a single aggregated flow to be returned.
			require.NoError(t, err)
			require.Len(t, r.Items, 1)
			require.Nil(t, r.AfterKey)

			// Assert that the stats from both flows are present in the single returned flow.
			// Both flows should be identical except for their stats, which should be summed.
			got := r.Items[0]

			require.Equal(t, exp1.TrafficStats.PacketsIn+exp2.TrafficStats.PacketsIn, got.TrafficStats.PacketsIn)
			require.Equal(t, exp1.TrafficStats.PacketsOut+exp2.TrafficStats.PacketsOut, got.TrafficStats.PacketsOut)
			require.Equal(t, exp1.TrafficStats.BytesIn+exp2.TrafficStats.BytesIn, got.TrafficStats.BytesIn)
			require.Equal(t, exp1.TrafficStats.BytesOut+exp2.TrafficStats.BytesOut, got.TrafficStats.BytesOut)

			// The policies should match the modern flow's policies.
			require.Equal(t, exp1.Policies, got.Policies)
		})
	}
}

func msg(got []v1.L3Flow, exp v1.L3Flow) string {
	expJSON, _ := gojson.MarshalIndent(exp, "", "  ")
	gotJSON, _ := gojson.MarshalIndent(got, "", "  ")
	return fmt.Sprintf("expected flow:\n%s\ngot:\n%s\n\nFull Exp Structure:\n%#v\n\nFull Got Structure:\n%#v", expJSON, gotJSON, exp, got)
}

// TestPagination tests that we return multiple flows properly using pagination.
func TestPagination(t *testing.T) {
	RunAllModes(t, "TestPagination", func(t *testing.T) {
		// Both flows use the same cluster information.
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		// Template for flow #1.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("34.15.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none").
			WithDestDomains("www.tigera.io", "www.calico.com", "www.kubernetes.io", "www.docker.com")
		exp1 := populateFlowData(t, ctx, bld, client, clusterInfo)

		// Template for flow #2.
		bld2 := backendutils.NewFlowLogBuilder()
		bld2.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none").
			WithDestDomains("www.tigera.io", "www.calico.com", "www.kubernetes.io", "www.docker.com")
		exp2 := populateFlowData(t, ctx, bld2, client, clusterInfo)

		// Set time range so that we capture all of the populated flow logs.
		opts := v1.L3FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		// Also set a max results of 1, so that we only get one flow at a time.
		opts.MaxPageSize = 1

		// Query for flows. There should be a single flow from the populated data.
		r, err := fb.List(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 1)
		require.NotNil(t, r.AfterKey)
		require.Equal(t, exp2, r.Items[0])

		// Now, send another request. This time, passing in the pagination key
		// returned from the first. We should get the second flow.
		opts.AfterKey = r.AfterKey
		r, err = fb.List(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 1)
		require.NotNil(t, r.AfterKey)
		require.Equal(t, exp1, r.Items[0])
	})
}

// Definitions for search results to be used in the tests below.

//go:embed testdata/elastic_valid_flow.json
var validSingleFlow []byte

// Test the handling of various responses from elastic. This suite of tests uses a mock http server
// to return custom responses from elastic without the need for running a real elastic server.
// This can be useful for simulating strange or malformed responses from Elasticsearch.
func TestElasticResponses(t *testing.T) {
	// Set elasticResponse in each test to mock out a given response from Elastic.
	var server *httptest.Server
	var ctx context.Context
	var opts v1.L3FlowParams
	var clusterInfo bapi.ClusterInfo

	// setupAndTeardown initializes and tears down each test.
	setupAndTeardown := func(t *testing.T, elasticResponse []byte) func() {
		// Hook logrus into testing.T
		config.ConfigureLogging("DEBUG")
		logCancel := logutils.RedirectLogrusToTestingT(t)

		// Create a mock server to return elastic responses.
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, err := w.Write(elasticResponse)
			require.NoError(t, err)
		}))

		// Configure the elastic client to use the URL of our test server.
		esClient, err := elastic.NewSimpleClient(elastic.SetURL(server.URL))

		require.NoError(t, err)
		client = lmaelastic.NewWithClient(esClient)

		// Create a FlowBackend using the client.
		fb = flows.NewFlowBackend(client)

		// Basic parameters for each test.
		clusterInfo.Cluster = backendutils.RandomClusterName()
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)

		// Teardown goes within this returned func.
		return func() {
			cancel()
			logCancel()
		}
	}

	type testCase struct {
		// Name of the test
		name string

		// Response from elastic to be returned by the mock server.
		response any

		// Expected error
		err bool
	}

	// Define the list of testcases to run
	testCases := []testCase{
		{
			name:     "empty json",
			response: []byte("{}"),
			err:      false,
		},
		{
			name:     "malformed json",
			response: []byte("{"),
			err:      true,
		},
		{
			name:     "timeout",
			response: elastic.SearchResult{TimedOut: true},
			err:      true,
		},
		{
			name:     "valid single flow",
			response: validSingleFlow,
			err:      false,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.name, func(t *testing.T) {
			// We allow either raw byte arrays, or structures to be passed
			// as input. If it's a struct, serialize it first.
			var err error
			bs, ok := testcase.response.([]byte)
			if !ok {
				bs, err = json.Marshal(testcase.response)
				require.NoError(t, err)
			}
			defer setupAndTeardown(t, bs)()

			// Query for flows.
			_, err = fb.List(ctx, clusterInfo, &opts)
			if testcase.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMultiTenancy creates data for multiple tenants and asserts that it is handled properly.
func TestMultiTenancy(t *testing.T) {
	RunAllModes(t, "multiple tenants basic", func(t *testing.T) {
		// For this test, we will use two tenants with the same cluster ID, to be
		// extra sneaky.
		tenantA := "tenant-a"
		tenantB := "tenant-b"
		tenantAInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenantA}
		tenantBInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenantB}

		// Template for flow.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("34.15.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none").
			WithDestDomains("www.tigera.io", "www.calico.com", "www.kubernetes.io", "www.docker.com")

		// Create the flow for tenant A.
		exp1 := populateFlowData(t, ctx, bld, client, tenantAInfo)

		// Set time range so that we capture all of the populated flow logs.
		opts := v1.L3FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		// Query for flows using tenant A - there should be one flow from the populated data.
		r, err := fb.List(ctx, tenantAInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 1)
		require.Nil(t, r.AfterKey)
		require.Equal(t, exp1, r.Items[0])

		// Query for the flow using tenant B - we should get no results.
		r, err = fb.List(ctx, tenantBInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 0)
		require.Nil(t, r.AfterKey)
	})

	RunAllModes(t, "multiple tenants with similar names", func(t *testing.T) {
		// For this test, we use tenant IDs that are prefixes of each other.
		tenantA := "shaz"
		tenantB := "shazam"
		tenantAInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenantA}
		tenantBInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenantB}

		// Template for flow.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("34.15.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("bread=rye", "cheese=brie", "wine=none").
			WithDestDomains("www.tigera.io", "www.calico.com", "www.kubernetes.io", "www.docker.com")

		// Modify the builder for tenant B so that we can distinguish the two flows.
		bld2 := bld.Copy()
		bld2.WithReporter("dst")

		// Create the flow for both tenants
		exp1 := populateFlowData(t, ctx, bld, client, tenantAInfo)
		exp2 := populateFlowData(t, ctx, bld2, client, tenantBInfo)

		// Set time range so that we capture all of the populated flow logs.
		opts := v1.L3FlowParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)

		// Query for flows using tenant A - there should be one flow from the populated data.
		r, err := fb.List(ctx, tenantAInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 1)
		require.Nil(t, r.AfterKey)
		require.Equal(t, exp1, r.Items[0])

		// Query for flows using tenant B - there should be one flow from the populated data.
		r, err = fb.List(ctx, tenantBInfo, &opts)
		require.NoError(t, err)
		require.Len(t, r.Items, 1)
		require.Nil(t, r.AfterKey)
		require.Equal(t, exp2, r.Items[0])

		// Query for the flow specifying a tenant with a wildcard in it - should get no results.
		// It isn't actually possible for this codepath to be hit in a real system, since Linseed enforces
		// an expected tenant ID on all requests. We test it here nonetheless.
		wildcardTenant := bapi.ClusterInfo{Cluster: cluster1, Tenant: "shaz*"}
		_, err = fb.List(ctx, wildcardTenant, &opts)
		require.Error(t, err)
	})
}

// populateFlowData writes a series of flow logs to elasticsearch, and returns the FlowLog that we
// should expect to exist as a result. This can be used to assert round-tripping and aggregation against ES is working correctly.
func populateFlowData(t *testing.T, ctx context.Context, b *backendutils.FlowLogBuilder, client lmaelastic.Client, info bapi.ClusterInfo) v1.L3Flow {
	return populateFlowDataN(t, ctx, b, client, info, 10)
}

func populateFlowDataN(t *testing.T, ctx context.Context, b *backendutils.FlowLogBuilder, client lmaelastic.Client, info bapi.ClusterInfo, n int) v1.L3Flow {
	batch := []v1.FlowLog{}

	for i := range n {
		// We want a variety of label keys and values,
		// so base this one off of the loop variable.
		// Note: We use a nested terms aggregation to get labels, which has an
		// inherent maximum number of buckets of 10. As a result, if a flow has more than
		// 10 labels, not all of them will be shown. We might be able to use a composite aggregation instead,
		// but these are more expensive.
		b.WithDestLabels(fmt.Sprintf("dest_iteration=%d", i))
		f, err := b.Build()
		require.NoError(t, err)

		// Add it to the batch
		batch = append(batch, *f)
	}

	// Create the batch.
	// Creating the flow logs may fail due to conflicts with other tests modifying the same index.
	// Since go test runs packages in parallel, we need to retry a few times to avoid flakiness.
	// We could avoid this by creating a new ES instance per-test or per-package, but that would
	// slow down the test and use more resources. This is a reasonable compromise, and what clients will need to do anyway.
	attempts := 0
	response, err := flb.Create(ctx, info, batch)
	for err != nil && attempts < 5 {
		logrus.WithError(err).Info("[TEST] Retrying flow log creation due to error")
		attempts++
		response, err = flb.Create(ctx, info, batch)
	}
	require.NoError(t, err)
	require.Equal(t, []v1.BulkError(nil), response.Errors)
	require.Equal(t, 0, response.Failed)

	// Refresh the index so that data is readily available for the test. Otherwise, we need to wait
	// for the refresh interval to occur.
	err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(info))
	require.NoError(t, err)

	// Return the expected flow based on the batch of flows we created above.
	expected := b.ExpectedFlow(t, info)
	return *expected
}

func ActionPtr(val v1.FlowAction) *v1.FlowAction {
	return &val
}

// TestL3FlowCount tests the L3 flow count API with various parameters and scenarios.
func TestL3FlowCount(t *testing.T) {
	RunAllModes(t, "should count flows basic", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create 5 flow logs that will aggregate into a single L3 flow
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithSourcePort(12345).
			WithProtocol("udp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("app=test")
		_ = populateFlowDataN(t, ctx, bld, client, clusterInfo, 5)

		// Create intra-namespace flow (production -> production) to validate no double-counting
		bldIntra := backendutils.NewFlowLogBuilder()
		bldIntra.WithType("wep").
			WithSourceNamespace("production").
			WithDestNamespace("production").
			WithDestName("api-*").
			WithDestIP("10.1.0.20").
			WithDestService("api", 8080).
			WithDestPort(8080).
			WithSourcePort(34567).
			WithProtocol("tcp").
			WithSourceName("frontend").
			WithSourceIP("192.168.3.5").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("app=frontend")
		_ = populateFlowDataN(t, ctx, bldIntra, client, clusterInfo, 3)

		// Count the flows
		opts := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			},
		}
		countResp, err := fb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(2), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Len(t, countResp.NamespacedCounts, 3)
		require.Equal(t, int64(1), countResp.NamespacedCounts["default"])
		require.Equal(t, int64(1), countResp.NamespacedCounts["kube-system"])
		require.Equal(t, int64(1), countResp.NamespacedCounts["production"]) // Validates no double-counting for intra-namespace flow

		// Count with a different tenant ID - should return 0
		countResp, err = fb.Count(ctx, bapi.ClusterInfo{Tenant: "dummy", Cluster: cluster1}, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(0), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Empty(t, countResp.NamespacedCounts)
	})

	RunAllModes(t, "should count flows with filtering by source type", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create WEP flows
		bldWep := backendutils.NewFlowLogBuilder()
		bldWep.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithSourcePort(12345).
			WithProtocol("udp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("app=wep-app")
		_ = populateFlowDataN(t, ctx, bldWep, client, clusterInfo, 3)

		// Create HEP flows
		bldHep := backendutils.NewFlowLogBuilder()
		bldHep.WithType("hep").
			WithSourceNamespace("production").
			WithDestNamespace("kube-system").
			WithDestName("api-*").
			WithDestIP("10.0.0.20").
			WithDestService("api", 443).
			WithDestPort(443).
			WithSourcePort(23456).
			WithProtocol("tcp").
			WithSourceName("api").
			WithSourceIP("192.168.2.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("app=hep-app")
		_ = populateFlowDataN(t, ctx, bldHep, client, clusterInfo, 2)

		// Count with selector filtering for wep
		opts := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				SourceTypes: []v1.EndpointType{v1.WEP},
			},
		}
		countResp, err := fb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(1), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Equal(t, int64(1), countResp.NamespacedCounts["default"])
		require.Equal(t, int64(1), countResp.NamespacedCounts["kube-system"])

		// Count with selector filtering for hep
		opts.SourceTypes = []v1.EndpointType{v1.HEP}
		countResp, err = fb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(1), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Equal(t, int64(1), countResp.NamespacedCounts["production"])
		require.Equal(t, int64(1), countResp.NamespacedCounts["kube-system"])
	})

	RunAllModes(t, "should count flows with namespace filtering", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create flow 1: default -> kube-system
		bld1 := backendutils.NewFlowLogBuilder()
		bld1.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithSourcePort(12345).
			WithProtocol("udp").
			WithSourceName("app1").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("app=app1")
		_ = populateFlowDataN(t, ctx, bld1, client, clusterInfo, 2)

		// Create flow 2: production -> database
		bld2 := backendutils.NewFlowLogBuilder()
		bld2.WithType("wep").
			WithSourceNamespace("production").
			WithDestNamespace("database").
			WithDestName("postgres-*").
			WithDestIP("10.0.0.20").
			WithDestService("postgres", 5432).
			WithDestPort(5432).
			WithSourcePort(23456).
			WithProtocol("tcp").
			WithSourceName("api").
			WithSourceIP("192.168.2.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("app=api")
		_ = populateFlowDataN(t, ctx, bld2, client, clusterInfo, 1)

		// Count with source namespace match
		opts := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				NamespaceMatches: []v1.NamespaceMatch{
					{
						Type:       v1.MatchTypeSource,
						Namespaces: []string{"default"},
					},
				},
			},
		}
		countResp, err := fb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(1), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Equal(t, int64(1), countResp.NamespacedCounts["default"])
		require.Equal(t, int64(1), countResp.NamespacedCounts["kube-system"])

		// Count with destination namespace match
		opts.NamespaceMatches = []v1.NamespaceMatch{
			{
				Type:       v1.MatchTypeDest,
				Namespaces: []string{"database"},
			},
		}
		countResp, err = fb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(1), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Equal(t, int64(1), countResp.NamespacedCounts["production"])
		require.Equal(t, int64(1), countResp.NamespacedCounts["database"])
	})

	RunAllModes(t, "should count flows across multiple clusters", func(t *testing.T) {
		tenant := backendutils.RandomTenantName()
		cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
		cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
		cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

		f := backendutils.NewFlowLogBuilder()
		f.WithType("wep").
			WithSourceNamespace("default").
			WithDestNamespace("kube-system").
			WithDestName("kube-dns-*").
			WithDestIP("10.0.0.10").
			WithDestService("kube-dns", 53).
			WithDestPort(53).
			WithSourcePort(12345).
			WithProtocol("udp").
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithSourceLabels("app=test")

		for _, info := range []struct {
			cluster bapi.ClusterInfo
			num     int
		}{
			{cluster1Info, 2},
			{cluster2Info, 3},
			{cluster3Info, 1},
		} {
			_ = populateFlowDataN(t, ctx, f.Copy(), client, info.cluster, info.num)
		}

		opts := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			},
		}

		// Count single cluster
		countResp, err := fb.Count(ctx, cluster1Info, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(1), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Equal(t, int64(1), countResp.NamespacedCounts["default"])
		require.Equal(t, int64(1), countResp.NamespacedCounts["kube-system"])

		// Count multiple clusters
		opts.SetClusters([]string{cluster2, cluster3})
		countResp, err = fb.Count(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(2), *countResp.GlobalCount) // 1 from cluster2 + 1 from cluster3
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Equal(t, int64(2), countResp.NamespacedCounts["default"])
		require.Equal(t, int64(2), countResp.NamespacedCounts["kube-system"])

		// Count all clusters
		opts.SetAllClusters(true)
		countResp, err = fb.Count(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(3), *countResp.GlobalCount) // 1 from cluster1 + 1 from cluster2 + 1 from cluster3
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Equal(t, int64(3), countResp.NamespacedCounts["default"])
		require.Equal(t, int64(3), countResp.NamespacedCounts["kube-system"])
	})

	RunAllModes(t, "should return 0 count when no flows exist", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Don't create any flows, just count
		opts := v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			},
		}
		countResp, err := fb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(0), *countResp.GlobalCount)
		require.False(t, countResp.GlobalCountTruncated)
		require.NotNil(t, countResp.NamespacedCounts)
		require.Empty(t, countResp.NamespacedCounts)
	})

	RunAllModes(t, "should error with no cluster ID", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{}
		opts := &v1.L3FlowCountParams{}
		countResp, err := fb.Count(ctx, clusterInfo, opts)
		require.Error(t, err)
		require.Nil(t, countResp)
	})

	// The following tests cover different combinations of page size, max count, and total count to test pagination and truncation.
	setupTruncationFlows := func(totalCount int64) bapi.ClusterInfo {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		for i := range totalCount {
			bld := backendutils.NewFlowLogBuilder()
			bld.WithType("wep").
				WithSourceNamespace(fmt.Sprintf("namespace-%d", i)).
				WithDestNamespace("kube-system").
				WithDestName("kube-dns-*").
				WithDestIP(fmt.Sprintf("10.0.0.%d", i+10)).
				WithDestService("kube-dns", int(53+i)).
				WithDestPort(int(53 + i)).
				WithSourcePort(int(10000 + i)).
				WithProtocol("udp").
				WithSourceName(fmt.Sprintf("app-%d", i)).
				WithSourceIP(fmt.Sprintf("192.168.1.%d", i+1)).
				WithRandomFlowStats().WithRandomPacketStats().
				WithReporter("src").WithAction("allowed").
				WithSourceLabels(fmt.Sprintf("app=app-%d", i))
			_ = populateFlowDataN(t, ctx, bld, client, clusterInfo, 1)
		}

		return clusterInfo
	}

	createCountRequest := func(max, pageSize int64) *v1.L3FlowCountParams {
		return &v1.L3FlowCountParams{
			L3FlowParams: v1.L3FlowParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
					MaxPageSize: int(pageSize),
				},
			},
			MaxGlobalCount: &max,
		}
	}

	expectResponse := func(t *testing.T, response *v1.CountResponse, err error, expectedCount int64, expectedTruncated bool) {
		require.NoError(t, err)
		if expectedTruncated {
			require.NotNil(t, response.GlobalCount)
			require.Equal(t, expectedCount, *response.GlobalCount)
			require.True(t, response.GlobalCountTruncated)
			require.Nil(t, response.NamespacedCounts)
		} else {
			require.NotNil(t, response.GlobalCount)
			require.Equal(t, expectedCount, *response.GlobalCount)
			require.False(t, response.GlobalCountTruncated)
			require.NotNil(t, response.NamespacedCounts)
			require.Len(t, response.NamespacedCounts, int(expectedCount+1)) // n source namespaces + kube-system
			for i := range expectedCount {
				require.Equal(t, int64(1), response.NamespacedCounts[fmt.Sprintf("namespace-%d", i)])
			}
			require.Equal(t, expectedCount, response.NamespacedCounts["kube-system"])
		}
	}

	RunAllModes(t, "should not truncate when max < total count and page size > total count", func(t *testing.T) {
		maxCount := int64(3)
		total := int64(5)
		pageSize := int64(10)

		clusterInfo := setupTruncationFlows(total)
		countReq := createCountRequest(maxCount, pageSize)
		countResp, err := fb.Count(ctx, clusterInfo, countReq)

		// Expect global count equal to total count, with no signaled truncation.
		expectResponse(t, countResp, err, total, false)
	})

	RunAllModes(t, "should not truncate when max < total count and page size = total count", func(t *testing.T) {
		maxCount := int64(3)
		total := int64(10)
		pageSize := int64(10)

		clusterInfo := setupTruncationFlows(total)
		countReq := createCountRequest(maxCount, pageSize)
		countResp, err := fb.Count(ctx, clusterInfo, countReq)

		// Since page size is equal to the total count, we expect no truncation. In reality, the handler does return the full
		// count but sets truncated to true. This is due to a limitation of how pagination works in ES - the last page is always
		// empty. Usually we can get around this by checking if the returned records for a page are less than the max page size,
		// and thus avoid the last page. But in this case, the returned record count for the last non-empty page equals the page
		// size, so we don't know if the next page will be empty or not. Thus we terminate pagination 'early' and signal truncation.
		expectResponse(t, countResp, err, total, true)
	})

	RunAllModes(t, "should not truncate when max < total count and max is not divisible by page size and max is on the last page", func(t *testing.T) {
		maxCount := int64(8)
		total := int64(9)
		pageSize := int64(5)

		clusterInfo := setupTruncationFlows(total)
		countReq := createCountRequest(maxCount, pageSize)
		countResp, err := fb.Count(ctx, clusterInfo, countReq)

		// Expect global count equal to total count, with no signaled truncation.
		expectResponse(t, countResp, err, total, false)
	})

	RunAllModes(t, "should truncate when max < total count and max is divisible by page size", func(t *testing.T) {
		maxCount := int64(6)
		total := int64(10)
		pageSize := int64(3)

		clusterInfo := setupTruncationFlows(total)

		countReq := createCountRequest(maxCount, pageSize)
		countResp, err := fb.Count(ctx, clusterInfo, countReq)

		// We'll hit the max before we hit the last page. The returned count will be the count up to the last page: 6.
		expectResponse(t, countResp, err, int64(6), true)
	})

	RunAllModes(t, "should truncate when max < total count and max is not divisible by page and max is not on the last page", func(t *testing.T) {
		maxCount := int64(5)
		total := int64(10)
		pageSize := int64(3)

		clusterInfo := setupTruncationFlows(total)
		countReq := createCountRequest(maxCount, pageSize)
		countResp, err := fb.Count(ctx, clusterInfo, countReq)

		// We'll hit the max before we hit the last page. The returned count will be the count up to the last page: 6.
		expectResponse(t, countResp, err, int64(6), true)
	})

	RunAllModes(t, "should not truncate when max = total count", func(t *testing.T) {
		maxCount := int64(7)
		total := int64(7)
		pageSize := int64(3)

		clusterInfo := setupTruncationFlows(total)

		countReq := createCountRequest(maxCount, pageSize)
		countResp, err := fb.Count(ctx, clusterInfo, countReq)

		// Expect global count equal to total count, with no signaled truncation.
		expectResponse(t, countResp, err, total, false)
	})

	RunAllModes(t, "should not truncate when max > total count", func(t *testing.T) {
		maxCount := int64(10)
		total := int64(5)
		pageSize := int64(3)

		clusterInfo := setupTruncationFlows(total)

		countReq := createCountRequest(maxCount, pageSize)
		countResp, err := fb.Count(ctx, clusterInfo, countReq)

		// Expect global count equal to total count, with no signaled truncation.
		expectResponse(t, countResp, err, total, false)
	})
}

func TestFlowFilteringEndpointTypes(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.L3FlowParams

		// Configuration for which flows are expected to match.
		ExpectFlow1 bool
		ExpectFlow2 bool
	}

	numExpected := func(tc testCase) int {
		num := 0
		if tc.ExpectFlow1 {
			num++
		}
		if tc.ExpectFlow2 {
			num++
		}
		return num
	}

	testcases := []testCase{
		{
			Name: "should query a flow based on network source type",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				SourceTypes: []v1.EndpointType{v1.Network},
			},
			ExpectFlow1: true,
			ExpectFlow2: false,
		},
		{
			Name: "should query a flow based on network set source type",
			Params: v1.L3FlowParams{
				QueryParams: v1.QueryParams{},
				SourceTypes: []v1.EndpointType{v1.NetworkSet},
			},
			ExpectFlow1: false,
			ExpectFlow2: true,
		},
	}

	for _, testcase := range testcases {
		RunAllModes(t, testcase.Name, func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

			tr := &lmav1.TimeRange{}
			tr.From = time.Now().Add(-5 * time.Minute)
			tr.To = time.Now().Add(5 * time.Minute)
			testcase.Params.TimeRange = tr

			// Flow 1: Network type
			bld := backendutils.NewFlowLogBuilder()
			bld.WithType("net").
				WithSourceNamespace("default").
				WithDestNamespace("kube-system").
				WithDestName("kube-dns-*").
				WithDestIP("10.0.0.10").
				WithDestService("kube-dns", 53).
				WithDestPort(53).
				WithProtocol("udp").
				WithSourceName("my-network").
				WithSourceIP("192.168.1.1").
				WithRandomFlowStats().WithRandomPacketStats().
				WithReporter("src").WithAction("allowed")
			exp1 := populateFlowData(t, ctx, bld, client, clusterInfo)

			// Flow 2: NetworkSet type
			bld2 := backendutils.NewFlowLogBuilder()
			bld2.WithType("ns").
				WithSourceNamespace("default").
				WithDestNamespace("kube-system").
				WithDestName("kube-dns-*").
				WithDestIP("10.0.0.10").
				WithDestService("kube-dns", 53).
				WithDestPort(53).
				WithProtocol("udp").
				WithSourceName("my-network-set").
				WithSourceIP("192.168.1.1").
				WithRandomFlowStats().WithRandomPacketStats().
				WithReporter("src").WithAction("allowed")
			exp2 := populateFlowData(t, ctx, bld2, client, clusterInfo)

			// Query for flows.
			r, err := fb.List(ctx, clusterInfo, &testcase.Params)

			require.NoError(t, err)
			require.Len(t, r.Items, numExpected(testcase))
			require.Nil(t, r.AfterKey)

			if testcase.ExpectFlow1 {
				require.Contains(t, r.Items, exp1)
			}
			if testcase.ExpectFlow2 {
				require.Contains(t, r.Items, exp2)
			}
		})
	}
}

func TestConvertPoliciesCompatibility(t *testing.T) {
	// 1. Get the bucket converter (a flowBackend with nil client)
	converter := flows.NewBucketConverter()
	entry := logrus.NewEntry(logrus.StandardLogger())

	// Helper to create bucket with specific terms
	createBucket := func(terms map[string]*lmaelastic.AggregatedTerm) *lmaelastic.CompositeAggregationBucket {
		// Initialize dummy key
		dummyKey := make(lmaelastic.CompositeAggregationKey, 50)
		for i := range dummyKey {
			dummyKey[i] = lmaelastic.CompositeAggregationSourceValue{Value: ""}
		}

		// Initialize required empty terms to avoid panics
		requiredTerms := []string{
			"dest_labels", "source_labels", "dest_domains",
			"source_ip", "dest_ip",
			"enforced_policies", "pending_policies", "transit_policies", "all_policies",
		}

		for _, term := range requiredTerms {
			if _, exists := terms[term]; !exists {
				terms[term] = &lmaelastic.AggregatedTerm{Buckets: map[any]int64{}}
			}
		}

		return &lmaelastic.CompositeAggregationBucket{
			DocCount:                10,
			CompositeAggregationKey: dummyKey,
			AggregatedTerms:         terms,
			AggregatedSums:          make(map[string]float64),
			AggregatedMin:           make(map[string]float64),
			AggregatedMax:           make(map[string]float64),
			AggregatedMean:          make(map[string]float64),
		}
	}

	t.Run("should fallback to enforced_policies when all_policies is empty", func(t *testing.T) {
		enforcedBuckets := make(map[any]int64)
		enforcedBuckets["0|default|test-policy|allow|0"] = 10

		aggTerms := map[string]*lmaelastic.AggregatedTerm{
			"enforced_policies": {Buckets: enforcedBuckets},
		}

		bucket := createBucket(aggTerms)
		flow := converter.ConvertBucket(entry, bucket)

		require.NotEmpty(t, flow.EnforcedPolicies)
		require.Equal(t, "default.test-policy", flow.EnforcedPolicies[0].Name)

		// Policies should match EnforcedPolicies
		require.Equal(t, flow.EnforcedPolicies, flow.Policies)
	})

	t.Run("should use all_policies when present", func(t *testing.T) {
		allPolicyBuckets := make(map[any]int64)
		allPolicyBuckets["0|default|all-policy|allow|0"] = 10

		enforcedBuckets := make(map[any]int64)
		enforcedBuckets["0|default|enforced-policy|allow|0"] = 10

		aggTerms := map[string]*lmaelastic.AggregatedTerm{
			"all_policies":      {Buckets: allPolicyBuckets},
			"enforced_policies": {Buckets: enforcedBuckets},
		}

		bucket := createBucket(aggTerms)
		flow := converter.ConvertBucket(entry, bucket)

		// Check EnforcedPolicies is populated from its own term
		require.NotEmpty(t, flow.EnforcedPolicies)
		require.Equal(t, "default.enforced-policy", flow.EnforcedPolicies[0].Name)

		// Check Policies matches all_policies, NOT enforced_policies
		require.NotEmpty(t, flow.Policies)
		require.Len(t, flow.Policies, 1)
		require.Equal(t, "default.all-policy", flow.Policies[0].Name)
		require.NotEqual(t, flow.EnforcedPolicies, flow.Policies)
	})

	t.Run("should respond with empty policies if both are empty", func(t *testing.T) {
		bucket := createBucket(map[string]*lmaelastic.AggregatedTerm{})
		flow := converter.ConvertBucket(entry, bucket)

		require.Empty(t, flow.EnforcedPolicies)
		require.Empty(t, flow.Policies)
	})
}
