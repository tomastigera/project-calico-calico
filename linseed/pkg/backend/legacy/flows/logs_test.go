// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package flows_test

import (
	"context"
	gojson "encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	backendutils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// TestFlowLogBasic includes basic read / write tests for flow logs.
func TestFlowLogBasic(t *testing.T) {
	RunAllModes(t, "should create and retrieve a flow log", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create a dummy flow.
		f := v1.FlowLog{
			StartTime:            time.Now().Unix(),
			EndTime:              time.Now().Unix(),
			DestType:             "wep",
			DestNamespace:        "kube-system",
			DestNameAggr:         "kube-dns-*",
			DestServiceNamespace: "default",
			DestServiceName:      "kube-dns",
			DestServicePortNum:   testutils.Int64Ptr(53),
			DestIP:               testutils.StringPtr("fe80::0"),
			SourceIP:             testutils.StringPtr("fe80::1"),
			Protocol:             "udp",
			DestPort:             testutils.Int64Ptr(53),
			SourceType:           "wep",
			SourceNamespace:      "default",
			SourceNameAggr:       "my-deployment",
			ProcessName:          "-",
			Reporter:             "src",
			Action:               "allowed",
		}

		response, err := flb.Create(ctx, clusterInfo, []v1.FlowLog{f})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Read it back and make sure it matches.
		opts := v1.FlowLogParams{}
		opts.TimeRange = &lmav1.TimeRange{}
		opts.TimeRange.From = time.Now().Add(-5 * time.Minute)
		opts.TimeRange.To = time.Now().Add(5 * time.Minute)
		resp, err := flb.List(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.Len(t, resp.Items, 1)
		backendutils.AssertFlowLogIDAndClusterAndReset(t, clusterInfo.Cluster, &resp.Items[0])
		require.Equal(t, f, resp.Items[0])

		// Attempt to read it back with a different tenant ID - it should return nothing.
		resp, err = flb.List(ctx, bapi.ClusterInfo{Tenant: "dummy", Cluster: cluster1}, &opts)
		require.NoError(t, err)
		require.Len(t, resp.Items, 0)
	})

	RunAllModes(t, "no cluster name given on request", func(t *testing.T) {
		// It should reject requests with no cluster name given.
		clusterInfo := bapi.ClusterInfo{}
		_, err := flb.Create(ctx, clusterInfo, []v1.FlowLog{})
		require.Error(t, err)

		params := &v1.FlowLogParams{}
		results, err := flb.List(ctx, clusterInfo, params)
		require.Error(t, err)
		require.Nil(t, results)
	})

	RunAllModes(t, "bad startFrom on request", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
		params := &v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				AfterKey: map[string]interface{}{"startFrom": "badvalue"},
			},
		}
		results, err := flb.List(ctx, clusterInfo, params)
		require.Error(t, err)
		require.Nil(t, results)
	})

	RunAllModes(t, "filter flow logs by generated times", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create a dummy flow.
		f := v1.FlowLog{
			StartTime:            time.Now().Unix(),
			EndTime:              time.Now().Unix(),
			DestType:             "wep",
			DestNamespace:        "kube-system",
			DestNameAggr:         "kube-dns-*",
			DestServiceNamespace: "default",
			DestServiceName:      "kube-dns",
			DestServicePortNum:   testutils.Int64Ptr(53),
			DestIP:               testutils.StringPtr("fe80::0"),
			SourceIP:             testutils.StringPtr("fe80::1"),
			Protocol:             "udp",
			DestPort:             testutils.Int64Ptr(53),
			SourceType:           "wep",
			SourceNamespace:      "default",
			SourceNameAggr:       "my-deployment",
			ProcessName:          "-",
			Reporter:             "src",
			Action:               "allowed",
		}

		// Create a flow log
		response, err := flb.Create(ctx, clusterInfo, []v1.FlowLog{f})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		// Adding sleep to make sure there is no time that falls in the same second...
		time.Sleep(1 * time.Second)
		inBetweenTime := time.Now().UTC()
		time.Sleep(1 * time.Second)

		response, err = flb.Create(ctx, clusterInfo, []v1.FlowLog{f})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Read it back and make sure generated time values are what we expect.
		allOpts := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Minute),
					To:   time.Now().Add(5 * time.Minute),
				},
			},
		}
		allResp, err := flb.List(ctx, clusterInfo, &allOpts)
		require.NoError(t, err)
		require.Len(t, allResp.Items, 2)

		require.LessOrEqual(t, allResp.Items[0].GeneratedTime.Unix(), allResp.Items[1].GeneratedTime.Unix())
		require.LessOrEqual(t, allResp.Items[0].GeneratedTime.Unix(), inBetweenTime.Unix())
		require.LessOrEqual(t, inBetweenTime.Unix(), allResp.Items[1].GeneratedTime.Unix())

		require.LessOrEqual(t, time.Now().Add(-5*time.Minute).Unix(), allResp.Items[0].GeneratedTime.Unix())

		// Get only the first flow log based on generated time
		FirstOpts := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From:  time.Now().Add(-5 * time.Minute),
					To:    inBetweenTime,
					Field: "generated_time",
				},
			},
		}
		firstResp, err := flb.List(ctx, clusterInfo, &FirstOpts)
		require.NoError(t, err)
		require.Len(t, firstResp.Items, 1)

		require.LessOrEqual(t, firstResp.Items[0].GeneratedTime.Unix(), inBetweenTime.Unix())

		// Get only the last flow log based on generated time
		LastOpts := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From:  inBetweenTime,
					To:    time.Now().Add(5 * time.Minute),
					Field: "generated_time",
				},
			},
		}
		LastResp, err := flb.List(ctx, clusterInfo, &LastOpts)
		require.NoError(t, err)
		require.Len(t, LastResp.Items, 1)

		require.Less(t, inBetweenTime.Unix(), LastResp.Items[0].GeneratedTime.Unix())
	})
}

func TestFlowSorting(t *testing.T) {
	RunAllModes(t, "should respect sorting", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}

		t1 := time.Unix(100, 0)
		t2 := time.Unix(500, 0)

		// Template for flow #1.
		bld := backendutils.NewFlowLogBuilder()
		bld.WithType("wep").
			WithSourceNamespace("tigera-operator").
			WithDestNamespace("openshift-dns").
			WithDestName("openshift-dns-*").
			WithDestIP("192.168.1.1").
			WithDestService("openshift-dns", 53).
			WithDestPort(1053).
			WithSourcePort(1010).
			WithProtocol("udp").
			WithSourceName("tigera-operator").
			WithSourceIP("34.15.66.3").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithEndTime(t1).
			WithSourceLabels("bread=rye", "cheese=cheddar", "wine=none")

		fl1, err := bld.Build()
		require.NoError(t, err)

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
			WithSourceName("my-deployment").
			WithSourceIP("192.168.1.1").
			WithRandomFlowStats().WithRandomPacketStats().
			WithReporter("src").WithAction("allowed").
			WithEndTime(t2).
			WithSourceLabels("cheese=brie")
		fl2, err := bld2.Build()
		require.NoError(t, err)

		response, err := flb.Create(ctx, clusterInfo, []v1.FlowLog{*fl1, *fl2})
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Query for flow logs without sorting.
		params := v1.FlowLogParams{}
		r, err := flb.List(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)
		require.Empty(t, err)

		// Assert that the logs are returned in the correct order.
		copyOfLogs := backendutils.AssertFlowLogsIDAndClusterAndReset(t, clusterInfo.Cluster, r)
		require.Equal(t, *fl1, copyOfLogs[0])
		require.Equal(t, *fl2, copyOfLogs[1])

		// Query again, this time sorting in order to get the logs in reverse order.
		params.Sort = []v1.SearchRequestSortBy{
			{
				Field:      "end_time",
				Descending: true,
			},
		}
		r, err = flb.List(ctx, clusterInfo, &params)
		require.NoError(t, err)
		require.Len(t, r.Items, 2)
		require.Nil(t, r.AfterKey)
		require.Empty(t, err)
		copyOfLogs = backendutils.AssertFlowLogsIDAndClusterAndReset(t, clusterInfo.Cluster, r)
		require.Equal(t, *fl2, copyOfLogs[0])
		require.Equal(t, *fl1, copyOfLogs[1])
	})
}

func TestFlowLogFiltering(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.FlowLogParams

		// Configuration for which logs are expected to match.
		ExpectLog1 bool
		ExpectLog2 bool

		// Whether to perform an equality comparison on the returned
		// logs. Can be useful for tests where stats differ.
		SkipComparison bool
	}

	numExpected := func(tc testCase) int {
		num := 0
		if tc.ExpectLog1 {
			num++
		}
		if tc.ExpectLog2 {
			num++
		}
		return num
	}

	testcases := []testCase{
		{
			Name:       "should query both flow logs",
			Params:     v1.FlowLogParams{},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on source type",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "source_type = wep",
				},
			},
			ExpectLog1: true,
			ExpectLog2: false, // Source is a hep.
		},
		{
			Name: "should support NOT selection based on source type",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "source_type != wep",
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on source IP match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				IPMatches: []v1.IPMatch{
					{
						Type: v1.MatchTypeSource,
						IPs:  []string{"192.168.1.1"},
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on multiple source IP matches",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				IPMatches: []v1.IPMatch{
					{
						Type: v1.MatchTypeSource,
						IPs:  []string{"192.168.1.1", "34.15.66.3"},
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on destination IP match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				IPMatches: []v1.IPMatch{
					{
						Type: v1.MatchTypeDest,
						IPs:  []string{"10.0.0.10"},
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on multiple destination IP matches",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				IPMatches: []v1.IPMatch{
					{
						Type: v1.MatchTypeDest,
						IPs:  []string{"10.0.0.10", "192.168.1.1"},
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on any IP matches",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				IPMatches: []v1.IPMatch{
					{
						Type: v1.MatchTypeAny,
						IPs:  []string{"192.168.1.1"},
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should support combined selectors",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					// This selector matches both.
					Selector: "(source_type != wep AND dest_type != wep) OR proto = udp AND dest_port = 1053",
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should support NOT with combined selectors",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					// Should match neither.
					Selector: "NOT ((source_type != wep AND dest_type != wep) OR proto = udp AND dest_port = 1053)",
				},
			},
			ExpectLog1: false,
			ExpectLog2: false,
		},
		{
			Name: "should support selection when only tier is specified",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier: "custom-tier",
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection with policy tier and namespace match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier:      "allow-tigera",
						Namespace: testutils.StringPtr("openshift-dns"),
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support selection with policy tier, name, and namespace match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier:      "allow-tigera",
						Namespace: testutils.StringPtr("openshift-dns"),
						Name:      testutils.StringPtr("allow-tigera.cluster-dns"),
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support selection with policy action and namespace match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Namespace: testutils.StringPtr("kube-system"),
						Action:    ActionPtr(v1.FlowActionPass),
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should select global policy when name and tier are set but namespace is not",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Name: testutils.StringPtr("malicious-traffic"),
						Tier: "allow-tigera",
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: false,
		},
		{
			Name: "should support selection with policy action=allow match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Action: ActionPtr(v1.FlowActionAllow),
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support selection with policy action=deny match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Action: ActionPtr(v1.FlowActionDeny),
					},
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on host match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: `host = "my-host"`,
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on tcp match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "tcp_lost_packets = 100 AND tcp_mean_send_congestion_window = 101 AND " +
						"tcp_min_send_congestion_window = 102 AND tcp_total_retransmissions = 103 AND tcp_unrecovered_to = 104",
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support selection based on tcp mss match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "tcp_mean_mss = 200 AND tcp_min_mss = 201",
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support selection based on tcp rtt fields match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "tcp_max_min_rtt = 300 AND tcp_max_smooth_rtt = 301 AND tcp_mean_min_rtt = 302 AND tcp_mean_smooth_rtt = 303",
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support selection based on labels nested field match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "\"source_labels.labels\" IN {\"*eese=chedd*\"}",
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support selection based on policies nested field match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "\"policies.pending_policies\" IN {\"*snp:default/policy*\"}",
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
		{
			Name: "should support dest_domains empty match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "dest_domains EMPTY",
				},
			},
			ExpectLog1: true,
			ExpectLog2: false,
		},
		{
			Name: "should support dest_domains not empty match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "NOT dest_domains EMPTY",
				},
			},
			ExpectLog1: false,
			ExpectLog2: true,
		},
	}

	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		for _, testcase := range testcases {
			// Each testcase creates multiple flow logs, and then uses
			// different filtering parameters provided in the params
			// to query one or more flow logs.
			name := fmt.Sprintf("%s (tenant=%s)", testcase.Name, tenant)
			RunAllModes(t, name, func(t *testing.T) {
				clusterInfo1 := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
				clusterInfo2 := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
				clusterInfo3 := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

				// Set the time range for the test. We set this per-test
				// so that the time range captures the windows that the logs
				// are created in.
				tr := &lmav1.TimeRange{}
				tr.From = time.Now().Add(-5 * time.Minute)
				tr.To = time.Now().Add(5 * time.Minute)
				params := testcase.Params
				params.TimeRange = tr

				// Template for flow #1.
				bld := backendutils.NewFlowLogBuilder()
				bld.WithType("wep").
					WithSourceNamespace("tigera-operator").
					WithDestNamespace("openshift-dns").
					WithDestName("openshift-dns-*").
					WithDestIP("192.168.1.1").
					WithDestService("openshift-dns", 53).
					WithDestPort(1053).
					WithSourcePort(1010).
					WithProtocol("udp").
					WithSourceName("tigera-operator").
					WithSourceIP("34.15.66.3").
					WithRandomFlowStats().WithRandomPacketStats().
					WithReporter("src").WithAction("allowed").
					WithSourceLabels("bread=rye", "cheese=cheddar", "wine=none").
					WithPolicy("1|allow-tigera|np:openshift-dns/allow-tigera.cluster-dns|allow|1").
					WithPolicy("0|allow-tigera|np:openshift-dns/mallicious-dns|pass|1").
					WithEnforcedPolicy("1|allow-tigera|np:openshift-dns/allow-tigera.cluster-dns|allow|1").
					WithEnforcedPolicy("0|allow-tigera|np:openshift-dns/mallicious-dns|pass|1").
					WithPendingPolicy("1|allow-tigera|np:openshift-dns/allow-tigera.cluster-dns|allow|1").
					WithPendingPolicy("0|allow-tigera|np:openshift-dns/mallicious-dns|pass|1").
					WithTransitPolicy("1|allow-tigera|np:openshift-dns/allow-tigera.cluster-dns|allow|1").
					WithTransitPolicy("0|allow-tigera|np:openshift-dns/mallicious-dns|pass|1").
					WithTCPLostPackets(100).
					WithTCPMeanSendCongestionWindow(101).
					WithTCPMinSendCongestionWindow(102).
					WithTCPTotalRetransmissions(103).
					WithTCPUnrecoveredTo(104).
					WithTCPMeanMSS(200).
					WithTCPMinMSS(201)

				fl1, err := bld.Build()
				require.NoError(t, err)

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
					WithSourceName("my-deployment").
					WithSourceIP("192.168.1.1").
					WithRandomFlowStats().WithRandomPacketStats().
					WithReporter("src").WithAction("allowed").
					WithSourceLabels("cheese=brie").
					WithPolicy("0|allow-tigera|np:kube-system/allow-tigera.cluster-dns|pass|1").
					WithPolicy("1|custom-tier|gnp:custom-tier.my-deployment-dns|deny|1").
					WithHost("my-host").
					WithTCPMaxMinRTT(300).
					WithTCPMaxSmoothRTT(301).
					WithTCPMeanMinRTT(302).
					WithTCPMeanSmoothRTT(303).
					WithDestDomains("tigera.domain").
					WithPendingPolicy("0|custom-tier2|snp:default/policy|allow|1")
				fl2, err := bld2.Build()
				require.NoError(t, err)

				for _, clusterInfo := range []bapi.ClusterInfo{clusterInfo1, clusterInfo2, clusterInfo3} {
					response, err := flb.Create(ctx, clusterInfo, []v1.FlowLog{*fl1, *fl2})
					require.NoError(t, err)
					require.Equal(t, []v1.BulkError(nil), response.Errors)
					require.Equal(t, 0, response.Failed)

					err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
					require.NoError(t, err)
				}

				t.Run("should query single cluster", func(t *testing.T) {
					// Query for flow logs.
					r, err := flb.List(ctx, clusterInfo1, &params)
					require.NoError(t, err)
					require.Len(t, r.Items, numExpected(testcase))
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)

					// Try querying with a different tenant ID and make sure we don't
					// get any flows back.
					r2, err := flb.List(ctx, bapi.ClusterInfo{Cluster: cluster1, Tenant: "dummy-tenant"}, &params)
					require.NoError(t, err)
					require.Len(t, r2.Items, 0)

					if !testcase.SkipComparison {
						copyOfLogs := backendutils.AssertFlowLogsIDAndClusterAndReset(t, clusterInfo1.Cluster, r)

						// Assert that the correct logs are returned.
						if testcase.ExpectLog1 {
							require.Contains(t, copyOfLogs, *fl1)
						}
						if testcase.ExpectLog2 {
							require.Contains(t, copyOfLogs, *fl2)
						}
					}
				})

				t.Run("should query multiple clusters", func(t *testing.T) {
					selectedClusters := []string{cluster2, cluster3}
					params.SetClusters(selectedClusters)
					r, err := flb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &params)
					require.NoError(t, err)
					require.Len(t, r.Items, numExpected(testcase)*2) // 2 clusters so double the expected number of logs.
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)

					if !testcase.SkipComparison {
						var copyOfLogs []v1.FlowLog
						for _, item := range r.Items {
							require.Contains(t, selectedClusters, item.Cluster)
							backendutils.AssertFlowLogIDAndClusterAndReset(t, item.Cluster, &item)

							copyOfLogs = append(copyOfLogs, item)
						}

						// Assert that the correct logs are returned.
						if testcase.ExpectLog1 {
							require.Contains(t, copyOfLogs, *fl1)
						}
						if testcase.ExpectLog2 {
							require.Contains(t, copyOfLogs, *fl2)
						}
					}

					if numExpected(testcase) > 0 {
						require.Falsef(t, backendutils.MatchIn(r.Items, backendutils.FlowLogClusterEquals(cluster1)), "found unexpected cluster %s", cluster1)
						for i, cluster := range selectedClusters {
							require.Truef(t, backendutils.MatchIn(r.Items, backendutils.FlowLogClusterEquals(cluster)), "didn't cluster %d: %s", i, cluster)
						}
					}
				})

				t.Run("should query all clusters", func(t *testing.T) {
					params.SetAllClusters(true)
					r, err := flb.List(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &params)
					require.NoError(t, err)
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)

					if !testcase.SkipComparison {
						var copyOfLogs []v1.FlowLog
						for _, item := range r.Items {
							backendutils.AssertFlowLogIDAndClusterAndReset(t, item.Cluster, &item)
							copyOfLogs = append(copyOfLogs, item)
						}

						// Assert that the correct logs are returned.
						if testcase.ExpectLog1 {
							require.Contains(t, copyOfLogs, *fl1)
						}
						if testcase.ExpectLog2 {
							require.Contains(t, copyOfLogs, *fl2)
						}
					}

					// We can't assert that *only* these clusters are returned, because other tests might be running
					// and we are querying all clusters.
					if numExpected(testcase) > 0 {
						allClusters := []string{cluster1, cluster2, cluster3}
						count := 0
						for _, item := range r.Items {
							for _, c := range allClusters {
								if item.Cluster == c {
									count++
									break
								}
							}
						}
						require.Equal(t, numExpected(testcase)*3, count)
					}
				})
			})
		}
	}
}

// TestLegacyPolicyStrings tests that legacy policy strings are still supported, and
// that queries correctly match both legacy and new style policy strings.
func TestLegacyPolicyStrings(t *testing.T) {
	type testCase struct {
		Name   string
		Params v1.FlowLogParams

		// Configuration for which logs are expected to match.
		ExpectLog1 bool
		ExpectLog2 bool

		// Whether to perform an equality comparison on the returned
		// logs. Can be useful for tests where stats differ.
		SkipComparison bool
	}

	testcases := []testCase{
		{
			Name: "should support selection with policy tier and namespace match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier:      "allow-tigera",
						Namespace: testutils.StringPtr("openshift-dns"),
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			Name: "should support staged policy selection with exact name match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Name:   testutils.StringPtr("custom-tier2.gnp"),
						Tier:   "custom-tier2",
						Staged: true,
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
		{
			// This should only match the first log.
			Name: "should support staged namespaced policy selection with exact name match",
			Params: v1.FlowLogParams{
				QueryParams: v1.QueryParams{},
				PendingPolicyMatches: []v1.PolicyMatch{
					{
						Name:      testutils.StringPtr("custom-tier2.policy2"),
						Namespace: testutils.StringPtr("default"),
						Tier:      "custom-tier2",
						Staged:    true,
					},
				},
			},
			ExpectLog1: true,
			ExpectLog2: true,
		},
	}

	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		for _, testcase := range testcases {
			// Each testcase creates multiple flow logs, and then uses
			// different filtering parameters provided in the params
			// to query one or more flow logs.
			name := fmt.Sprintf("%s (tenant=%s)", testcase.Name, tenant)
			RunAllModes(t, name, func(t *testing.T) {
				clusterInfo1 := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
				clusterInfo2 := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
				clusterInfo3 := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

				// Set the time range for the test. We set this per-test
				// so that the time range captures the windows that the logs
				// are created in.
				tr := &lmav1.TimeRange{}
				tr.From = time.Now().Add(-5 * time.Minute)
				tr.To = time.Now().Add(5 * time.Minute)
				params := testcase.Params
				params.TimeRange = tr

				// Create a flow log builder base template, without any policies.
				tmpl := backendutils.NewFlowLogBuilder()
				tmpl.WithType("wep").
					WithSourceNamespace("tigera-operator").
					WithDestNamespace("openshift-dns").
					WithDestName("openshift-dns-*").
					WithDestIP("192.168.1.1").
					WithDestService("openshift-dns", 53).
					WithDestPort(1053).
					WithSourcePort(1010).
					WithProtocol("udp").
					WithSourceName("tigera-operator").
					WithSourceIP("34.15.66.3").
					WithRandomFlowStats().WithRandomPacketStats().
					WithReporter("src").WithAction("allowed").
					WithSourceLabels("bread=rye", "cheese=cheddar", "wine=none").
					WithTCPLostPackets(100).
					WithTCPMeanSendCongestionWindow(101).
					WithTCPMinSendCongestionWindow(102).
					WithTCPTotalRetransmissions(103).
					WithTCPUnrecoveredTo(104).
					WithTCPMeanMSS(200).
					WithTCPMinMSS(201)

				// Create a builder that uses legacy style policy strings.
				leg := tmpl.Copy().
					WithPolicy("1|allow-tigera|openshift-dns/allow-tigera.cluster-dns|allow|1").   // Tier part of the name.
					WithPolicy("0|allow-tigera|allow-tigera.gnp|pass|1").                          // Tier not part of name.
					WithPendingPolicy("0|custom-tier2|custom-tier2.staged:gnp|allow|1").           // Tier part of name.
					WithPendingPolicy("1|custom-tier2|default/custom-tier2.staged:policy|deny|1"). // Tier not part of the name.
					WithPendingPolicy("1|custom-tier2|default/custom-tier2.staged:policy2|deny|1") // Only present in old flow.
				fl1, err := leg.Build()
				require.NoError(t, err)

				// Template for flow #2, which is the same as flow #1 but with its policy strings
				// in the new format.
				bld2 := tmpl.Copy().
					WithPolicy("1|allow-tigera|openshift-dns/allow-tigera.cluster-dns|allow|1").      // Tier part of the name.
					WithPolicy("0|allow-tigera|gnp|pass|1").                                          // Tier not part of name.
					WithPendingPolicy("0|custom-tier2|custom-tier2.staged:custom-tier2.gnp|allow|1"). // Tier part of name.
					WithPendingPolicy("1|custom-tier2|default/custom-tier2.staged:policy|deny|1")     // Tier not part of name.
				fl2, err := bld2.Build()
				require.NoError(t, err)

				for _, clusterInfo := range []bapi.ClusterInfo{clusterInfo1, clusterInfo2, clusterInfo3} {
					response, err := flb.Create(ctx, clusterInfo, []v1.FlowLog{*fl1, *fl2})
					require.NoError(t, err)
					require.Equal(t, []v1.BulkError(nil), response.Errors)
					require.Equal(t, 0, response.Failed)

					err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
					require.NoError(t, err)
				}

				t.Run("should query single cluster", func(t *testing.T) {
					// Query for flow logs.
					r, err := flb.List(ctx, clusterInfo1, &params)
					require.NoError(t, err)
					require.Len(t, r.Items, 2) // We expect both logs to match.
					require.Nil(t, r.AfterKey)
					require.Empty(t, err)

					if !testcase.SkipComparison {
						copyOfLogs := backendutils.AssertFlowLogsIDAndClusterAndReset(t, clusterInfo1.Cluster, r)

						// Assert that the correct logs are returned.
						if testcase.ExpectLog1 {
							require.Contains(t, copyOfLogs, *fl1)
						}
						if testcase.ExpectLog2 {
							require.Contains(t, copyOfLogs, *fl2)
						}
					}
				})
			})
		}
	}
}

// TestAggregations tests running a real elasticsearch query to get aggregations.
func TestAggregations(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should return time-series flow log aggregation results (tenant=%s)", tenant), func(t *testing.T) {
			cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
			cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
			cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

			// Start the test numLogs minutes in the past.
			numLogs := 5
			timeBetweenLogs := 10 * time.Second
			testStart := time.Unix(0, 0)
			now := testStart.Add(time.Duration(numLogs) * time.Minute)

			// Several dummy logs.
			logs := []v1.FlowLog{}
			for i := 1; i < numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				end := start.Add(timeBetweenLogs)
				log := v1.FlowLog{
					StartTime: start.Unix(),
					EndTime:   end.Unix(),
					BytesIn:   1,
				}
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
				resp, err := flb.Create(ctx, clusterInfo, logs)
				require.NoError(t, err)
				require.Empty(t, resp.Errors)

				// Refresh.
				err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
				require.NoError(t, err)
			}

			type testCase struct {
				Name           string
				XClusterID     string
				ParamsCallback func(params *v1.FlowLogAggregationParams)
				ExpectedCount  int
			}

			testcases := []testCase{
				{
					Name:          "single cluster",
					XClusterID:    cluster1,
					ExpectedCount: 1,
				},
				{
					Name:       "multiple clusters",
					XClusterID: v1.QueryMultipleClusters,
					ParamsCallback: func(params *v1.FlowLogAggregationParams) {
						params.SetClusters([]string{cluster2, cluster3})
					},
					ExpectedCount: 2,
				},
				{
					Name:       "all clusters",
					XClusterID: v1.QueryMultipleClusters,
					ParamsCallback: func(params *v1.FlowLogAggregationParams) {
						params.SetAllClusters(true)
					},
					ExpectedCount: 3,
				},
			}

			for _, tc := range testcases {
				t.Run(tc.Name, func(t *testing.T) {
					clusterInfo := bapi.ClusterInfo{Cluster: tc.XClusterID, Tenant: tenant}

					params := v1.FlowLogAggregationParams{}
					params.TimeRange = &lmav1.TimeRange{}
					params.TimeRange.From = testStart
					params.TimeRange.To = now
					params.NumBuckets = 4
					if f := tc.ParamsCallback; f != nil {
						f(&params)
					}

					// Add a simple aggregation to add up the total bytes_in from the logs.
					sumAgg := elastic.NewSumAggregation().Field("bytes_in")
					src, err := sumAgg.Source()
					require.NoError(t, err)
					bytes, err := json.Marshal(src)
					require.NoError(t, err)
					params.Aggregations = map[string]gojson.RawMessage{"count": bytes}

					// Use the backend to perform a query.
					aggs, err := flb.Aggregations(ctx, clusterInfo, &params)
					require.NoError(t, err)
					require.NotNil(t, aggs)

					ts, ok := aggs.AutoDateHistogram("tb")
					require.True(t, ok)

					// We asked for 4 buckets.
					require.Len(t, ts.Buckets, 4)

					times := []string{"11", "12", "13", "14"}

					for i, b := range ts.Buckets {
						require.Equal(t, int64(tc.ExpectedCount), b.DocCount, fmt.Sprintf("Bucket %d", i))

						// We asked for a count agg, which should include a single log
						// in each bucket.
						count, ok := b.Sum("count")
						require.True(t, ok, "Bucket missing count agg")
						require.NotNil(t, count.Value)
						require.Equal(t, float64(tc.ExpectedCount), *count.Value)

						// The key should be the timestamp for the bucket.
						require.NotNil(t, b.KeyAsString)
						require.Equal(t, times[i], *b.KeyAsString)
					}
				})
			}
		})

		RunAllModes(t, fmt.Sprintf("should return aggregate stats (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			// Start the test numLogs minutes in the past.
			numLogs := 5
			timeBetweenLogs := 10 * time.Second
			testStart := time.Unix(0, 0)
			now := testStart.Add(time.Duration(numLogs) * time.Minute)

			// Several dummy logs.
			logs := []v1.FlowLog{}
			for i := 1; i < numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				end := start.Add(timeBetweenLogs)
				log := v1.FlowLog{
					StartTime: start.Unix(),
					EndTime:   end.Unix(),
					BytesIn:   1,
				}
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := flb.Create(ctx, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			params := v1.FlowLogAggregationParams{}
			params.TimeRange = &lmav1.TimeRange{}
			params.TimeRange.From = testStart
			params.TimeRange.To = now
			params.NumBuckets = 0 // Return aggregated stats over the whole time range.

			// Add a simple aggregation to add up the total bytes_in from the logs.
			sumAgg := elastic.NewSumAggregation().Field("bytes_in")
			src, err := sumAgg.Source()
			require.NoError(t, err)
			bytes, err := json.Marshal(src)
			require.NoError(t, err)
			params.Aggregations = map[string]gojson.RawMessage{"count": bytes}

			// Use the backend to perform a stats query.
			result, err := flb.Aggregations(ctx, clusterInfo, &params)
			require.NoError(t, err)

			// We should get a sum aggregation with all 4 logs.
			count, ok := result.ValueCount("count")
			require.True(t, ok)
			require.NotNil(t, count.Value)
			require.Equal(t, float64(4), *count.Value)
		})
	}
}

func TestPreserveIDs(t *testing.T) {
	// Run each testcase both as a multi-tenant scenario, as well as a single-tenant case.
	for _, tenant := range []string{backendutils.RandomTenantName(), ""} {
		RunAllModes(t, fmt.Sprintf("should preserve IDs across bulk ingestion requests (tenant=%s)", tenant), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}

			numLogs := 5
			timeBetweenLogs := 10 * time.Second
			testStart := time.Unix(0, 0).UTC()

			// Several dummy logs.
			logs := []v1.FlowLog{}
			for i := 1; i <= numLogs; i++ {
				start := testStart.Add(time.Duration(i) * time.Second)
				end := start.Add(timeBetweenLogs)
				log := v1.FlowLog{
					StartTime: start.Unix(),
					EndTime:   end.Unix(),
					BytesIn:   1,
				}
				logs = append(logs, log)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := flb.Create(ctx, clusterInfo, logs)
			require.NoError(t, err)
			require.Empty(t, resp.Errors)

			// Refresh.
			err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)

			// Read it back and make sure generated time values are what we expect.
			allOpts := v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: testStart.Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			}
			first, err := flb.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, first.Items, numLogs)

			bulk, err := flb.Create(ctx, clusterInfo, first.Items)
			require.NoError(t, err)
			require.Empty(t, bulk.Errors)

			second, err := flb.List(ctx, clusterInfo, &allOpts)
			require.NoError(t, err)
			require.Len(t, second.Items, numLogs)

			for _, log := range first.Items {
				backendutils.AssertGeneratedTimeAndReset[v1.FlowLog](t, &log)
			}
			for _, log := range second.Items {
				backendutils.AssertGeneratedTimeAndReset[v1.FlowLog](t, &log)
			}

			require.Equal(t, first.Items, second.Items)

			// Refresh before cleaning up data
			err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
			require.NoError(t, err)
		})
	}
}

// TestFlowLogCount tests the Count() method for flow logs.
func TestFlowLogCount(t *testing.T) {
	RunAllModes(t, "should return correct count for basic query", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create 5 flow logs
		f := v1.FlowLog{
			StartTime:            time.Now().Unix(),
			EndTime:              time.Now().Unix(),
			DestType:             "wep",
			DestNamespace:        "kube-system",
			DestNameAggr:         "kube-dns-*",
			DestServiceNamespace: "default",
			DestServiceName:      "kube-dns",
			DestServicePortNum:   testutils.Int64Ptr(53),
			DestIP:               testutils.StringPtr("fe80::0"),
			SourceIP:             testutils.StringPtr("fe80::1"),
			Protocol:             "udp",
			DestPort:             testutils.Int64Ptr(53),
			SourceType:           "wep",
			SourceNamespace:      "default",
			SourceNameAggr:       "my-deployment",
			ProcessName:          "-",
			Reporter:             "src",
			Action:               "allowed",
		}

		logs := []v1.FlowLog{f, f, f, f, f}
		response, err := flb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Count the logs
		opts := v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			},
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(5), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		// Count with a different tenant ID - should return 0
		countResp, err = flb.Count(ctx, bapi.ClusterInfo{Tenant: "dummy", Cluster: cluster1}, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(0), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)
	})

	RunAllModes(t, "should return correct count with selector", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create flow logs with different source types
		f1 := v1.FlowLog{
			StartTime:       time.Now().Unix(),
			EndTime:         time.Now().Unix(),
			SourceType:      "wep",
			DestType:        "wep",
			DestNamespace:   "kube-system",
			DestNameAggr:    "kube-dns-*",
			DestIP:          testutils.StringPtr("fe80::0"),
			SourceIP:        testutils.StringPtr("fe80::1"),
			Protocol:        "udp",
			DestPort:        testutils.Int64Ptr(53),
			SourceNamespace: "default",
			SourceNameAggr:  "my-deployment",
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		f2 := v1.FlowLog{
			StartTime:       time.Now().Unix(),
			EndTime:         time.Now().Unix(),
			SourceType:      "hep",
			DestType:        "hep",
			DestNamespace:   "kube-system",
			DestNameAggr:    "kube-dns-*",
			DestIP:          testutils.StringPtr("fe80::0"),
			SourceIP:        testutils.StringPtr("fe80::2"),
			Protocol:        "tcp",
			DestPort:        testutils.Int64Ptr(80),
			SourceNamespace: "test",
			SourceNameAggr:  "test-pod",
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		logs := []v1.FlowLog{f1, f1, f1, f2, f2}
		response, err := flb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Count with selector filtering for wep
		opts := v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "source_type = wep",
				},
			},
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(3), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		// Count with selector filtering for hep
		opts.Selector = "source_type = hep"
		countResp, err = flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(2), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)
	})

	RunAllModes(t, "should return correct count with IP matches", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create flow logs with different IPs
		f1 := v1.FlowLog{
			StartTime:       time.Now().Unix(),
			EndTime:         time.Now().Unix(),
			SourceType:      "wep",
			DestType:        "wep",
			DestNamespace:   "kube-system",
			DestNameAggr:    "kube-dns-*",
			DestIP:          testutils.StringPtr("10.0.0.1"),
			SourceIP:        testutils.StringPtr("192.168.1.1"),
			Protocol:        "udp",
			DestPort:        testutils.Int64Ptr(53),
			SourceNamespace: "default",
			SourceNameAggr:  "my-deployment",
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		f2 := v1.FlowLog{
			StartTime:       time.Now().Unix(),
			EndTime:         time.Now().Unix(),
			SourceType:      "wep",
			DestType:        "wep",
			DestNamespace:   "kube-system",
			DestNameAggr:    "kube-dns-*",
			DestIP:          testutils.StringPtr("10.0.0.2"),
			SourceIP:        testutils.StringPtr("192.168.1.2"),
			Protocol:        "tcp",
			DestPort:        testutils.Int64Ptr(80),
			SourceNamespace: "test",
			SourceNameAggr:  "test-pod",
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		logs := []v1.FlowLog{f1, f1, f2}
		response, err := flb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Count with source IP match
		opts := v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				IPMatches: []v1.IPMatch{
					{
						Type: v1.MatchTypeSource,
						IPs:  []string{"192.168.1.1"},
					},
				},
			},
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(2), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		// Count with destination IP match
		opts.IPMatches = []v1.IPMatch{
			{
				Type: v1.MatchTypeDest,
				IPs:  []string{"10.0.0.2"},
			},
		}
		countResp, err = flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(1), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)
	})

	RunAllModes(t, "should return correct count with policy matches", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create flow logs with different policies using simple struct
		nowUnix := time.Now().Unix()
		fl1 := v1.FlowLog{
			StartTime:       nowUnix,
			EndTime:         nowUnix,
			SourceType:      "wep",
			DestType:        "wep",
			SourceNamespace: "default",
			DestNamespace:   "kube-system",
			DestNameAggr:    "kube-dns-*",
			DestIP:          testutils.StringPtr("10.0.0.10"),
			DestPort:        testutils.Int64Ptr(53),
			Protocol:        "udp",
			SourceNameAggr:  "my-deployment",
			SourceIP:        testutils.StringPtr("192.168.1.1"),
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
			Policies: &v1.FlowLogPolicy{
				AllPolicies:      []string{"1|allow-tigera|allow-tigera.cluster-dns|allow|1"},
				EnforcedPolicies: []string{"1|allow-tigera|allow-tigera.cluster-dns|allow|1"},
				PendingPolicies:  []string{"1|allow-tigera|allow-tigera.cluster-dns|allow|1"},
				TransitPolicies:  []string{"1|allow-tigera|allow-tigera.cluster-dns|allow|1"},
			},
		}

		fl2 := v1.FlowLog{
			StartTime:       nowUnix,
			EndTime:         nowUnix,
			SourceType:      "wep",
			DestType:        "wep",
			SourceNamespace: "test",
			DestNamespace:   "kube-system",
			DestNameAggr:    "kube-dns-*",
			DestIP:          testutils.StringPtr("10.0.0.10"),
			DestPort:        testutils.Int64Ptr(53),
			Protocol:        "tcp",
			SourceNameAggr:  "test-pod",
			SourceIP:        testutils.StringPtr("192.168.1.2"),
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
			Policies: &v1.FlowLogPolicy{
				AllPolicies:      []string{"1|custom-tier|custom-tier.my-policy|deny|1"},
				EnforcedPolicies: []string{"1|custom-tier|custom-tier.my-policy|deny|1"},
				PendingPolicies:  []string{"1|custom-tier|custom-tier.my-policy|deny|1"},
				TransitPolicies:  []string{"1|custom-tier|custom-tier.my-policy|deny|1"},
			},
		}

		logs := []v1.FlowLog{fl1, fl1, fl2}
		response, err := flb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		// Count with tier match
		opts := v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				PolicyMatches: []v1.PolicyMatch{
					{
						Tier: "allow-tigera",
					},
				},
			},
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(2), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		// Count with different tier match
		opts.PolicyMatches = []v1.PolicyMatch{
			{
				Tier: "custom-tier",
			},
		}
		countResp, err = flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(1), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)
	})

	RunAllModes(t, "should return correct count across multiple clusters", func(t *testing.T) {
		tenant := backendutils.RandomTenantName()
		cluster1Info := bapi.ClusterInfo{Cluster: cluster1, Tenant: tenant}
		cluster2Info := bapi.ClusterInfo{Cluster: cluster2, Tenant: tenant}
		cluster3Info := bapi.ClusterInfo{Cluster: cluster3, Tenant: tenant}

		// Create flow logs in each cluster
		f := v1.FlowLog{
			StartTime:       time.Now().Unix(),
			EndTime:         time.Now().Unix(),
			SourceType:      "wep",
			DestType:        "wep",
			DestNamespace:   "kube-system",
			DestNameAggr:    "kube-dns-*",
			DestIP:          testutils.StringPtr("10.0.0.1"),
			SourceIP:        testutils.StringPtr("192.168.1.1"),
			Protocol:        "udp",
			DestPort:        testutils.Int64Ptr(53),
			SourceNamespace: "default",
			SourceNameAggr:  "my-deployment",
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		// 2 logs in cluster1, 3 in cluster2, 1 in cluster3
		for i, info := range []struct {
			cluster bapi.ClusterInfo
			num     int
		}{
			{cluster1Info, 2},
			{cluster2Info, 3},
			{cluster3Info, 1},
		} {
			logs := make([]v1.FlowLog, info.num)
			for j := 0; j < info.num; j++ {
				logs[j] = f
			}
			response, err := flb.Create(ctx, info.cluster, logs)
			require.NoError(t, err, "cluster %d", i)
			require.Equal(t, []v1.BulkError(nil), response.Errors)
			require.Equal(t, 0, response.Failed)

			err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(info.cluster))
			require.NoError(t, err)
		}

		opts := v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			},
			CountType: v1.CountTypeGlobal,
		}

		// Count single cluster
		countResp, err := flb.Count(ctx, cluster1Info, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(2), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		// Count multiple clusters
		opts.SetClusters([]string{cluster2, cluster3})
		countResp, err = flb.Count(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(4), *countResp.GlobalCount) // 3 + 1
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		// Count all clusters
		opts.SetAllClusters(true)
		countResp, err = flb.Count(ctx, bapi.ClusterInfo{Cluster: v1.QueryMultipleClusters, Tenant: tenant}, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(6), *countResp.GlobalCount) // 2 + 3 + 1
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)
	})

	RunAllModes(t, "should correctly filter by time range", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create flow logs with specific timestamps spread across a 30-minute period
		// Base time: 2024-01-01 12:00:00
		timeFromHourMin := func(hour, min int) time.Time {
			return time.Date(2025, 1, 1, hour, min, 0, 0, time.UTC)
		}

		// Create logs at: 12:00, 12:05, 12:10, 12:15, 12:20, 12:25, 12:30
		logs := []v1.FlowLog{}
		for i := 0; i < 7; i++ {
			timestamp := timeFromHourMin(12, i*5)
			logs = append(logs, v1.FlowLog{
				StartTime:       timestamp.Unix(),
				EndTime:         timestamp.Unix(),
				SourceType:      "wep",
				DestType:        "wep",
				SourceNamespace: "default",
				DestNamespace:   "kube-system",
				DestNameAggr:    "test-pod",
				DestIP:          testutils.StringPtr("10.0.0.1"),
				SourceIP:        testutils.StringPtr("192.168.1.1"),
				Protocol:        "tcp",
				DestPort:        testutils.Int64Ptr(80),
				SourceNameAggr:  "source-pod",
				ProcessName:     "-",
				Reporter:        "src",
				Action:          "allowed",
			})
		}

		response, err := flb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		opts := v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: timeFromHourMin(11, 0),
						To:   timeFromHourMin(13, 0),
					},
				},
			},
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(7), *countResp.GlobalCount, "should count all logs in a larger time range")
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		// Our time range queries are exclusive of the first time instant (> from, <= to)
		opts.TimeRange = &lmav1.TimeRange{
			From: timeFromHourMin(12, 0),
			To:   timeFromHourMin(12, 30),
		}
		countResp, err = flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(6), *countResp.GlobalCount, "should count all logs except first when using exact time range")
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		opts.TimeRange = &lmav1.TimeRange{
			From: timeFromHourMin(12, 7),
			To:   timeFromHourMin(12, 23),
		}
		countResp, err = flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(3), *countResp.GlobalCount, "should count logs in middle portion")
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		opts.TimeRange = &lmav1.TimeRange{
			From: timeFromHourMin(11, 0),
			To:   timeFromHourMin(11, 30),
		}
		countResp, err = flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(0), *countResp.GlobalCount, "should count zero logs before time range")
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)

		opts.TimeRange = &lmav1.TimeRange{
			From: timeFromHourMin(13, 0),
			To:   timeFromHourMin(13, 30),
		}
		countResp, err = flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(0), *countResp.GlobalCount, "should count zero logs after time range")
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)
	})

	RunAllModes(t, "should handle empty result set", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Don't create any logs, just count
		opts := v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
			},
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, &opts)
		require.NoError(t, err)
		require.NotNil(t, countResp.GlobalCount)
		require.Equal(t, int64(0), *countResp.GlobalCount)
		require.Nil(t, countResp.NamespacedCounts)
		require.False(t, countResp.GlobalCountTruncated)
	})

	RunAllModes(t, "should error with no cluster ID", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{}
		opts := &v1.FlowLogCountParams{
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, opts)
		require.Error(t, err)
		require.Nil(t, countResp)
	})

	RunAllModes(t, "should error with invalid selector", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{Cluster: cluster1}
		opts := &v1.FlowLogCountParams{
			FlowLogParams: v1.FlowLogParams{
				QueryParams: v1.QueryParams{
					TimeRange: &lmav1.TimeRange{
						From: time.Now().Add(-5 * time.Minute),
						To:   time.Now().Add(5 * time.Minute),
					},
				},
				LogSelectionParams: v1.LogSelectionParams{
					Selector: "invalid selector syntax !!!",
				},
			},
			CountType: v1.CountTypeGlobal,
		}
		countResp, err := flb.Count(ctx, clusterInfo, opts)
		require.Error(t, err)
		require.Nil(t, countResp)
	})

	RunAllModes(t, "should return namespaced counts with different CountTypes", func(t *testing.T) {
		clusterInfo := bapi.ClusterInfo{
			Cluster: cluster1,
			Tenant:  backendutils.RandomTenantName(),
		}

		// Create flow logs with various namespace combinations to test namespace counting.
		// This setup creates 5 logs with the following namespace distribution:
		// Note: Namespace counting includes both source and dest (unless source==dest)
		// - default: appears in 3 logs (3 as source: log1,log2,log5)
		// - kube-system: appears in 4 logs (1 as source: log3; 3 as dest: log1,log2,log5)
		// - production: appears in 2 logs (2 as source: log3,log4; 1 as dest: log3; log4 is intra-namespace)
		nowUnix := time.Now().Unix()

		log1 := v1.FlowLog{
			StartTime:       nowUnix,
			EndTime:         nowUnix,
			SourceType:      "wep",
			DestType:        "wep",
			SourceNamespace: "default",
			DestNamespace:   "kube-system",
			SourceNameAggr:  "app1",
			DestNameAggr:    "app2",
			DestIP:          testutils.StringPtr("10.0.0.1"),
			SourceIP:        testutils.StringPtr("192.168.1.1"),
			Protocol:        "tcp",
			DestPort:        testutils.Int64Ptr(80),
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		log2 := v1.FlowLog{
			StartTime:       nowUnix,
			EndTime:         nowUnix,
			SourceType:      "wep",
			DestType:        "wep",
			SourceNamespace: "default",
			DestNamespace:   "kube-system",
			SourceNameAggr:  "app1",
			DestNameAggr:    "app3",
			DestIP:          testutils.StringPtr("10.0.0.2"),
			SourceIP:        testutils.StringPtr("192.168.1.2"),
			Protocol:        "tcp",
			DestPort:        testutils.Int64Ptr(443),
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		log3 := v1.FlowLog{
			StartTime:       nowUnix,
			EndTime:         nowUnix,
			SourceType:      "wep",
			DestType:        "wep",
			SourceNamespace: "kube-system",
			DestNamespace:   "production",
			SourceNameAggr:  "dns",
			DestNameAggr:    "database",
			DestIP:          testutils.StringPtr("10.0.0.3"),
			SourceIP:        testutils.StringPtr("192.168.1.3"),
			Protocol:        "tcp",
			DestPort:        testutils.Int64Ptr(5432),
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		log4 := v1.FlowLog{
			StartTime:       nowUnix,
			EndTime:         nowUnix,
			SourceType:      "wep",
			DestType:        "wep",
			SourceNamespace: "production",
			DestNamespace:   "production", // Intra-namespace communication
			SourceNameAggr:  "api",
			DestNameAggr:    "database",
			DestIP:          testutils.StringPtr("10.0.0.4"),
			SourceIP:        testutils.StringPtr("192.168.1.4"),
			Protocol:        "tcp",
			DestPort:        testutils.Int64Ptr(8080),
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		log5 := v1.FlowLog{
			StartTime:       nowUnix,
			EndTime:         nowUnix,
			SourceType:      "wep",
			DestType:        "wep",
			SourceNamespace: "default",
			DestNamespace:   "kube-system",
			SourceNameAggr:  "app4",
			DestNameAggr:    "app5",
			DestIP:          testutils.StringPtr("10.0.0.5"),
			SourceIP:        testutils.StringPtr("192.168.1.5"),
			Protocol:        "tcp",
			DestPort:        testutils.Int64Ptr(9000),
			ProcessName:     "-",
			Reporter:        "src",
			Action:          "allowed",
		}

		logs := []v1.FlowLog{log1, log2, log3, log4, log5}
		response, err := flb.Create(ctx, clusterInfo, logs)
		require.NoError(t, err)
		require.Equal(t, []v1.BulkError(nil), response.Errors)
		require.Equal(t, 0, response.Failed)

		err = backendutils.RefreshIndex(ctx, client, indexGetter.Index(clusterInfo))
		require.NoError(t, err)

		flowLogParams := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Minute),
					To:   time.Now().Add(5 * time.Minute),
				},
				// Set page size to 2 to ensure pagination occurs during namespace counting
				MaxPageSize: 2,
			},
		}

		t.Run("CountType=Namespaced should return only namespaced counts", func(t *testing.T) {
			opts := v1.FlowLogCountParams{
				FlowLogParams: flowLogParams,
				CountType:     v1.CountTypeNamespaced,
			}

			countResp, err := flb.Count(ctx, clusterInfo, &opts)
			require.NoError(t, err)

			// GlobalCount should be nil when CountType is Namespaced
			require.Nil(t, countResp.GlobalCount)
			require.False(t, countResp.GlobalCountTruncated)

			// Verify namespaced counts
			require.NotNil(t, countResp.NamespacedCounts)
			require.Equal(t, int64(3), countResp.NamespacedCounts["default"])
			require.Equal(t, int64(4), countResp.NamespacedCounts["kube-system"])
			require.Equal(t, int64(2), countResp.NamespacedCounts["production"])
		})

		t.Run("CountType=GlobalAndNamespaced should return both global and namespaced counts", func(t *testing.T) {
			opts := v1.FlowLogCountParams{
				FlowLogParams: flowLogParams,
				CountType:     v1.CountTypeGlobalAndNamespaced,
			}

			countResp, err := flb.Count(ctx, clusterInfo, &opts)
			require.NoError(t, err)

			// GlobalCount should be set to the total number of flow logs
			require.NotNil(t, countResp.GlobalCount)
			require.Equal(t, int64(5), *countResp.GlobalCount)
			require.False(t, countResp.GlobalCountTruncated)

			// Verify namespaced counts match those from the Namespaced-only test
			require.NotNil(t, countResp.NamespacedCounts)
			require.Equal(t, int64(3), countResp.NamespacedCounts["default"])
			require.Equal(t, int64(4), countResp.NamespacedCounts["kube-system"])
			require.Equal(t, int64(2), countResp.NamespacedCounts["production"])
		})
	})
}
