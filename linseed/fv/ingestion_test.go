// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/goldmane/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// ingestionSetupAndTeardown performs additional setup and teardown for ingestion tests.
func ingestionSetupAndTeardown(t *testing.T, idx bapi.Index) func() {
	// Get the token to use in HTTP authorization header.
	var err error
	token, err = os.ReadFile(TokenPath)
	require.NoError(t, err)
	return func() {
	}
}

func TestFV_FlowIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/flows/logs/bulk"
	expectedResponse := `{"failed":0, "succeeded":25, "total":25}`

	RunFlowLogTest(t, "ingest flow logs via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(flowLogs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(1675468688, 0),
					To:   time.Unix(1675469001, 0),
				},
			},
		}

		resultList, err := cli.FlowLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(25), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertFlowLogIDAndClusterAndReset(t, cluster, &log)
			logStr, err := json.Marshal(log)
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		assert.Equal(t, flowLogs, strings.Join(esLogs, "\n"))
	})
}

func TestFV_FlowIngestionTruncatedLogs(t *testing.T) {
	addr := "https://localhost:8443/api/v1/flows/logs/bulk"
	// 26 total lines: 1 malformed + 25 valid, so 1 failed and 25 succeeded
	expectedResponse := `{"failed":1, "succeeded":25, "total":26}`

	RunFlowLogTest(t, "ingest flow logs skipping malformed lines", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(truncatedFlowLogs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(1675468688, 0),
					To:   time.Unix(1675469001, 0),
				},
			},
		}

		resultList, err := cli.FlowLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		// Only the 25 valid flow logs should have been ingested.
		require.Equal(t, int64(25), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertFlowLogIDAndClusterAndReset(t, cluster, &log)
			logStr, err := json.Marshal(log)
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		// truncatedFlowLogs is the same 25 flow logs as flowLogs with one malformed
		// line prepended, so the ingested valid logs should match exactly.
		assert.Equal(t, flowLogs, strings.Join(esLogs, "\n"))
	})
}

func TestFV_DNSIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/dns/logs/bulk"
	expectedResponse := `{"failed":0, "succeeded":11, "total":11}`

	RunDNSLogTest(t, "ingest dns logs via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(dnsLogs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		endTime, err := time.Parse(time.RFC3339Nano, "2023-02-22T23:54:02.736970074Z")
		require.NoError(t, err)
		startTime, err := time.Parse(time.RFC3339Nano, "2023-02-10T01:11:46.413467767Z")
		require.NoError(t, err)

		params := v1.DNSLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   endTime,
				},
			},
		}

		resultList, err := cli.DNSLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(11), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertDNSLogIDAndClusterAndReset(t, cluster, &log)
			logStr, err := json.Marshal(log)
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		assert.Equal(t, dnsLogs, strings.Join(esLogs, "\n"))
	})
}

func TestFV_L7Ingestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/l7/logs/bulk"
	expectedResponse := `{"failed":0, "succeeded":15, "total":15}`

	RunL7LogTest(t, "ingest l7 logs via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(l7Logs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.L7LogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(1676062496, 0),
					To:   time.Unix(1676067134, 0),
				},
			},
		}

		resultList, err := cli.L7Logs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(15), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertL7LogClusterAndReset(t, cluster, &log)
			testutils.AssertGeneratedTimeAndReset(t, &log)
			logStr, err := json.Marshal(log)
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		assert.Equal(t, l7Logs, strings.Join(esLogs, "\n"))
	})

	RunL7LogTest(t, "ingest l7 logs with gateway collector fields via bulk API", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(l7LogsGatewayCollector))

		// make the request to ingest gateway collector logs
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		expectedResponse := `{"failed":0, "succeeded":4, "total":4}`
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.L7LogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(1732464722, 0),
					To:   time.Unix(1732464902, 0),
				},
			},
		}

		resultList, err := cli.L7Logs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(3), resultList.TotalHits)

		// Verify that the new gateway collector fields are present in the results
		for i, log := range resultList.Items {
			testutils.AssertL7LogClusterAndReset(t, cluster, &log)
			testutils.AssertGeneratedTimeAndReset(t, &log)

			// Verify new collector fields are present
			require.Equal(t, "gateway-collector", log.CollectorName, "CollectorName should be set")
			require.NotEmpty(t, log.CollectorType, "CollectorType should be set")
			require.NotEmpty(t, log.GatewayNamespace, "GatewayNamespace should be set")
			require.NotEmpty(t, log.GatewayClass, "GatewayClass should be set")

			// Verify new gateway listener fields
			require.NotEmpty(t, log.GatewayListenerFullName, "GatewayListenerFullName should be set")
			require.NotEmpty(t, log.GatewayListenerHostname, "GatewayListenerHostname should be set")

			// Verify new unified gateway route fields
			require.NotEmpty(t, log.GatewayRouteName, "GatewayRouteName should be set")
			require.NotEmpty(t, log.GatewayRouteNamespace, "GatewayRouteNamespace should be set")
			require.NotEmpty(t, log.GatewayRouteStatus, "GatewayRouteStatus should be set")

			if i < 2 {
				// First two logs are HTTP routes
				require.Equal(t, "http", log.GatewayRouteType, "GatewayRouteType should be 'http' for HTTP routes")
			} else {
				// Third log is a GRPC route
				require.Equal(t, "grpc", log.GatewayRouteType, "GatewayRouteType should be 'grpc' for GRPC routes")
			}

			logStr, err := json.Marshal(log)
			require.NoError(t, err)
			require.NotEmpty(t, string(logStr))
		}
	})
}

func TestFV_KubeAuditIngestion(t *testing.T) {
	cluster := cluster1
	clusterInfo := cluster1Info
	addr := "https://localhost:8443/api/v1/audit/logs/kube/bulk"
	expectedResponse := `{"failed":0, "succeeded":32, "total":32}`

	RunAuditKubeTest(t, "ingest kube audit logs via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(kubeAuditLogs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		startTime, err := time.Parse(time.RFC3339, "2023-02-10T01:15:20.855601Z")
		require.NoError(t, err)
		endTime, err := time.Parse(time.RFC3339, "2023-02-14T00:08:47.590948Z")
		require.NoError(t, err)
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   endTime,
				},
			},
			Type: v1.AuditLogTypeKube,
		}

		resultList, err := cli.AuditLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)
		require.Equal(t, 32, len(resultList.Items))
		require.Equal(t, int64(32), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertAuditLogClusterAndReset(t, cluster, &log)
			testutils.AssertGeneratedTimeAndReset(t, &log)
			logStr, err := log.MarshalJSON()
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		assert.Equal(t, kubeAuditLogs, strings.Join(esLogs, "\n"))
	})
}

func TestFV_EEAuditIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/audit/logs/ee/bulk"
	expectedResponse := `{"failed":0, "succeeded":35, "total":35}`

	RunAuditEETest(t, "ingest ee audit logs via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(eeAuditLogs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		startTime, err := time.Parse(time.RFC3339, "2023-02-10T21:40:58.476376Z")
		require.NoError(t, err)
		endTime, err := time.Parse(time.RFC3339, "2023-02-10T21:42:03.168059Z")
		require.NoError(t, err)
		params := v1.AuditLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   endTime,
				},
			},
			Type: v1.AuditLogTypeEE,
		}

		resultList, err := cli.AuditLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(35), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertAuditLogClusterAndReset(t, cluster, &log)
			testutils.AssertGeneratedTimeAndReset(t, &log)
			logStr, err := log.MarshalJSON()
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		assert.Equal(t, eeAuditLogs, strings.Join(esLogs, "\n"))
	})
}

func TestFV_BGPIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/bgp/logs/bulk"
	expectedResponse := `{"failed":0, "succeeded":4, "total":4}`

	RunBGPLogTest(t, "ingest bgp logs via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(bgpLogs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		startTime, err := time.Parse(v1.BGPLogTimeFormat, "2023-02-23T00:10:46")
		require.NoError(t, err)
		endTime, err := time.Parse(v1.BGPLogTimeFormat, "2023-02-23T00:15:46")
		require.NoError(t, err)
		params := v1.BGPLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   endTime,
				},
			},
		}

		resultList, err := cli.BGPLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(4), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertBGPLogClusterAndReset(t, cluster, &log)
			testutils.AssertGeneratedTimeAndReset(t, &log)
			buffer := &bytes.Buffer{}
			encoder := json.NewEncoder(buffer)
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(log)
			require.NoError(t, err)
			esLogs = append(esLogs, strings.Trim(buffer.String(), "\n"))
		}

		assert.Equal(t, bgpLogs, strings.Join(esLogs, "\n"))
	})
}

func TestFV_WAFIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/waf/logs/bulk"
	expectedResponse := `{"failed":0, "succeeded":2, "total":2}`

	RunWAFTest(t, "ingest waf logs via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(wafLogs))

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		endTime, err := time.Parse(time.RFC3339Nano, "2023-06-22T23:59:59.999999999Z")
		require.NoError(t, err)
		startTime, err := time.Parse(time.RFC3339Nano, "2022-02-11T00:00:00.000000000Z")
		require.NoError(t, err)

		params := v1.WAFLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   endTime,
				},
			},
		}

		resultList, err := cli.WAFLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(2), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			testutils.AssertWAFLogClusterAndReset(t, cluster, &log)
			testutils.AssertGeneratedTimeAndReset(t, &log)
			// testutils.AssertWAFLogGeneratedTimeAndReset(t, &log)
			logStr, err := json.Marshal(log)
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		assert.Equal(t, wafLogs, strings.Join(esLogs, "\n"))
	})
}

func TestFV_GoldmaneFlowIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/flows/bulk"
	expectedResponse := `{"failed":0, "succeeded":1, "total":1}`

	flo := &proto.Flow{
		Key: &proto.FlowKey{
			SourceName:      "sourcename",
			SourceNamespace: "sourcenamespace",
			SourceType:      proto.EndpointType_WorkloadEndpoint,
			DestName:        "destname",
			DestNamespace:   "destnamespace",
			DestType:        proto.EndpointType_WorkloadEndpoint,
			Reporter:        proto.Reporter_Src,
			Action:          proto.Action_Allow,
			DestServiceName: "destservice",
			DestServicePort: int64(80),
			DestPort:        int64(80),
			Proto:           "14",
			Policies: &proto.PolicyTrace{
				EnforcedPolicies: []*proto.PolicyHit{
					{
						Kind:        proto.PolicyKind_AdminNetworkPolicy,
						Name:        "pol",
						Tier:        "tier",
						Action:      proto.Action_Allow,
						PolicyIndex: 1,
						RuleIndex:   1,
					},
					{
						Kind:        proto.PolicyKind_Profile,
						Name:        "kns.calico-system",
						Tier:        "",
						Action:      proto.Action_Allow,
						PolicyIndex: 0,
						RuleIndex:   1,
					},
				},
				PendingPolicies: []*proto.PolicyHit{
					{
						Kind:   proto.PolicyKind_AdminNetworkPolicy,
						Name:   "pol",
						Tier:   "tier",
						Action: proto.Action_Allow,
					},
				},
			},
		},
		BytesIn:                 int64(100),
		BytesOut:                int64(100),
		PacketsIn:               int64(10),
		PacketsOut:              int64(10),
		NumConnectionsStarted:   int64(1),
		NumConnectionsCompleted: int64(1),
		NumConnectionsLive:      int64(1),
		StartTime:               100,
		EndTime:                 115,
	}

	RunFlowLogTest(t, "ingest Goldmane flow logs via bulk API", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		b, err := json.Marshal(flo)
		require.NoError(t, err)

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, b)

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// send a few more.
		for range 10 {
			res, resBody = doRequest(t, httpClient, spec)
			assert.Equal(t, http.StatusOK, res.StatusCode)
			assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))
		}

		// Force a refresh in order to read the newly ingested data
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		params := v1.FlowLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(0, 0),
					To:   time.Unix(1675469001, 0),
				},
			},
		}

		resultList, err := cli.FlowLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)
		require.Equal(t, int64(11), resultList.TotalHits)
		require.NotNil(t, resultList.Items[0].Policies)
		require.Len(t, resultList.Items[0].Policies.EnforcedPolicies, 2)
		require.Len(t, resultList.Items[0].Policies.PendingPolicies, 1)

		// We should be able to make a Flows request as well and get the same data.
		flowParams := v1.L3FlowParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Unix(0, 0),
					To:   time.Unix(1675469001, 0),
				},
			},
		}
		flows, err := cli.L3Flows(cluster).List(ctx, &flowParams)
		require.NoError(t, err)
		require.Equal(t, 1, len(flows.Items))
		require.Equal(t, 2, len(flows.Items[0].EnforcedPolicies))
		require.Equal(t, 1, len(flows.Items[0].PendingPolicies))
	})
}

func TestFV_RuntimeIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/runtime/reports/bulk"
	expectedResponse := `{"failed":0, "succeeded":29, "total":29}`

	RunRuntimeReportTest(t, "ingest runtime reports via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(runtimeReports))

		// make the request to ingest runtime reports
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		endTime, err := time.Parse(time.RFC3339Nano, "2023-03-14T01:40:59.401474246Z")
		require.NoError(t, err)
		startTime, err := time.Parse(time.RFC3339Nano, "2023-03-14T01:39:41.654053441Z")
		require.NoError(t, err)

		params := v1.RuntimeReportParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   endTime,
				},
			},
		}

		resultList, err := cli.RuntimeReports(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(29), resultList.TotalHits)

		var esLogs []string
		for _, log := range resultList.Items {
			// Null out the GeneratedTime field.  Linseed will have populated this - and
			// the following line verifies that - but we can't predict the exact value
			// and hence our runtimeReports fixture does not include it.
			require.NotNil(t, log.Report.GeneratedTime)
			testutils.AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t, cluster, &log)
			logStr, err := json.Marshal(log.Report)
			require.NoError(t, err)
			esLogs = append(esLogs, string(logStr))
		}

		assert.Equal(t, runtimeReports, strings.Join(esLogs, "\n"))
	})
}

func TestFV_Ingestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/audit/logs/ee/bulk"
	expectedResponse := `{"Msg":"http: request body too large", "Status":400}`

	RunAuditEETest(t, "cannot ingest arequest bigger than 2Gb", func(t *testing.T, idx bapi.Index) {
		t.Skip()

		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		// setup HTTP httpClient and HTTP request
		httpClient := mTLSClient(t)
		var largeBody []byte
		for float64(len(largeBody)) < 2*1024*1024*1024+10 {
			largeBody = append(largeBody, []byte(eeAuditLogs)...)
		}

		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, largeBody)

		// make the request to ingest flows
		res, resBody := doRequest(t, httpClient, spec)
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		assert.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))
	})
}

func TestFV_AnomalyDetectionEventsIngestion(t *testing.T) {
	addr := "https://localhost:8443/api/v1/events/bulk"
	expectedResponse := `{"failed":0, "succeeded":1, "total":1}`

	RunEventsTest(t, "ingest anomaly detection events via bulk API with production data", func(t *testing.T, idx bapi.Index) {
		defer ingestionSetupAndTeardown(t, idx)()

		cluster := cluster1
		clusterInfo := cluster1Info

		spec := xndJSONPostHTTPReqSpec(addr, clusterInfo.Tenant, cluster, token, []byte(anomalyDetectionEvent))
		httpClient := mTLSClient(t)

		// make the request to ingest anomaly detection alerts
		res, resBody := doRequest(t, httpClient, spec)
		require.Equal(t, http.StatusOK, res.StatusCode)
		require.JSONEq(t, expectedResponse, strings.Trim(string(resBody), "\n"))

		// Force a refresh in order to read the newly ingested data
		err := testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		endTime, err := time.Parse(time.RFC3339, "2023-04-28T19:38:14+00:00")
		require.NoError(t, err)
		startTime, err := time.Parse(time.RFC3339, "2023-04-28T19:37:14+00:00")
		require.NoError(t, err)

		params := v1.EventParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: startTime,
					To:   endTime,
				},
			},
		}

		resultList, err := cli.Events(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resultList)

		require.Equal(t, int64(1), resultList.TotalHits)
		expectedEvent := v1.Event{}
		err = json.Unmarshal([]byte(anomalyDetectionEvent), &expectedEvent)
		require.NoError(t, err)
		assert.Equal(t, []v1.Event{expectedEvent}, testutils.AssertEventsIDAndClusterAndGeneratedTimeAndReset(t, cluster, resultList))
	})
}
