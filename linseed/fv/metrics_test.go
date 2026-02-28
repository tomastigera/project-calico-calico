// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

// metricsSetupAndTeardown sets up additional test environment for the metrics tests.
func metricsSetupAndTeardown(t *testing.T) func() {
	// Get the token to use in HTTP authorization header.
	var err error
	token, err = os.ReadFile(TokenPath)
	require.NoError(t, err)
	return func() {
	}
}

func TestMetrics(t *testing.T) {
	metricsAddr := "localhost:9095"

	RunDNSLogTest(t, "should provide a metrics endpoint", func(t *testing.T, idx bapi.Index) {
		defer metricsSetupAndTeardown(t)()

		client := mTLSClient(t)
		httpReqSpec := noBodyHTTPReqSpec("GET", fmt.Sprintf("https://%s/metrics", metricsAddr), "", "", token)
		res, _ := doRequest(t, client, httpReqSpec)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})

	RunDNSLogTest(t, "should create metrics based on the requests made", func(t *testing.T, idx bapi.Index) {
		defer metricsSetupAndTeardown(t)()
		cluster := cluster1
		clusterInfo := cluster1Info

		// Create a basic dns log.
		logs := []v1.DNSLog{
			{
				EndTime: time.Now().UTC(),
				QName:   "service.namespace.svc.cluster.local",
				QClass:  v1.DNSClass(layers.DNSClassIN),
				QType:   v1.DNSType(layers.DNSTypeAAAA),
				RCode:   v1.DNSResponseCode(layers.DNSResponseCodeNXDomain),
				RRSets:  v1.DNSRRSets{},
			},
		}
		bulk, err := cli.DNSLogs(cluster).Create(ctx, logs)
		require.NoError(t, err)
		require.Equal(t, bulk.Succeeded, 1, "create dns log did not succeed")

		// Refresh elasticsearch so that results appear.
		err = testutils.RefreshIndex(ctx, lmaClient, idx.Index(clusterInfo))
		require.NoError(t, err)

		// Read it back.
		params := v1.DNSLogParams{
			QueryParams: v1.QueryParams{
				TimeRange: &lmav1.TimeRange{
					From: time.Now().Add(-5 * time.Second),
					To:   time.Now().Add(5 * time.Second),
				},
			},
		}
		resp, err := cli.DNSLogs(cluster).List(ctx, &params)
		require.NoError(t, err)
		require.NotNil(t, resp)
		for i := range resp.Items {
			testutils.AssertDNSLogIDAndClusterAndReset(t, cluster, &resp.Items[i])
		}
		require.Equal(t, logs, resp.Items)

		client := mTLSClient(t)
		httpReqSpec := noBodyHTTPReqSpec("GET", fmt.Sprintf("https://%s/metrics", metricsAddr), "", "", token)
		res, body := doRequest(t, client, httpReqSpec)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		// Check application metrics used for billing
		bytesWritten, err := json.Marshal(logs)
		require.NoError(t, err)
		bytesRead, err := json.Marshal(params)
		require.NoError(t, err)
		bytesReadMetric := fmt.Sprintf(`tigera_linseed_bytes_read{cluster_id="%s",tenant_id="tenant-a"} %d`, cluster, len(bytesRead))
		bytesWrittenMetric := fmt.Sprintf(`tigera_linseed_bytes_written{cluster_id="%s",tenant_id="tenant-a"}`, cluster)
		require.Contains(t, string(body), bytesReadMetric, fmt.Sprintf("missing %s from %s", bytesReadMetric, string(body)))
		require.Contains(t, string(body), bytesWrittenMetric, fmt.Sprintf("missing %s from %s", bytesWrittenMetric, string(body)))

		metric := regexp.MustCompile(fmt.Sprintf("%s [\\d]+", bytesWrittenMetric)).Find(body)
		value, err := strconv.Atoi(string(regexp.MustCompile("[1-9][0-9]*").Find(metric)))
		require.NoError(t, err)

		require.InDeltaf(t, len(bytesWritten), value, 3, fmt.Sprintf("expecting %d to be in range of %d", len(bytesWritten), value))
	})
}
