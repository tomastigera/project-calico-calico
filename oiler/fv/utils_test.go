// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package fv

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/apis/audit"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/api"
	backendutils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/list"
	"github.com/projectcalico/calico/oiler/pkg/checkpoint"
	"github.com/projectcalico/calico/oiler/pkg/migrator"
)

const (
	lastGeneratedReadMetric    = `tigera_oiler_last_read_generated_timestamp{cluster_id="%s",job_name="%s"}`
	lastGeneratedWrittenMetric = `tigera_oiler_last_written_generated_timestamp{cluster_id="%s",job_name="%s"}`
	docsReadMetric             = `tigera_oiler_docs_read{cluster_id="%s",job_name="%s",source="primary",tenant_id="%s"}`
	docsWrittenMetric          = `tigera_oiler_docs_writes_successful{cluster_id="%s",job_name="%s",source="secondary",tenant_id="%s"}`
	eNotationFloatingPoint     = "[-+]?[0-9]*\\.?[0-9]+([eE][-+]?[0-9]+)?"
)

func readMetrics(t *testing.T, port int) []byte {
	var err error
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", port))
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return body
}

func getValue(t *testing.T, allMetrics []byte, name string) float64 {
	// Metrics have the following format `name{label="abc} 1.2e+1`
	metric := regexp.MustCompile(fmt.Sprintf("%s [0-9+-eE.]+", name)).Find(allMetrics)
	valStr := string(regexp.MustCompile(eNotationFloatingPoint).Find(metric))
	require.NotEmpty(t, valStr)
	value, err := strconv.ParseFloat(valStr, 64)
	require.NoError(t, err)
	return value
}

func validateMetrics(t *testing.T, jobName string, primary api.ClusterInfo, secondary api.ClusterInfo, numberOfLogs, last int64, port int) {
	metrics := readMetrics(t, port)

	lastGeneratedRead := getValue(t, metrics, fmt.Sprintf(lastGeneratedReadMetric, primary.Cluster, jobName))
	lastGeneratedWritten := getValue(t, metrics, fmt.Sprintf(lastGeneratedWrittenMetric, primary.Cluster, jobName))
	docsRead := getValue(t, metrics, fmt.Sprintf(docsReadMetric, primary.Cluster, jobName, primary.Tenant))
	docsWritten := getValue(t, metrics, fmt.Sprintf(docsWrittenMetric, secondary.Cluster, jobName, secondary.Tenant))

	require.Equal(t, float64(numberOfLogs), docsRead)
	require.Equal(t, float64(numberOfLogs), docsWritten)
	require.Equal(t, float64(last), lastGeneratedRead)
	require.InDelta(t, float64(last), lastGeneratedWritten, 5000)
}

func cleanUpData(t *testing.T, idx api.Index, clusters ...api.ClusterInfo) {
	for _, clusterInfo := range clusters {
		err := backendutils.CleanupIndices(context.Background(), esClient.Backend(), idx.IsSingleIndex(), idx, clusterInfo)
		require.NoError(t, err)
	}
}

func validateCheckpoints(t *testing.T, dataType api.DataType, primary api.ClusterInfo, last time.Time) {
	configMapName := checkpoint.ConfigMapName(dataType, primary.Cluster, primary.Tenant)
	configMap, err := k8sClient.CoreV1().ConfigMaps("default").Get(ctx, configMapName, metav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, configMap)
	require.NotNil(t, configMap.Data)
	require.NotEmpty(t, configMap.Labels)
	require.Contains(t, configMap.Labels, "generated-by")
	require.Equal(t, configMap.Labels["generated-by"], "oiler")
	lastCheckpoint, ok := configMap.Data["checkpoint"]
	require.True(t, ok)
	val, err := time.Parse(time.RFC3339, lastCheckpoint)
	require.NoError(t, err)
	require.InDelta(t, last.UnixMilli(), val.UnixMilli(), 1000)
}

func cleanUpCheckPoints(dataType api.DataType, primaries ...api.ClusterInfo) {
	for _, primary := range primaries {
		configMapName := checkpoint.ConfigMapName(dataType, primary.Cluster, primary.Tenant)
		err := k8sClient.CoreV1().ConfigMaps("default").Delete(ctx, configMapName, metav1.DeleteOptions{})
		if err != nil {
			logrus.WithError(err).Warn("Failed to clean up checkpoint configmap")
		}
	}
}

func generateData(t *testing.T, catalogue migrator.BackendCatalogue, numLogs int, dataType api.DataType, clusterInfo api.ClusterInfo) {
	t.Helper()

	var err error
	var response *v1.BulkResponse
	switch dataType {
	case api.FlowLogs:
		var logs []v1.FlowLog
		startTime := time.Now().UTC()
		endTime := startTime.Add(5 * time.Second)
		for i := range numLogs {
			logs = append(logs, v1.FlowLog{
				StartTime: startTime.Unix(),
				EndTime:   endTime.Unix(),
				Host:      fmt.Sprintf("flows-%d", i),
			})
		}
		response, err = catalogue.FlowLogBackend.Create(ctx, clusterInfo, logs)
	case api.AuditEELogs, api.AuditKubeLogs:
		var logs []v1.AuditLog
		startTime := time.Now().UTC()
		for range numLogs {
			logs = append(logs, v1.AuditLog{Event: audit.Event{
				AuditID:                  "any-ee-id",
				RequestReceivedTimestamp: metav1.NewMicroTime(startTime),
			}})
		}
		var auditType v1.AuditLogType
		if dataType == api.AuditEELogs {
			auditType = v1.AuditLogTypeEE
		} else {
			auditType = v1.AuditLogTypeKube
		}
		response, err = catalogue.AuditBackend.Create(ctx, auditType, clusterInfo, logs)
	case api.BGPLogs:
		var logs []v1.BGPLog
		startTime := time.Now().UTC()
		for range numLogs {
			logs = append(logs, v1.BGPLog{LogTime: startTime.Format(v1.BGPLogTimeFormat)})
		}
		response, err = catalogue.BGPBackend.Create(ctx, clusterInfo, logs)
	case api.DNSLogs:
		var logs []v1.DNSLog
		startTime := time.Now().UTC()
		endTime := startTime.Add(5 * time.Second)
		for i := range numLogs {
			logs = append(logs, v1.DNSLog{
				StartTime: startTime,
				EndTime:   endTime,
				Host:      fmt.Sprintf("dns-%d", i)})
		}
		response, err = catalogue.DNSLogBackend.Create(ctx, clusterInfo, logs)
	case api.Benchmarks:
		var logs []v1.Benchmarks
		startTime := time.Now().UTC()
		for range numLogs {
			logs = append(logs, v1.Benchmarks{
				Version:           "v1",
				KubernetesVersion: "v1.0",
				Type:              v1.TypeKubernetes,
				NodeName:          "lodestone",
				Timestamp:         metav1.Time{Time: startTime},
				Error:             "",
				Tests: []v1.BenchmarkTest{
					{
						Section:     "a.1",
						SectionDesc: "testing the test",
						TestNumber:  "1",
						TestDesc:    "making sure that we're right",
						TestInfo:    "information is fluid",
						Status:      "Just swell",
						Scored:      true,
					},
				},
			})
		}
		response, err = catalogue.BenchmarksBackend.Create(ctx, clusterInfo, logs)
	case api.ReportData:
		var logs []v1.ReportData
		startTime := time.Now().UTC()
		for range numLogs {
			logs = append(logs, v1.ReportData{ReportData: &apiv3.ReportData{
				ReportName:     "test-report",
				ReportTypeName: "my-report-type",
				StartTime:      metav1.Time{Time: startTime},
				EndTime:        metav1.Time{Time: startTime.Add(2 * time.Second)},
				GenerationTime: metav1.Time{Time: startTime.Add(3 * time.Second)},
			}})
		}
		response, err = catalogue.ReportsBackend.Create(ctx, clusterInfo, logs)
	case api.Snapshots:
		var logs []v1.Snapshot
		startTime := time.Now().UTC()
		for i := range numLogs {
			logs = append(logs, v1.Snapshot{
				ResourceList: list.TimestampedResourceList{
					ResourceList: &apiv3.NetworkPolicyList{
						TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
						ListMeta: metav1.ListMeta{},
						Items: []apiv3.NetworkPolicy{
							{
								TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
								ObjectMeta: metav1.ObjectMeta{
									Name:      fmt.Sprintf("np-%d", i),
									Namespace: "default",
								},
							},
						},
					},
					RequestStartedTimestamp:   metav1.Time{Time: startTime},
					RequestCompletedTimestamp: metav1.Time{Time: startTime.Add(time.Duration(2*i) * time.Second)},
				},
			})
		}
		response, err = catalogue.SnapshotsBackend.Create(ctx, clusterInfo, logs)
	case api.Events:
		var logs []v1.Event
		startTime := time.Now().UTC()
		for range numLogs {
			logs = append(logs, v1.Event{
				Time:        v1.NewEventTimestamp(startTime.Unix()),
				Description: "A rather uneventful evening",
				Origin:      "TODO",
				Severity:    1,
				Type:        "TODO",
			},
			)
		}
		response, err = catalogue.EventBackend.Create(ctx, clusterInfo, logs)
	case api.L7Logs:
		var logs []v1.L7Log
		startTime := time.Now().UTC()
		for i := range numLogs {
			logs = append(logs, v1.L7Log{
				StartTime: startTime.Unix(),
				EndTime:   startTime.Unix() + int64(i),
				Host:      fmt.Sprintf("l7-%d", i),
			},
			)
		}
		response, err = catalogue.L7LogBackend.Create(ctx, clusterInfo, logs)
	case api.WAFLogs:
		var logs []v1.WAFLog
		startTime := time.Now().UTC()
		for i := range numLogs {
			logs = append(logs, v1.WAFLog{
				Timestamp: startTime.Add(time.Duration(i) * time.Second),
				Host:      fmt.Sprintf("waf-%d", i),
			},
			)
		}
		response, err = catalogue.WAFBackend.Create(ctx, clusterInfo, logs)
	case api.RuntimeReports:
		var logs []v1.Report
		startTime := time.Now().UTC()
		for i := range numLogs {
			logs = append(logs, v1.Report{
				StartTime: startTime,
				EndTime:   startTime.Add(5 * time.Second),
				Host:      fmt.Sprintf("runtime-%d", i),
			},
			)
		}
		response, err = catalogue.RuntimeBackend.Create(ctx, clusterInfo, logs)
	case api.IPSet:
		var logs []v1.IPSetThreatFeed
		startTime := time.Now().UTC()
		for i := range numLogs {
			logs = append(logs, v1.IPSetThreatFeed{
				ID: fmt.Sprintf("feed-a-%d", i),
				Data: &v1.IPSetThreatFeedData{
					CreatedAt: startTime,
					IPs:       []string{"1.2.3.4/32"},
				},
			},
			)
		}
		response, err = catalogue.IPSetBackend.Create(ctx, clusterInfo, logs)
	case api.DomainNameSet:
		var logs []v1.DomainNameSetThreatFeed
		startTime := time.Now().UTC()
		for i := range numLogs {
			logs = append(logs, v1.DomainNameSetThreatFeed{
				ID: fmt.Sprintf("feed-a-%d", i),
				Data: &v1.DomainNameSetThreatFeedData{
					CreatedAt: startTime,
					Domains:   []string{"a.b.c.d"},
				},
			},
			)
		}
		response, err = catalogue.DomainNameSetBackend.Create(ctx, clusterInfo, logs)

	default:
		t.Fatalf("Unsupported data type: %s", dataType)
	}

	require.NoError(t, err)
	require.NotNil(t, response)
	require.Zero(t, response.Failed)
}

func lastGeneratedTimeFromPrimary(t *testing.T, catalogue migrator.BackendCatalogue, dataType api.DataType, primary api.ClusterInfo) time.Time {
	t.Helper()

	switch dataType {
	case api.FlowLogs:
		primaryData, err := catalogue.FlowLogBackend.List(ctx, primary, &v1.FlowLogParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.AuditEELogs:
		primaryData, err := catalogue.AuditBackend.List(ctx, primary, &v1.AuditLogParams{
			QueryParams: queryParams(),
			Type:        v1.AuditLogTypeEE,
			Sort:        sortParams(),
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.AuditKubeLogs:
		primaryData, err := catalogue.AuditBackend.List(ctx, primary, &v1.AuditLogParams{
			QueryParams: queryParams(),
			Type:        v1.AuditLogTypeKube,
			Sort:        sortParams(),
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.BGPLogs:
		primaryData, err := catalogue.BGPBackend.List(ctx, primary, &v1.BGPLogParams{
			QueryParams: queryParams(),
			Sort:        sortParams(),
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.DNSLogs:
		primaryData, err := catalogue.DNSLogBackend.List(ctx, primary, &v1.DNSLogParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.Benchmarks:
		primaryData, err := catalogue.BenchmarksBackend.List(ctx, primary, &v1.BenchmarksParams{
			QueryParams: queryParams(),
			Sort:        sortParams(),
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.ReportData:
		primaryData, err := catalogue.ReportsBackend.List(ctx, primary, &v1.ReportDataParams{
			QueryParams: queryParams(),
			Sort:        sortParams(),
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.Snapshots:
		primaryData, err := catalogue.SnapshotsBackend.List(ctx, primary, &v1.SnapshotParams{
			QueryParams: queryParams(),
			Sort:        sortParams(),
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].ResourceList.GeneratedTime
		return expected
	case api.Events:
		primaryData, err := catalogue.EventBackend.List(ctx, primary, &v1.EventParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.L7Logs:
		primaryData, err := catalogue.L7LogBackend.List(ctx, primary, &v1.L7LogParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.WAFLogs:
		primaryData, err := catalogue.WAFBackend.List(ctx, primary, &v1.WAFLogParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].GeneratedTime
		return expected
	case api.RuntimeReports:
		primaryData, err := catalogue.RuntimeBackend.List(ctx, primary, &v1.RuntimeReportParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].Report.GeneratedTime
		return expected
	case api.IPSet:
		primaryData, err := catalogue.IPSetBackend.List(ctx, primary, &v1.IPSetThreatFeedParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].Data.GeneratedTime
		return expected
	case api.DomainNameSet:
		primaryData, err := catalogue.DomainNameSetBackend.List(ctx, primary, &v1.DomainNameSetThreatFeedParams{
			QueryParams: queryParams(),
			QuerySortParams: v1.QuerySortParams{
				Sort: sortParams(),
			},
		})
		require.NoError(t, err)
		require.Len(t, primaryData.Items, 1)
		expected := *primaryData.Items[0].Data.GeneratedTime
		return expected

	default:
		t.Fatalf("unknown data type %v", dataType)
	}

	return time.Time{}
}

func sortParams() []v1.SearchRequestSortBy {
	return []v1.SearchRequestSortBy{{Field: "generated_time", Descending: true}}
}

func queryParams() v1.QueryParams {
	return v1.QueryParams{
		TimeRange: &lmav1.TimeRange{
			Field: "generated_time",
		},
		MaxPageSize: 1,
	}
}

func validateMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, dataType api.DataType, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	switch dataType {
	case api.FlowLogs:
		validateFlowMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.AuditEELogs:
		validateAuditMigratedData(t, primary, secondary, catalogue, v1.AuditLogTypeEE, waitFor, tick)
	case api.AuditKubeLogs:
		validateAuditMigratedData(t, primary, secondary, catalogue, v1.AuditLogTypeKube, waitFor, tick)
	case api.BGPLogs:
		validateBGPMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.DNSLogs:
		validateDNSMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.Benchmarks:
		validateBenchmarksMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.ReportData:
		validateComplianceReportsMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.Snapshots:
		validateSnapshotsMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.Events:
		validateEventsMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.L7Logs:
		validateL7MigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.WAFLogs:
		validateWAFMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.RuntimeReports:
		validateRuntimeMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.IPSet:
		validateIPSetMigratedData(t, primary, secondary, catalogue, waitFor, tick)
	case api.DomainNameSet:
		validateDomainSetMigratedData(t, primary, secondary, catalogue, waitFor, tick)

	default:
		t.Fatalf("unknown data type %v", dataType)
	}

}

func validateAuditMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, auditType v1.AuditLogType, waitFor time.Duration, tick time.Duration) {
	require.Eventually(t, func() bool {
		t.Helper()

		originalData, err := catalogue.AuditBackend.List(ctx, primary, &v1.AuditLogParams{QueryParams: sinceStartOfTime(), Type: auditType})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list %v logs for primary cluster %s", auditType, primary.Cluster)
			return false
		}

		migratedData, err := catalogue.AuditBackend.List(ctx, secondary, &v1.AuditLogParams{QueryParams: sinceStartOfTime(), Type: auditType})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list %v logs for secondary cluster %s", auditType, secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func validateFlowMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.FlowLogBackend.List(ctx, primary, &v1.FlowLogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list flow logs for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.FlowLogBackend.List(ctx, secondary, &v1.FlowLogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list flow logs for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func validateBGPMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.BGPBackend.List(ctx, primary, &v1.BGPLogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list bgp logs for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.BGPBackend.List(ctx, secondary, &v1.BGPLogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list bgp logs for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func sinceStartOfTime() v1.QueryParams {
	const inThePast = -time.Hour * 24 * 365 * 10

	return v1.QueryParams{TimeRange: &lmav1.TimeRange{
		Field: "generated_time",
		From:  time.Now().Add(inThePast),
	}}
}

func validateDNSMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.DNSLogBackend.List(ctx, primary, &v1.DNSLogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list dns logs for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.DNSLogBackend.List(ctx, secondary, &v1.DNSLogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list dns logs for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func validateBenchmarksMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.BenchmarksBackend.List(ctx, primary, &v1.BenchmarksParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list benchmarks for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.BenchmarksBackend.List(ctx, secondary, &v1.BenchmarksParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list benchmarks for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func validateComplianceReportsMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.ReportsBackend.List(ctx, primary, &v1.ReportDataParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list compliance reports for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.ReportsBackend.List(ctx, secondary, &v1.ReportDataParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list compliance reports for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func validateSnapshotsMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.SnapshotsBackend.List(ctx, primary, &v1.SnapshotParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list snapshots for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.SnapshotsBackend.List(ctx, secondary, &v1.SnapshotParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list snapshots for secondary cluster %s", secondary.Cluster)
			return false
		}

		if len(migratedData.Items) != len(originalData.Items) {
			return false
		}

		if len(migratedData.Items) == 0 {
			return false
		}

		for id := range originalData.Items {
			resetUniqueFields(&originalData.Items[id].ResourceList)
		}

		for id := range migratedData.Items {
			resetUniqueFields(&migratedData.Items[id].ResourceList)
		}

		if !reflect.DeepEqual(migratedData.Items, originalData.Items) {
			logrus.Infof("Diff between migrated and original data: %s", cmp.Diff(migratedData.Items, originalData.Items))
			return false
		}

		return true
	}, waitFor, tick)
}

func validateEventsMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.EventBackend.List(ctx, primary, &v1.EventParams{QueryParams: v1.QueryParams{TimeRange: &lmav1.TimeRange{
			Field: "generated_time",
			From:  time.Now().Add(-time.Hour * 24 * 365 * 10),
		}}})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list events for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.EventBackend.List(ctx, secondary, &v1.EventParams{QueryParams: v1.QueryParams{TimeRange: &lmav1.TimeRange{
			Field: "generated_time",
			From:  time.Now().Add(-time.Hour * 24 * 365 * 10),
		}}})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list events for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func validateL7MigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.L7LogBackend.List(ctx, primary, &v1.L7LogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list l7 log for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.L7LogBackend.List(ctx, secondary, &v1.L7LogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list l7 log for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func validateWAFMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.WAFBackend.List(ctx, primary, &v1.WAFLogParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list waf logs for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.WAFBackend.List(ctx, secondary, &v1.WAFLogParams{QueryParams: v1.QueryParams{TimeRange: &lmav1.TimeRange{
			Field: "generated_time",
			From:  time.Now().Add(-time.Hour * 24 * 365 * 10),
		}}})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list waf logs for secondary cluster %s", secondary.Cluster)
			return false
		}

		return compareData(migratedData, originalData)
	}, waitFor, tick)
}

func compareData[T any](migratedData *v1.List[T], originalData *v1.List[T]) bool {
	if len(originalData.Items) == 0 {
		return false
	}

	if len(migratedData.Items) != len(originalData.Items) {
		return false
	}

	for id := range originalData.Items {
		resetUniqueFields(&originalData.Items[id])
	}

	for id := range migratedData.Items {
		resetUniqueFields(&migratedData.Items[id])
	}

	if !reflect.DeepEqual(migratedData.Items, originalData.Items) {
		logrus.Infof("Diff between migrated and original data: %s", cmp.Diff(migratedData.Items, originalData.Items))
		return false
	}

	return true
}

func validateRuntimeMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.RuntimeBackend.List(ctx, primary, &v1.RuntimeReportParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list runtime reports for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.RuntimeBackend.List(ctx, secondary, &v1.RuntimeReportParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list runtime reports for secondary cluster %s", secondary.Cluster)
			return false
		}

		if len(migratedData.Items) != len(originalData.Items) {
			return false
		}

		if len(migratedData.Items) == 0 {
			return false
		}

		for id := range originalData.Items {
			originalData.Items[id].Report.GeneratedTime = nil
			if originalData.Items[id].Tenant != primary.Tenant {
				logrus.Warnf("Items were not inserted correctly. Tenant value is set to %s instead of %s",
					originalData.Items[id].Tenant, primary.Tenant)
				return false
			}

			originalData.Items[id].Tenant = ""
		}

		for id := range migratedData.Items {
			migratedData.Items[id].Report.GeneratedTime = nil
			if migratedData.Items[id].Tenant != secondary.Tenant {
				logrus.Warnf("Items were not inserted correctly. Tenant value is set to %s instead of %s",
					migratedData.Items[id].Tenant, secondary.Tenant)
				return false
			}

			migratedData.Items[id].Tenant = ""
		}

		if !reflect.DeepEqual(migratedData.Items, originalData.Items) {
			logrus.Infof("Diff between migrated and original data: %s", cmp.Diff(migratedData.Items, originalData.Items))
			return false
		}

		return true
	}, waitFor, tick)
}

func validateIPSetMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.IPSetBackend.List(ctx, primary, &v1.IPSetThreatFeedParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list ip set threat feeds for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.IPSetBackend.List(ctx, secondary, &v1.IPSetThreatFeedParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list ip set threat feeds for secondary cluster %s", secondary.Cluster)
			return false
		}

		if len(migratedData.Items) != len(originalData.Items) {
			return false
		}

		if len(migratedData.Items) == 0 {
			return false
		}

		for id := range originalData.Items {
			resetUniqueFields(originalData.Items[id].Data)
		}

		for id := range migratedData.Items {
			resetUniqueFields(migratedData.Items[id].Data)
		}

		if !reflect.DeepEqual(migratedData.Items, originalData.Items) {
			logrus.Infof("Diff between migrated and original data: %s", cmp.Diff(migratedData.Items, originalData.Items))
			return false
		}

		return true
	}, waitFor, tick)
}

func validateDomainSetMigratedData(t *testing.T, primary api.ClusterInfo, secondary api.ClusterInfo, catalogue migrator.BackendCatalogue, waitFor time.Duration, tick time.Duration) {
	t.Helper()

	require.Eventually(t, func() bool {
		originalData, err := catalogue.DomainNameSetBackend.List(ctx, primary, &v1.DomainNameSetThreatFeedParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list domain set threat feeds for primary cluster %s", primary.Cluster)
			return false
		}

		migratedData, err := catalogue.DomainNameSetBackend.List(ctx, secondary, &v1.DomainNameSetThreatFeedParams{QueryParams: sinceStartOfTime()})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list domain set threat feeds for secondary cluster %s", secondary.Cluster)
			return false
		}

		if len(migratedData.Items) != len(originalData.Items) {
			return false
		}

		if len(migratedData.Items) == 0 {
			return false
		}

		for id := range originalData.Items {
			resetUniqueFields(originalData.Items[id].Data)
		}

		for id := range migratedData.Items {
			resetUniqueFields(migratedData.Items[id].Data)
		}

		if !reflect.DeepEqual(migratedData.Items, originalData.Items) {
			logrus.Infof("Diff between migrated and original data: %s", cmp.Diff(migratedData.Items, originalData.Items))
			return false
		}

		return true
	}, waitFor, tick)
}

func resetUniqueFields[T any](migratedData *T) {
	val := reflect.ValueOf(migratedData).Elem()
	generatedTime := val.FieldByName("GeneratedTime")
	generatedTime.SetZero()
}
