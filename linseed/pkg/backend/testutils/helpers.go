// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.
//

package testutils

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
)

func AssertFlowLogsIDAndClusterAndReset(t *testing.T, expectedCluster string, r *v1.List[v1.FlowLog]) []v1.FlowLog {
	require.NotNil(t, r)

	// Assert that we have an ID assigned from Elastic
	var copyOfLogs []v1.FlowLog
	for _, item := range r.Items {
		AssertFlowLogIDAndClusterAndReset(t, expectedCluster, &item)
		copyOfLogs = append(copyOfLogs, item)
	}
	return copyOfLogs
}

func AssertFlowLogIDAndClusterAndReset(t *testing.T, expectedCluster string, item *v1.FlowLog) {
	require.NotNil(t, item)
	require.NotEmpty(t, item.ID)
	item.ID = ""

	require.NotNil(t, item.GeneratedTime)
	item.GeneratedTime = nil

	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertFlowClusterAndReset(t *testing.T, expectedCluster string, item *v1.L3Flow) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Key.Cluster)
	item.Key.Cluster = ""
}

func AssertEventIDAndClusterAndGeneratedTimeAndReset(t *testing.T, expectedCluster string, item v1.Event) v1.Event {
	require.NotEmpty(t, item.ID)
	item.ID = ""

	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""

	require.NotNil(t, item.GeneratedTime)
	item.GeneratedTime = nil

	return item
}

func AssertEventClusterAndReset(t *testing.T, expectedCluster string, item *v1.Event) {
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertDNSLogsIDAndClusterAndReset(t *testing.T, expectedCluster string, r *v1.List[v1.DNSLog]) []v1.DNSLog {
	require.NotNil(t, r)

	// Assert that we have an ID assigned from Elastic
	var copyOfLogs []v1.DNSLog
	for _, item := range r.Items {
		AssertDNSLogIDAndClusterAndReset(t, expectedCluster, &item)
		copyOfLogs = append(copyOfLogs, item)
	}
	return copyOfLogs
}

func AssertDNSLogIDAndClusterAndReset(t *testing.T, expectedCluster string, item *v1.DNSLog) {
	require.NotNil(t, item)
	require.NotEmpty(t, item.ID)
	item.ID = ""

	// Similarly for GeneratedTime field, as test code cannot predict the exact value that
	// Linseed will populate here.
	require.NotNil(t, item.GeneratedTime)
	item.GeneratedTime = nil

	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertAuditLogClusterAndReset(t *testing.T, expectedCluster string, item *v1.AuditLog) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertAuditLogsGeneratedTimeAndReset(t *testing.T, items *v1.List[v1.AuditLog]) {
	require.NotNil(t, items)
	for i := range items.Items {
		AssertGeneratedTimeAndReset(t, &items.Items[i])
	}
}
func AssertBenchmarkIDAndClusterAndReset(t *testing.T, expectedID string, expectedCluster string, item *v1.Benchmarks) {
	require.NotNil(t, item)
	require.Equal(t, expectedID, item.ID)
	item.ID = ""
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertBenchmarkClusterAndReset(t *testing.T, expectedCluster string, item *v1.Benchmarks) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertDomainNameSetThreatFeedClusterAndReset(t *testing.T, expectedCluster string, item *v1.DomainNameSetThreatFeed) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Data.Cluster)
	item.Data.Cluster = ""
}

func AssertDomainNameSetThreatFeedGeneratedTimeAndReset(t *testing.T, item *v1.DomainNameSetThreatFeed) {
	require.NotNil(t, item)
	require.NotNil(t, item.Data.GeneratedTime)
	item.Data.GeneratedTime = nil
}

func AssertIPSetThreatFeedClusterAndReset(t *testing.T, expectedCluster string, item *v1.IPSetThreatFeed) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Data.Cluster)
	item.Data.Cluster = ""
}

func AssertIPSetThreatFeedGeneratedTimeAndReset(t *testing.T, item *v1.IPSetThreatFeed) {
	require.NotNil(t, item)
	require.NotNil(t, item.Data.GeneratedTime)
	item.Data.GeneratedTime = nil
}

func AssertReportDataIDAndClusterAndReset(t *testing.T, expectedID string, expectedCluster string, item *v1.ReportData) {
	require.NotNil(t, item)
	require.Equal(t, expectedID, item.ID)
	item.ID = ""
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertReportDataClusterAndReset(t *testing.T, expectedCluster string, item *v1.ReportData) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertSnapshotIDAndClusterAndReset(t *testing.T, expectedCluster string, item *v1.Snapshot) {
	require.NotNil(t, item)
	require.NotEmpty(t, item.ID)
	item.ID = ""
	require.Equal(t, expectedCluster, item.ResourceList.Cluster)
	item.ResourceList.Cluster = ""
}

func AssertSnapshotGeneratedTimeAndReset(t *testing.T, item *v1.Snapshot) {
	require.NotNil(t, item)
	require.NotNil(t, item.ResourceList)
	require.NotNil(t, item.ResourceList.GeneratedTime)
	item.ResourceList.GeneratedTime = nil
}

func AssertSnapshotClusterAndReset(t *testing.T, expectedCluster string, item *v1.Snapshot) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.ResourceList.Cluster)
	item.ResourceList.Cluster = ""
}

func AssertBGPLogClusterAndReset(t *testing.T, expectedCluster string, item *v1.BGPLog) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertWAFLogClusterAndReset(t *testing.T, expectedCluster string, item *v1.WAFLog) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertGeneratedTimeAndReset[T any](t *testing.T, item *T) {
	t.Helper()

	val := reflect.ValueOf(item).Elem()
	generatedTime := val.FieldByName("GeneratedTime")
	require.False(t, generatedTime.IsZero())
	require.NotNil(t, generatedTime)
	generatedTime.SetZero()
}

func AssertL7LogClusterAndReset(t *testing.T, expectedCluster string, item *v1.L7Log) {
	require.NotNil(t, item)
	require.Equal(t, expectedCluster, item.Cluster)
	item.Cluster = ""
}

func AssertEventsIDAndClusterAndGeneratedTimeAndReset(t *testing.T, expectedCluster string, r *v1.List[v1.Event]) []v1.Event {
	require.NotNil(t, r)

	// Assert that we have an ID assigned from Elastic
	var copyOfEvents []v1.Event
	for _, item := range r.Items {
		item = AssertEventIDAndClusterAndGeneratedTimeAndReset(t, expectedCluster, item)
		copyOfEvents = append(copyOfEvents, item)
	}
	return copyOfEvents
}

func AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t *testing.T, expectedCluster string, item *v1.RuntimeReport) {
	require.NotNil(t, item)
	require.NotEmpty(t, item.ID)
	item.ID = ""
	item.Report.ID = ""

	require.NotNil(t, item.Report.GeneratedTime)
	item.Report.GeneratedTime = nil

	require.Equal(t, expectedCluster, item.Report.Cluster)
	item.Report.Cluster = ""
}

func AssertRuntimeReportsIDAndGeneratedTimeAndClusterAndReset(t *testing.T, expectedCluster string, r *v1.List[v1.RuntimeReport]) {
	require.NotNil(t, r)
	for i := range r.Items {
		AssertRuntimeReportIDAndGeneratedTimeAndClusterAndReset(t, expectedCluster, &r.Items[i])
	}
}

func CheckFieldsInJSON(t *testing.T, jsonMap map[string]interface{}, mappings map[string]interface{}, excludeFieldList map[string]bool) bool {
	for key, val := range jsonMap {
		if excludeFieldList[key] { // List include id and other object json type
			continue
		}
		switch val.(type) {
		case map[string]interface{}:
			t.Log(key)
			prop := mappings[key].(map[string]interface{})
			if _, ok := prop["properties"]; ok { // this is need to skip map[string][string] where it would be populated as client_labels :{"":""}
				if !CheckFieldsInJSON(t, val.(map[string]interface{}), prop["properties"].(map[string]interface{}), nil) {
					return false
				}
			}
		case []interface{}:
			t.Log(key)
			if !parseArray(t, val.([]interface{}), mappings[key].(map[string]interface{}), excludeFieldList) {
				return false
			}
		default:
			t.Log(key)
			if key == "" || excludeFieldList[key] { // Exclude map values populating key,val as ""
				continue
			}
			if _, ok := mappings[key]; !ok {
				t.Log("Mapping missing the value:", key)
				return false
			}
		}
	}
	return true
}

func IsDynamicMappingDisabled(t *testing.T, mappings map[string]interface{}) {
	require.NotNil(t, mappings["dynamic"])
	require.Equal(t, false, mappings["dynamic"])
}

func parseArray(t *testing.T, anArray []interface{}, mappings map[string]interface{}, excludeFieldList map[string]bool) bool {
	for _, val := range anArray {
		switch val := val.(type) {
		case map[string]interface{}:
			if checkExcludeSliceItem(val, excludeFieldList) {
				continue
			}
			if !CheckFieldsInJSON(t, val, mappings["properties"].(map[string]interface{}), excludeFieldList) {
				return false
			}
		case []interface{}:
			if !parseArray(t, val, mappings, excludeFieldList) {
				return false
			}
		}
	}
	return true
}

func checkExcludeSliceItem(tempMap map[string]interface{}, excludeFieldList map[string]bool) bool {
	for key := range tempMap {
		if excludeFieldList[key] { // if string check for it in excluded list
			return true
		}
	}
	return false
}

func MustUnmarshalStructToMap(t *testing.T, log []byte) map[string]interface{} {
	m := map[string]interface{}{}
	err := json.Unmarshal(log, &m)
	require.NoError(t, err)
	return m
}

func Populate(value reflect.Value) {
	fmt.Println(value.String())
	if value.IsValid() {
		typeOf := value.Type()
		if typeOf.Name() == "Unknown" { // runtime.Unknown is an interface
			return
		}
		if typeOf.Kind() == reflect.Struct {
			for i := 0; i < value.NumField(); i++ {
				f := value.Field(i)
				if f.CanSet() {
					switch f.Kind() {
					case reflect.Interface:
						hack := map[string]interface{}{}
						newMap := reflect.MakeMap(reflect.TypeOf(hack))
						f.Set(newMap)
					case reflect.Map:
						newMap := reflect.MakeMapWithSize(f.Type(), 1)
						key := reflect.Zero(f.Type().Key())
						val := reflect.Zero(f.Type().Elem())
						newMap.SetMapIndex(key, val)
						f.Set(newMap)
					case reflect.Slice:
						newSlice := reflect.MakeSlice(f.Type(), 1, 1)
						f.Set(newSlice)
					case reflect.Struct:
						newStruct := reflect.New(f.Type())
						Populate(newStruct.Elem())
						f.Set(newStruct.Elem())
					case reflect.Ptr:
						newPointer := reflect.New(f.Type().Elem())
						Populate(newPointer.Elem())
						f.Set(newPointer)
					case reflect.String:
						f.SetString("empty")
					case reflect.Bool:
						f.SetBool(true) // when set false omitempty will not populate this field.
					case reflect.Int, reflect.Int64:
						x := int64(7)
						if !f.OverflowInt(x) {
							f.SetInt(x)
						}
					case reflect.Uint64, reflect.Uint8:
						x := uint64(7)
						if !f.OverflowUint(x) {
							f.SetUint(x)
						}
					}
				}
			}
		}
	}
}

func CheckSingleIndexTemplateBootstrapping(t *testing.T, ctx context.Context, client *elastic.Client, idx bapi.Index, i bapi.ClusterInfo, indexPattern, shards, replicas, ILMPolicy string) {
	// Check that the template was created.
	templateResp, err := client.IndexGetIndexTemplate(idx.IndexTemplateName(i)).Do(ctx)
	require.NoError(t, err)
	_, templateExists := templateResp.IndexTemplates.ByName(idx.IndexTemplateName(i))
	require.True(t, templateExists)

	// Check that the bootstrap index exists
	indexExists, err := client.IndexExists(idx.BootstrapIndexName(i)).Do(ctx)
	require.NoError(t, err)
	require.True(t, indexExists, "index doesn't exist: %s", idx.BootstrapIndexName(i))

	// Check that write alias exists.
	index := fmt.Sprintf("%s.%s-%s-%s", idx.Name(i), "linseed", time.Now().UTC().Format("20060102"), indexPattern)
	responseAlias, err := client.CatAliases().Do(ctx)
	require.NoError(t, err)
	require.Greater(t, len(responseAlias), 0)
	hasAlias := false
	numWriteIndex := 0
	numNonWriteIndex := 0
	for _, row := range responseAlias {
		if row.Alias == idx.Alias(i) {
			hasAlias = true
			if row.IsWriteIndex == "true" {
				require.Equal(t, index, row.Index)
				numWriteIndex++
			} else {
				require.NotEqual(t, index, row.Index)
				numNonWriteIndex++
			}
		}
	}
	require.True(t, hasAlias)
	require.Equal(t, 1, numWriteIndex)

	responseSettings, err := client.IndexGetSettings(index).Do(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, responseSettings)
	require.Contains(t, responseSettings, index)
	require.NotEmpty(t, responseSettings[index].Settings)
	require.Contains(t, responseSettings[index].Settings, "index")
	settings, _ := responseSettings[index].Settings["index"].(map[string]interface{})
	if idx.HasLifecycleEnabled() {
		// Check lifecycle section
		require.Contains(t, settings, "lifecycle")
		lifecycle, _ := settings["lifecycle"].(map[string]interface{})
		require.Contains(t, lifecycle, "name")
		require.EqualValues(t, lifecycle["name"], ILMPolicy)
		require.EqualValues(t, lifecycle["rollover_alias"], idx.Alias(i))
	}
	// Check shards and replicas
	require.Contains(t, settings, "number_of_replicas")
	require.EqualValues(t, settings["number_of_replicas"], replicas)
	require.Contains(t, settings, "number_of_shards")
	require.EqualValues(t, settings["number_of_shards"], shards)
}

// MatchIn returns true if the given predicate returns true for any element in the slice
func MatchIn[T any](slice []T, predicate func(T) bool) bool {
	for _, e := range slice {
		if predicate(e) {
			return true
		}
	}
	return false
}

func FlowLogClusterEquals(expectedCluster string) func(v1.FlowLog) bool {
	return func(log v1.FlowLog) bool {
		return log.Cluster == expectedCluster
	}
}

func AuditLogClusterEquals(expectedCluster string) func(log v1.AuditLog) bool {
	return func(log v1.AuditLog) bool {
		return log.Cluster == expectedCluster
	}
}

func BGPLogClusterEquals(expectedCluster string) func(log v1.BGPLog) bool {
	return func(log v1.BGPLog) bool {
		return log.Cluster == expectedCluster
	}
}

func ReportDataClusterEquals(expectedCluster string) func(log v1.ReportData) bool {
	return func(log v1.ReportData) bool {
		return log.Cluster == expectedCluster
	}
}

func BenchmarkClusterEquals(expectedCluster string) func(log v1.Benchmarks) bool {
	return func(log v1.Benchmarks) bool {
		return log.Cluster == expectedCluster
	}
}

func SnapshotClusterEquals(expectedCluster string) func(log v1.Snapshot) bool {
	return func(log v1.Snapshot) bool {
		return log.ResourceList.Cluster == expectedCluster
	}
}

func DNSLogClusterEquals(expectedCluster string) func(log v1.DNSLog) bool {
	return func(log v1.DNSLog) bool {
		return log.Cluster == expectedCluster
	}
}

func DNSFlowClusterEquals(expectedCluster string) func(log v1.DNSFlow) bool {
	return func(log v1.DNSFlow) bool {
		return log.Key.Cluster == expectedCluster
	}
}

func EventClusterEquals(expectedCluster string) func(log v1.Event) bool {
	return func(log v1.Event) bool {
		return log.Cluster == expectedCluster
	}
}

func L7LogClusterEquals(expectedCluster string) func(log v1.L7Log) bool {
	return func(log v1.L7Log) bool {
		return log.Cluster == expectedCluster
	}
}

func L7FlowClusterEquals(expectedCluster string) func(log v1.L7Flow) bool {
	return func(log v1.L7Flow) bool {
		return log.Key.Cluster == expectedCluster
	}
}

func ProcessInfoClusterEquals(expectedCluster string) func(log v1.ProcessInfo) bool {
	return func(log v1.ProcessInfo) bool {
		return log.Cluster == expectedCluster
	}
}

func RuntimeReportClusterEquals(expectedCluster string) func(log v1.RuntimeReport) bool {
	return func(log v1.RuntimeReport) bool {
		return log.Report.Cluster == expectedCluster
	}
}

func DomainNameSetThreatFeedClusterEquals(expectedCluster string) func(log v1.DomainNameSetThreatFeed) bool {
	return func(log v1.DomainNameSetThreatFeed) bool {
		return log.Data.Cluster == expectedCluster
	}
}

func IPSetThreatFeedClusterEquals(expectedCluster string) func(log v1.IPSetThreatFeed) bool {
	return func(log v1.IPSetThreatFeed) bool {
		return log.Data.Cluster == expectedCluster
	}
}

func WAFLogClusterEquals(expectedCluster string) func(log v1.WAFLog) bool {
	return func(log v1.WAFLog) bool {
		return log.Cluster == expectedCluster
	}
}
