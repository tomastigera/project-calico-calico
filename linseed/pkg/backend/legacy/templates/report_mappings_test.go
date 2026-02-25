// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package templates

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	utils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

var excludeReportField = map[string]bool{
	// TODO: Below ones are referred as an object in mapping. Should need to include into the mapping
	"id":                  true,
	"endpointsSummary":    true,
	"namespacesSummary":   true,
	"servicesSummary":     true,
	"auditSummary":        true,
	"flows":               true,
	"cisBenchmark":        true,
	"cisBenchmarkSummary": true,
	"service":             true,
	"endpoint":            true,
	"namespace":           true,
	// TODO: Add all the fields for detail exclude
	"auditEvents": true,
}

func TestCompareReportStructAndTemplate(t *testing.T) {

	t.Run("Check for Reports api and template matches", func(t *testing.T) {
		reportMap := testutils.MustUnmarshalToMap(t, ReportMappings)
		val := new(v1.ReportData)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, reportMap["properties"].(map[string]any), excludeReportField))
	})

	t.Run("Check for Report api and template not matches", func(t *testing.T) {
		reportMap := testutils.MustUnmarshalToMap(t, ReportMappings)
		type FakeReport struct {
			v1.ReportData `json:",inline"`
			Unknown       string `json:"unknown"`
		}

		val := new(FakeReport)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, reportMap["properties"].(map[string]any), excludeReportField))
	})
}
