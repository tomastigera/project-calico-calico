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

var excludeRuntimeReportsField = map[string]bool{
	"id": true,
}

func TestCompareRuntimeReportStructAndTemplate(t *testing.T) {

	t.Run("Check for RuntimeReport api and template matches", func(t *testing.T) {
		runtimeMap := testutils.MustUnmarshalToMap(t, RuntimeReportsMappings)
		utils.IsDynamicMappingDisabled(t, runtimeMap)
		val := new(v1.Report)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, runtimeMap["properties"].(map[string]any), excludeRuntimeReportsField))
	})
	t.Run("Check for RuntimeReport api and template not matches", func(t *testing.T) {
		runtimeMap := testutils.MustUnmarshalToMap(t, RuntimeReportsMappings)
		type FakeReport struct {
			v1.Report `json:",inline"`
			Unknown   string `json:"unknown"`
		}
		val := new(FakeReport)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, runtimeMap["properties"].(map[string]any), excludeRuntimeReportsField))
	})
}
