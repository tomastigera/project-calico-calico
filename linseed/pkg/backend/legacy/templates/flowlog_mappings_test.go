package templates

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	utils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

var excludeFlowLogsField = map[string]bool{
	"id": true,
}

func TestCompareFlowLogsStructAndTemplate(t *testing.T) {
	t.Run("Check for FlowLogs api and template matches", func(t *testing.T) {
		flowlogMap := testutils.MustUnmarshalToMap(t, FlowLogMappings)
		utils.IsDynamicMappingDisabled(t, flowlogMap)
		val := new(v1.FlowLog)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, flowlogMap["properties"].(map[string]any), excludeFlowLogsField))
	})
	t.Run("Check for FlowLogs api and template not matches", func(t *testing.T) {
		flowlogMap := testutils.MustUnmarshalToMap(t, FlowLogMappings)
		type FakeFlowLog struct {
			v1.FlowLog `json:",inline"`
			Unknown    string `json:"unknown"`
		}
		val := new(FakeFlowLog)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, flowlogMap["properties"].(map[string]any), excludeFlowLogsField))
	})
}
