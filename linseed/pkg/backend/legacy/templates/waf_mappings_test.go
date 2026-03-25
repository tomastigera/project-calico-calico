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

var excludeWAFLogsField = map[string]bool{
	"id":        true,
	"rule_info": true,
}

func TestCompareWAFStructAndTemplate(t *testing.T) {

	t.Run("Check for WAF api and template matches", func(t *testing.T) {
		wafMap := testutils.MustUnmarshalToMap(t, WAFMappings)
		utils.IsDynamicMappingDisabled(t, wafMap)
		val := new(v1.WAFLog)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, wafMap["properties"].(map[string]any), excludeWAFLogsField))
	})
	t.Run("Check for WAF api and template not matches", func(t *testing.T) {
		wafMap := testutils.MustUnmarshalToMap(t, WAFMappings)
		type FakeWAF struct {
			v1.WAFLog `json:",inline"`
			Unknown   string `json:"unknown"`
		}
		utils.IsDynamicMappingDisabled(t, wafMap)
		val := new(FakeWAF)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, wafMap["properties"].(map[string]any), nil))
	})
}
