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

var excludeL7LogsField = map[string]bool{
	"id": true,
}

func TestCompareL7logStructAndTemplate(t *testing.T) {

	t.Run("Check for L7log api and template matches", func(t *testing.T) {
		l7logMap := testutils.MustUnmarshalToMap(t, L7LogMappings)
		utils.IsDynamicMappingDisabled(t, l7logMap)
		val := new(v1.L7Log)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, l7logMap["properties"].(map[string]any), excludeL7LogsField))
	})
	t.Run("Check for L7Log api and template not matches", func(t *testing.T) {
		l7logMap := testutils.MustUnmarshalToMap(t, L7LogMappings)
		type FakeL7Log struct {
			v1.L7Log `json:",inline"`
			Unknown  string `json:"unknown"`
		}
		val := new(FakeL7Log)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, l7logMap["properties"].(map[string]any), nil))
	})
}
