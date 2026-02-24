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

var excludeBGPFields = map[string]bool{
	"id": true,
}

func TestCompareBGPStructAndTemplate(t *testing.T) {

	t.Run("Check for BGP api and template matches", func(t *testing.T) {
		bgpMap := testutils.MustUnmarshalToMap(t, BGPMappings)
		utils.IsDynamicMappingDisabled(t, bgpMap)
		val := new(v1.BGPLog)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, bgpMap["properties"].(map[string]any), excludeBGPFields))
	})
	t.Run("Check for BGP api and template not matches", func(t *testing.T) {
		bgpMap := testutils.MustUnmarshalToMap(t, BGPMappings)
		type FakeBGP struct {
			v1.BGPLog `json:",inline"`
			Unknown   string `json:"unknown"`
		}
		val := new(FakeBGP)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, bgpMap["properties"].(map[string]any), nil))
	})
}
