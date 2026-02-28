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

var excludeBenchmarkFields = map[string]bool{
	"id": true,
}

func TestCompareBenchmarksStructAndTemplate(t *testing.T) {

	t.Run("Check for benchmarks api and template matches", func(t *testing.T) {
		val := new(v1.Benchmarks)
		utils.Populate(reflect.ValueOf(val).Elem())
		benchmarksMap := testutils.MustUnmarshalToMap(t, BenchmarksMappings)
		utils.IsDynamicMappingDisabled(t, benchmarksMap)
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, benchmarksMap["properties"].(map[string]any), excludeBenchmarkFields))
	})
	t.Run("Check for benchmarks api and template not matches", func(t *testing.T) {
		benchmarksMap := testutils.MustUnmarshalToMap(t, BenchmarksMappings)

		type FakeBenchmarks struct {
			v1.Benchmarks `json:",inline"`
			Unknown       string `json:"unknown"`
		}
		val := new(FakeBenchmarks)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, benchmarksMap["properties"].(map[string]any), excludeBenchmarkFields))
	})
}
