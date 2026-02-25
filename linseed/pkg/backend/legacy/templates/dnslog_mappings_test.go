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

var excludeDNSField = map[string]bool{
	"id": true,
}

func TestCompareDNSStructAndTemplate(t *testing.T) {

	t.Run("Check for DNS api and template matches", func(t *testing.T) {
		dnsMap := testutils.MustUnmarshalToMap(t, DNSLogMappings)

		val := new(v1.DNSLog)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, dnsMap["properties"].(map[string]any), excludeDNSField))
	})
	t.Run("Check for DNS api and template not matches", func(t *testing.T) {
		dnsMap := testutils.MustUnmarshalToMap(t, DNSLogMappings)
		type FakeDNS struct {
			v1.DNSLog `json:",inline"`
			Unknown   string `json:"unknown"`
		}

		val := new(FakeDNS)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)

		require.False(t, utils.CheckFieldsInJSON(t, m, dnsMap["properties"].(map[string]any), excludeDNSField))
	})
}
