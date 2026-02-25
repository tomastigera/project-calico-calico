package templates

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	utils "github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

var excludeAuditFields = map[string]bool{
	"id": true,
}

func TestCompareAuditStructAndTemplate(t *testing.T) {

	t.Run("Check for Audit api and template matches", func(t *testing.T) {
		auditMap := testutils.MustUnmarshalToMap(t, AuditMappings)

		aud := new(v1.AuditLog)
		utils.Populate(reflect.ValueOf(aud).Elem())
		jsonLog, err := aud.MarshalJSON()
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, auditMap["properties"].(map[string]any), excludeAuditFields))
	})

	t.Run("Check for Audit api and template not matches", func(t *testing.T) {
		auditMap := testutils.MustUnmarshalToMap(t, AuditMappings)
		audit := v1.AuditLog{}
		jsonLog, err := audit.MarshalJSON()
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		m["unknown"] = "unknown"
		require.False(t, utils.CheckFieldsInJSON(t, m, auditMap["properties"].(map[string]any), excludeAuditFields))
	})
}
