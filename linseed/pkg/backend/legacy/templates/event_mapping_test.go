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

var excludeEventField = map[string]bool{
	"id": true,
}

func TestCompareEventStructAndTemplate(t *testing.T) {

	t.Run("Check for Events api and template matches", func(t *testing.T) {
		eventMap := testutils.MustUnmarshalToMap(t, EventsMappings)
		val := new(v1.Event)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.True(t, utils.CheckFieldsInJSON(t, m, eventMap["properties"].(map[string]any), excludeEventField))
	})
	t.Run("Check for Event api and template not matches", func(t *testing.T) {
		eventMap := testutils.MustUnmarshalToMap(t, EventsMappings)
		type FakeEvent struct {
			v1.Event `json:",inline"`
			Unknown  string `json:"unknown"`
		}
		val := new(FakeEvent)
		utils.Populate(reflect.ValueOf(val).Elem())
		jsonLog, err := json.Marshal(val)
		require.NoError(t, err)
		m := utils.MustUnmarshalStructToMap(t, jsonLog)
		require.False(t, utils.CheckFieldsInJSON(t, m, eventMap["properties"].(map[string]any), excludeEventField))
	})
}
