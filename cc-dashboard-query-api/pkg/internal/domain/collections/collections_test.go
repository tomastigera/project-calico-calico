package collections

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tigera/tds-apiserver/lib/slices"
)

func TestCollections(t *testing.T) {

	allCollections := Collections()

	t.Run("match expected collection names", func(t *testing.T) {

		collectionNames := slices.Map(allCollections, func(c Collection) CollectionName {
			return c.Name()
		})
		require.ElementsMatch(t, collectionNames, []CollectionName{"dns", "flows", "l7"})
	})

	t.Run("contains start_time field", func(t *testing.T) {
		for _, c := range allCollections {
			field, found := c.Field("start_time")
			require.True(t, found)
			require.Equal(t, collectionFieldGeneric{fieldType: FieldTypeDate, fieldName: "start_time", filterDisabled: true}, field, c.name)
		}
	})
}
