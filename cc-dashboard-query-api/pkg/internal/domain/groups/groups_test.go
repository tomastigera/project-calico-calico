package groups

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGroups(t *testing.T) {

	t.Run("append group values", func(t *testing.T) {
		g := &GroupValue{Key: "g"}
		g1 := &GroupValue{Key: "g1"}
		g2 := &GroupValue{Key: "g2"}

		g.AppendGroupValue(g1)
		g.AppendGroupValue(g2)

		require.Equal(t, g, &GroupValue{
			Key:            "g",
			SubGroupValues: []*GroupValue{{Key: "g1"}, {Key: "g2"}},
		})
	})
}
