package filters

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCriterionRelativeTimeRange(t *testing.T) {

	t.Run("validation", func(t *testing.T) {
		_, err := NewRelativeTimeRange("", "", false)
		require.ErrorContains(t, err, "invalid relativeTimeRange duration")

		_, err = NewRelativeTimeRange("hello world", "", false)
		require.ErrorContains(t, err, "failed to parse relativeTimeRange gte field")

		_, err = NewRelativeTimeRange("", "hello world", false)
		require.ErrorContains(t, err, "failed to parse relativeTimeRange lte field")

		_, err = NewRelativeTimeRange("15m", "", false)
		require.NoError(t, err)

		_, err = NewRelativeTimeRange("", "15m", false)
		require.NoError(t, err)
	})
}
