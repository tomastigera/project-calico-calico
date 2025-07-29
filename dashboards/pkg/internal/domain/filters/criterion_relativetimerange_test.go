package filters

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCriterionRelativeTimeRange(t *testing.T) {

	t.Run("validation", func(t *testing.T) {
		var zeroDuration time.Duration
		t.Run("gte and lte is unset", func(t *testing.T) {
			_, err := NewRelativeTimeRange(nil, zeroDuration, zeroDuration, false)
			require.ErrorContains(t, err, "invalid relativeTimeRange duration")
		})

		t.Run("gte is negative", func(t *testing.T) {
			_, err := NewRelativeTimeRange(nil, time.Duration(-1)*time.Minute, time.Duration(1)*time.Minute, false)
			require.ErrorContains(t, err, "invalid relativeTimeRange duration")
		})

		t.Run("lte is negative", func(t *testing.T) {
			_, err := NewRelativeTimeRange(nil, time.Duration(1)*time.Minute, time.Duration(-1)*time.Minute, false)
			require.ErrorContains(t, err, "invalid relativeTimeRange duration")
		})

		t.Run("lte is greater than gte", func(t *testing.T) {
			_, err := NewRelativeTimeRange(nil, time.Duration(1)*time.Minute, time.Duration(2)*time.Minute, false)
			require.ErrorContains(t, err, "invalid relativeTimeRange duration")
		})

		t.Run("success", func(t *testing.T) {
			_, err := NewRelativeTimeRange(nil, time.Duration(1)*time.Minute, zeroDuration, false)
			require.NoError(t, err)

			_, err = NewRelativeTimeRange(nil, time.Duration(1)*time.Minute, time.Duration(1)*time.Minute, false)
			require.NoError(t, err)

			_, err = NewRelativeTimeRange(nil, time.Duration(2)*time.Minute, time.Duration(1)*time.Minute, false)
			require.NoError(t, err)
		})
	})
}
