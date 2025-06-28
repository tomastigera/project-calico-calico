package waf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func TestAggregatorController(t *testing.T) {
	t.Run("basic lifecycle", func(t *testing.T) {
		type logSink struct {
			received []*v1.WAFLog
		}
		sink := &logSink{}

		aggregationPeriod := 100 * time.Millisecond
		controller, err := NewAggregatorController(
			aggregationPeriod,
			[]string{"path", "method"},
			func(logs []*v1.WAFLog) {
				sink.received = append(sink.received, logs...)
			},
		)
		require.NoError(t, err)

		go controller.Run()
		defer controller.Stop()

		controller.AddLog(&v1.WAFLog{
			Path:      "/foo",
			Method:    "GET",
			RequestId: "abc",
		})
		controller.AddLog(&v1.WAFLog{
			Path:      "/foo",
			Method:    "GET",
			RequestId: "def",
		})

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			require.Len(c, sink.received, 1)
			require.Equal(c, 2, sink.received[0].Count)
			require.Equal(c, "/foo", sink.received[0].Path)
			require.Equal(c, "GET", sink.received[0].Method)
			require.Equal(c, "-", sink.received[0].RequestId)
		}, 500*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("flush on stop", func(t *testing.T) {
		type logSink struct {
			received []*v1.WAFLog
		}
		sink := &logSink{}

		aggregationPeriod := 100 * time.Millisecond
		controller, err := NewAggregatorController(
			aggregationPeriod,
			[]string{"path", "method"},
			func(logs []*v1.WAFLog) {
				sink.received = append(sink.received, logs...)
			},
		)
		require.NoError(t, err)

		go controller.Run()

		controller.AddLog(&v1.WAFLog{
			Path:      "/foo",
			Method:    "GET",
			RequestId: "abc",
		})
		controller.AddLog(&v1.WAFLog{
			Path:      "/foo",
			Method:    "GET",
			RequestId: "def",
		})

		// Make sure we got some logs aggregated (i.e. controller is running)
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			require.Len(c, sink.received, 1)
			require.Equal(c, 2, sink.received[0].Count)
			require.Equal(c, "/foo", sink.received[0].Path)
			require.Equal(c, "GET", sink.received[0].Method)
			require.Equal(c, "-", sink.received[0].RequestId)
		}, 500*time.Millisecond, 10*time.Millisecond)

		controller.AddLog(&v1.WAFLog{
			Path:      "/bar",
			Method:    "POST",
			RequestId: "ghi",
		})
		// Stop should flush the logs even if period hasn't elapsed
		controller.Stop()

		// Previous one s still in the sink, so we should have 2 logs
		require.Len(t, sink.received, 2)
		require.Equal(t, 1, sink.received[1].Count)
		require.Equal(t, "/bar", sink.received[1].Path)
		require.Equal(t, "POST", sink.received[1].Method)
		require.Equal(t, "ghi", sink.received[1].RequestId)
	})
}
