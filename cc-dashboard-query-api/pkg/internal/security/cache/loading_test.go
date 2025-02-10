// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package cache

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/lma/pkg/cache"
)

type expensiveOperation struct {
	hitCount atomic.Int32
}

func (op *expensiveOperation) execute(input string) (string, error) {
	op.hitCount.Add(1)

	time.Sleep(10 * time.Millisecond)
	if input == "error" {
		return "", fmt.Errorf("expensive error")
	}
	return strings.ToUpper(input), nil
}

func TestLoading(t *testing.T) {

	const (
		cleanupInterval = 100 * time.Millisecond
		metricsInterval = 5 * time.Millisecond
	)

	var (
		cancelFunc   context.CancelFunc
		subject      *loading[string, string]
		backingCache cache.Cache[string, string]
		expensiveOp  *expensiveOperation
	)

	setup := func() {
		var ctx context.Context
		var err error

		ctx, cancelFunc = context.WithCancel(context.Background())

		backingCache, err = cache.NewExpiring[string, string](cache.ExpiringConfig{
			Context:                        ctx,
			Name:                           "test",
			TTL:                            3 * cleanupInterval,
			ExpiredElementsCleanupInterval: cleanupInterval,
			MetricsCollectionInterval:      metricsInterval,
		})
		require.NoError(t, err)

		subject = newLoading(backingCache)

		expensiveOp = &expensiveOperation{}
	}

	t.Cleanup(func() {
		cancelFunc()
	})
	/*
		requireSizeMetricEventually := func(expected int) {
			EventuallyWithOffset(1, func() int {
				result, err := backingCache.sizeMetric()
				Expect(err).ToNot(HaveOccurred())
				return result

			}, 5*time.Second, metricsInterval).Should(Equal(expected))
		}
	*/
	t.Run("should cache values and report metrics", func(t *testing.T) {
		setup()
		execute := func(key, value string, expectError bool, expectedHitsMetric, expectedMissesMetric, expectedSizeMetric, expectedLoadCallCount int) {
			result, err := subject.GetOrLoad(key, func() (string, error) {
				return expensiveOp.execute(key)
			})

			require.Equal(t, expectError, err != nil, key, "expectError=%b", expectError)

			//ExpectWithOffset(1, err != nil).To(Equal(expectError), key, "expectError", expectError)
			if !expectError {
				require.Equal(t, value, result, key)
				//ExpectWithOffset(1, result).To(Equal(value), key)
			}
			/*
				hits, err := backingCache.hitsMetric()
				ExpectWithOffset(1, err).ToNot(HaveOccurred())
				ExpectWithOffset(1, hits).To(Equal(expectedHitsMetric), key, "cache hits")

				misses, err := backingCache.missesMetric()
				ExpectWithOffset(1, err).ToNot(HaveOccurred())
				ExpectWithOffset(1, misses).To(Equal(expectedMissesMetric), key, "cache misses")
			*/
			loadCallCount := expensiveOp.hitCount.Load()
			require.Equal(t, int32(expectedLoadCallCount), loadCallCount, key, "load call count")

			//requireSizeMetricEventually(expectedSizeMetric)
		}

		execute("baz", "BAZ", false, 0, 1, 1, 1)
		execute("baz", "BAZ", false, 1, 1, 1, 1)
		execute("qux", "QUX", false, 1, 2, 2, 2)
		execute("qux", "QUX", false, 2, 2, 2, 2)
		execute("qux", "QUX", false, 3, 2, 2, 2)
		execute("error", "", true, 3, 3, 2, 3)

		t.Run("time passes the cache will empty", func(t *testing.T) {
			//requireSizeMetricEventually(0)
			time.Sleep(4 * time.Second)
			execute("baz", "BAZ", false, 3, 4, 1, 4)
			execute("baz", "BAZ", false, 4, 4, 1, 4)
		})
	})

	t.Run("should load once for each concurrent request for the same key", func(t *testing.T) {
		setup()
		var wg sync.WaitGroup
		var unexpectedResultCount atomic.Int32

		getOrLoad := func(key string) {
			defer wg.Done()
			result, _ := subject.GetOrLoad(key, func() (string, error) {
				return expensiveOp.execute(key)
			})
			if result != strings.ToUpper(key) {
				t.Logf("unexpected result for key %s: %s\n", key, result)
				unexpectedResultCount.Add(1)
			}
		}

		wg.Add(5)
		go getOrLoad("baz")
		go getOrLoad("baz")
		go getOrLoad("baz")
		go getOrLoad("foo")
		go getOrLoad("foo")

		wg.Wait()

		require.Equal(t, int32(2), expensiveOp.hitCount.Load())
		require.Equal(t, int32(0), unexpectedResultCount.Load(), "unexpected results returned, see logs")
	})

}
