// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package cache

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type fakeExpensiveOperation struct {
	hitCount atomic.Int32
}

func (op *fakeExpensiveOperation) execute(input string) (string, error) {
	op.hitCount.Add(1)

	time.Sleep(10 * time.Millisecond)
	if input == "error" {
		return "", fmt.Errorf("expensive error")
	}
	return strings.ToUpper(input), nil
}

var _ = Describe("Test Loading", func() {

	const (
		cleanupInterval = 100 * time.Millisecond
		metricsInterval = 5 * time.Millisecond
	)

	var (
		cancel       context.CancelFunc
		subject      *loading[string, string]
		backingCache *expiring[string, string]
		expensiveOp  *fakeExpensiveOperation
	)

	BeforeEach(func() {
		var ctx context.Context
		var err error

		ctx, cancel = context.WithCancel(context.Background())

		backingCache, err = newExpiring[string, string](ExpiringConfig{
			Context:                        ctx,
			Name:                           fmt.Sprintf("loading-test-%d", time.Now().UnixMicro()),
			TTL:                            3 * cleanupInterval,
			ExpiredElementsCleanupInterval: cleanupInterval,
			MetricsCollectionInterval:      metricsInterval,
		})
		Expect(err).ToNot(HaveOccurred())

		subject = newLoading[string, string](backingCache)

		expensiveOp = &fakeExpensiveOperation{}
	})

	AfterEach(func() {
		cancel()
	})

	requireSizeMetricEventually := func(expected int, description string) {
		EventuallyWithOffset(1, func() int {
			result, err := backingCache.sizeMetric()
			Expect(err).ToNot(HaveOccurred())
			return result

		}, 5*time.Second, metricsInterval).Should(Equal(expected), description+": size metric")
	}

	It("should cache values and report metrics", func() {

		type TestCase struct {
			Key                  string
			Value                string
			ExpectError          bool
			ExpectedHitsMetric   int
			ExpectedMissesMetric int
			ExpectedSizeMetric   int
			ExpectedLoadCalls    int
			Description          string
		}

		execute := func(tc TestCase) {
			result, err := subject.GetOrLoad(tc.Key, func() (string, error) {
				return expensiveOp.execute(tc.Key)
			})
			Expect(err != nil).To(Equal(tc.ExpectError), tc.Key, tc.Description+" expectError", tc.ExpectError)
			if !tc.ExpectError {
				Expect(result).To(Equal(tc.Value), tc.Key)
			}

			hits, err := backingCache.hitsMetric()
			Expect(err).ToNot(HaveOccurred())
			Expect(hits).To(Equal(tc.ExpectedHitsMetric), tc.Key, tc.Description+": cache hits")

			misses, err := backingCache.missesMetric()
			Expect(err).ToNot(HaveOccurred())
			Expect(misses).To(Equal(tc.ExpectedMissesMetric), tc.Key, tc.Description+": cache misses")

			loadCallCount := expensiveOp.hitCount.Load()
			Expect(loadCallCount).To(Equal(int32(tc.ExpectedLoadCalls)), tc.Key, tc.Description+": load call count")

			if tc.ExpectedSizeMetric >= 0 {
				requireSizeMetricEventually(tc.ExpectedSizeMetric, tc.Description)
			}
		}

		execute(TestCase{
			Description:          "first key should miss",
			Key:                  "baz",
			Value:                "BAZ",
			ExpectedHitsMetric:   0,
			ExpectedMissesMetric: 1,
			ExpectedSizeMetric:   1,
			ExpectedLoadCalls:    1,
		})
		execute(TestCase{
			Description:          "first key should hit",
			Key:                  "baz",
			Value:                "BAZ",
			ExpectedHitsMetric:   1,
			ExpectedMissesMetric: 1,
			ExpectedSizeMetric:   1,
			ExpectedLoadCalls:    1,
		})
		execute(TestCase{
			Description:          "second key should miss",
			Key:                  "qux",
			Value:                "QUX",
			ExpectedHitsMetric:   1,
			ExpectedMissesMetric: 2,
			ExpectedSizeMetric:   2,
			ExpectedLoadCalls:    2,
		})
		execute(TestCase{
			Description:          "second key should hit",
			Key:                  "qux",
			Value:                "QUX",
			ExpectedHitsMetric:   2,
			ExpectedMissesMetric: 2,
			ExpectedSizeMetric:   2,
			ExpectedLoadCalls:    2,
		})
		execute(TestCase{
			Description:          "second key should hit again",
			Key:                  "qux",
			Value:                "QUX",
			ExpectedHitsMetric:   3,
			ExpectedMissesMetric: 2,
			ExpectedSizeMetric:   2,
			ExpectedLoadCalls:    2,
		})
		execute(TestCase{
			Description:          "special error key should miss and return an error",
			Key:                  "error",
			ExpectError:          true,
			ExpectedHitsMetric:   3,
			ExpectedMissesMetric: 3,
			ExpectedSizeMetric:   -1,
			ExpectedLoadCalls:    3,
		})

		By("time passes the cache will empty")
		requireSizeMetricEventually(0, "after TTL")
		execute(TestCase{
			Description:          "first key should miss after TTL",
			Key:                  "baz",
			Value:                "BAZ",
			ExpectedHitsMetric:   3,
			ExpectedMissesMetric: 4,
			ExpectedSizeMetric:   1,
			ExpectedLoadCalls:    4,
		})
		execute(TestCase{
			Description:          "first key should hit again",
			Key:                  "baz",
			Value:                "BAZ",
			ExpectedHitsMetric:   4,
			ExpectedMissesMetric: 4,
			ExpectedSizeMetric:   1,
			ExpectedLoadCalls:    4,
		})
	})

	It("should load once for each concurrent request for the same key", func() {
		var wg sync.WaitGroup
		var unexpectedResultCount atomic.Int32

		getOrLoad := func(key string) {
			defer wg.Done()
			result, _ := subject.GetOrLoad(key, func() (string, error) {
				return expensiveOp.execute(key)
			})
			if result != strings.ToUpper(key) {
				_, err := fmt.Fprintf(GinkgoWriter, "unexpected result for key %s: %s\n", key, result)
				Expect(err).ToNot(HaveOccurred())
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

		Expect(expensiveOp.hitCount.Load()).To(Equal(int32(2)), "expected 2 load calls")
		Expect(unexpectedResultCount.Load()).To(Equal(int32(0)), "unexpected results returned, see logs")
	})

	It("should not write to the cache if the load fails", func() {
		key := "error"
		result, err := subject.GetOrLoad(key, func() (string, error) {
			return expensiveOp.execute(key)
		})
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Equal("expensive error"))
		Expect(result).To(Equal(""), "result should be empty")

		_, cached := backingCache.Get(key)
		Expect(cached).To(BeFalse(), "key should not be in the cache")
	})

})
