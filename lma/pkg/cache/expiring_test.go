// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package cache

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/patrickmn/go-cache"
)

var _ = Describe("Test Expiring", func() {

	const (
		cleanupInterval = 100 * time.Millisecond
		metricsInterval = 5 * time.Millisecond
	)

	var (
		cancelFunc context.CancelFunc
		subject    *expiring[string, string]
	)

	BeforeEach(func() {
		var ctx context.Context
		var err error

		ctx, cancelFunc = context.WithCancel(context.Background())

		subject, err = newExpiring[string, string](ExpiringConfig{
			Context:                        ctx,
			Name:                           "test",
			TTL:                            3 * cleanupInterval,
			ExpiredElementsCleanupInterval: cleanupInterval,
			MetricsCollectionInterval:      metricsInterval,
		})
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		cancelFunc()
	})

	requireSizeMetricEventually := func(expected int) {
		EventuallyWithOffset(1, func() int {
			result, err := subject.sizeMetric()
			Expect(err).ToNot(HaveOccurred())
			return result

		}, 5*time.Second, metricsInterval).Should(Equal(expected))
	}

	execute := func(key, value string, expectHit bool, expectedHitsMetric, expectedMissesMetric, expectedSizeMetric int) {
		result, hit := subject.Get(key)
		ExpectWithOffset(1, hit).To(Equal(expectHit), key)
		if hit {
			ExpectWithOffset(1, result).To(Equal(value), key)
		} else {
			subject.Set(key, value)
		}

		hits, err := subject.hitsMetric()
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		ExpectWithOffset(1, hits).To(Equal(expectedHitsMetric), key, "cache hits")

		misses, err := subject.missesMetric()
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		ExpectWithOffset(1, misses).To(Equal(expectedMissesMetric), key, "cache misses")

		requireSizeMetricEventually(expectedSizeMetric)
	}

	It("should cache values and report metrics", func() {

		execute("baz", "a", false, 0, 1, 1)
		execute("baz", "a", true, 1, 1, 1)
		execute("qux", "b", false, 1, 2, 2)
		execute("qux", "b", true, 2, 2, 2)
		execute("qux", "b", true, 3, 2, 2)

		By("waiting for the cache to empty after time passes")
		requireSizeMetricEventually(0)
		execute("baz", "x", false, 3, 3, 1)
		execute("baz", "x", true, 4, 3, 1)
	})

	It("should panic when a value of the wrong type is encountered", func() {
		key := "some-key"
		subject.cache.Set(key, 42, cache.DefaultExpiration)

		Expect(func() { subject.Get(key) }).To(PanicWith(Equal("value of wrong type found in cache - expected: string, actual: int: 42")))
	})

})
