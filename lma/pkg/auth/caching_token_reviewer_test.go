// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package auth

import (
	"context"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authnv1 "k8s.io/api/authentication/v1"

	"github.com/projectcalico/calico/lma/pkg/cache/fake"
)

var _ = Describe("Test Caching Token Reviewer", func() {

	var (
		fakeReviewer *fakeTokenReviewer
		fakeCache    *fake.Cache[string, authnv1.TokenReviewStatus]
		subject      *cachingTokenReviewer
	)

	BeforeEach(func() {
		fakeReviewer = &fakeTokenReviewer{}
		fakeCache = fake.NewCache[string, authnv1.TokenReviewStatus]()

		subject = newCachingTokenReviewer(fakeCache, fakeReviewer)
	})

	It("should cache values and report metrics", func() {
		execute := func(ctx context.Context, spec authnv1.TokenReviewSpec, expectedHits, expectedMisses, expectedSize int) {
			_, err := subject.Review(ctx, spec)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())

			ExpectWithOffset(1, fakeCache.Hits()).To(Equal(expectedHits), "cache hits")
			ExpectWithOffset(1, fakeCache.Misses()).To(Equal(expectedMisses), "cache misses")
			ExpectWithOffset(1, fakeCache.Size()).To(Equal(expectedSize), "cache size")
		}

		ctx := context.Background()

		spec1 := authnv1.TokenReviewSpec{
			Token:     "token1",
			Audiences: nil,
		}
		spec2 := authnv1.TokenReviewSpec{
			Token:     "token1",
			Audiences: []string{"foo", "bar"},
		}
		spec3 := authnv1.TokenReviewSpec{
			Token:     "token2",
			Audiences: []string{"foo", "bar"},
		}

		execute(ctx, spec1, 0, 1, 1)
		execute(ctx, spec1, 1, 1, 1)
		execute(ctx, spec2, 1, 2, 2)
		execute(ctx, spec2, 2, 2, 2)
		execute(ctx, spec3, 2, 3, 3)
		execute(ctx, spec3, 3, 3, 3)
		execute(ctx, spec2, 4, 3, 3)
		execute(ctx, spec1, 5, 3, 3)

		fakeCache.Clear()
		execute(ctx, spec1, 5, 4, 1)
	})
})

var _ = Describe("Test Caching Token Reviewer Key", func() {
	It("should handle nil audiences", func() {
		result := toTokenReviewerCacheKey(authnv1.TokenReviewSpec{
			Token:     "token",
			Audiences: nil,
		})

		Expect(result).To(Equal("{Token:token Audiences:[]}"))
	})

	It("should handle non-nil audiences", func() {
		result := toTokenReviewerCacheKey(authnv1.TokenReviewSpec{
			Token:     "token",
			Audiences: []string{"aud1", "aud2"},
		})

		Expect(result).To(Equal("{Token:token Audiences:[aud1 aud2]}"))
	})
})

type fakeTokenReviewer struct {
	callCount atomic.Int32
}

func (f *fakeTokenReviewer) Review(_ context.Context, _ authnv1.TokenReviewSpec) (authnv1.TokenReviewStatus, error) {
	f.callCount.Add(1)
	return authnv1.TokenReviewStatus{}, nil
}
