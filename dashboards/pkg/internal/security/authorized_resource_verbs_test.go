package security

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/logging"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/lma/pkg/k8s"
)

// mockReviewer implements authzreview.Reviewer for tests.
type mockReviewer struct {
	fn func(ctx context.Context, usr user.Info, cluster string, attrs []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error)
}

func (m *mockReviewer) Review(ctx context.Context, usr user.Info, cluster string, attrs []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error) {
	return m.fn(ctx, usr, cluster, attrs)
}

func (m *mockReviewer) ReviewForLogs(ctx context.Context, usr user.Info, cluster string) ([]v3.AuthorizedResourceVerbs, error) {
	return m.Review(ctx, usr, cluster, nil)
}

func TestAuthorizedResourcesVerbsCacheItem(t *testing.T) {

	logger := logging.New("TestAuthorizedResourcesVerbsCacheItem")

	newUserAuthContext := func() Context {
		mockClientSetFactory := k8s.NewMockClientSetFactory(t)

		ctx := NewUserAuthContext(
			context.Background(),
			&user.DefaultInfo{Name: "fake-user"},
			nil,
			nil,
			"Bearer fake-token",
			mockClientSetFactory,
			"fake-tenant",
			nil,
		)

		return ctx
	}

	t.Run("does not revalidate unexpired item", func(t *testing.T) {
		ctx := newUserAuthContext()

		revalidateAt := time.Now().Add(1 * time.Hour)
		arbCacheEntry := authorizedResourcesVerbsCacheEntry{
			revalidateAt: revalidateAt,
		}

		err := arbCacheEntry.Revalidate(ctx, logger, "fake-resource", 1*time.Minute, 2*time.Minute)
		require.NoError(t, err)
		require.Equal(t, revalidateAt, arbCacheEntry.revalidateAt)
		require.Len(t, arbCacheEntry.authorizedResourceVerbs, 0)
	})

	t.Run("revalidates expired item", func(t *testing.T) {
		ctx := newUserAuthContext()

		reviewer := &mockReviewer{fn: func(_ context.Context, _ user.Info, _ string, _ []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error) {
			return []v3.AuthorizedResourceVerbs{{
				APIGroup: "projectcalico.org",
				Resource: "fake-resource",
				Verbs: []v3.AuthorizedResourceVerb{{
					Verb: "list",
					ResourceGroups: []v3.AuthorizedResourceGroup{{
						Namespace: "fake-namespace",
					}},
				}},
			}}, nil
		}}

		revalidateAt := time.Now().Add(-1 * time.Hour)
		arbCacheEntry := authorizedResourcesVerbsCacheEntry{
			revalidateAt: revalidateAt,
			reviewer:     reviewer,
		}

		err := arbCacheEntry.Revalidate(ctx, logger, "fake-resource", 5*time.Second, 10*time.Second)
		require.NoError(t, err)
		require.Greater(t, arbCacheEntry.revalidateAt, revalidateAt)
		require.Equal(t, []v3.AuthorizedResourceVerbs{{
			APIGroup: "projectcalico.org",
			Resource: "fake-resource",
			Verbs: []v3.AuthorizedResourceVerb{{
				Verb: "list",
				ResourceGroups: []v3.AuthorizedResourceGroup{{
					Namespace: "fake-namespace",
				}},
			}},
		}}, arbCacheEntry.authorizedResourceVerbs)
	})

	t.Run("return revalidation error", func(t *testing.T) {
		ctx := newUserAuthContext()

		reviewer := &mockReviewer{fn: func(_ context.Context, _ user.Info, _ string, _ []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error) {
			return nil, fmt.Errorf("an expected error")
		}}

		revalidateAt := time.Now().Add(-1 * time.Hour)
		arbCacheEntry := authorizedResourcesVerbsCacheEntry{
			revalidateAt: revalidateAt,
			reviewer:     reviewer,
		}

		err := arbCacheEntry.Revalidate(ctx, logger, "fake-resource", 5*time.Second, 10*time.Second)
		require.Error(t, err)
	})

	t.Run("performs a single successful AuthorizationReview for concurrent revalidations", func(t *testing.T) {
		ctx := newUserAuthContext()

		var reviewCount atomic.Int32
		reviewer := &mockReviewer{fn: func(_ context.Context, _ user.Info, _ string, _ []v3.AuthorizationReviewResourceAttributes) ([]v3.AuthorizedResourceVerbs, error) {
			count := reviewCount.Add(1)

			// Delay response so other goroutines can catch up in case there is a bug
			time.Sleep(1 * time.Second)

			return []v3.AuthorizedResourceVerbs{{
				APIGroup: "projectcalico.org",
				Resource: "fake-resource",
				Verbs: []v3.AuthorizedResourceVerb{{
					Verb: "list",
					ResourceGroups: []v3.AuthorizedResourceGroup{{
						Namespace: fmt.Sprintf("fake-namespace%d", count),
					}},
				}},
			}}, nil
		}}

		revalidateAt := time.Now().Add(-1 * time.Hour)
		arbCacheEntry := authorizedResourcesVerbsCacheEntry{
			revalidateAt: revalidateAt,
			reviewer:     reviewer,
		}

		ch := make(chan error, 10)
		for range 10 {
			go func() {
				ch <- arbCacheEntry.Revalidate(ctx, logger, "fake-resource", 5*time.Second, 10*time.Second)
			}()
		}

		for range 10 {
			require.NoError(t, <-ch)
			require.Equal(t, []v3.AuthorizedResourceVerbs{{
				APIGroup: "projectcalico.org",
				Resource: "fake-resource",
				Verbs: []v3.AuthorizedResourceVerb{{
					Verb: "list",
					ResourceGroups: []v3.AuthorizedResourceGroup{{
						Namespace: "fake-namespace1",
					}},
				}},
			}}, arbCacheEntry.authorizedResourceVerbs)
		}

		require.Equal(t, int32(1), reviewCount.Load())
	})
}
