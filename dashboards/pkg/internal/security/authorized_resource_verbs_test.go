package security

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakeprojectcalicov3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3/fake"
	"github.com/tigera/tds-apiserver/lib/logging"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	testing2 "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/lma/pkg/k8s"
)

func TestAuthorizedResourcesVerbsCacheItem(t *testing.T) {

	logger := logging.New("TestAuthorizedResourcesVerbsCacheItem")

	newUserAuthContext := func() (Context, *fakeprojectcalicov3.FakeProjectcalicoV3, *k8s.MockClientSetFactory) {

		scheme := runtime.NewScheme()
		require.NoError(t, v3.AddToScheme(scheme))
		require.NoError(t, fake.AddToScheme(scheme))

		k8sClient := dynamicfake.NewSimpleDynamicClient(scheme)
		fakeCalicoClient := &fakeprojectcalicov3.FakeProjectcalicoV3{Fake: &k8sClient.Fake}

		mockClientSetFactory := k8s.NewMockClientSetFactory(t)

		ctx := NewUserAuthContext(
			context.Background(),
			&user.DefaultInfo{Name: "fake-user"},
			nil,
			nil,
			"Bearer fake-token",
			mockClientSetFactory,
		)

		return ctx, fakeCalicoClient, mockClientSetFactory
	}

	t.Run("does not revalidate unexpired item", func(t *testing.T) {
		ctx, _, _ := newUserAuthContext()

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
		ctx, fakeCalicoClient, mockClientSetFactory := newUserAuthContext()

		mockClientSet := k8s.NewMockClientSet(t)
		mockClientSet.On("ProjectcalicoV3").Return(fakeCalicoClient)
		mockClientSetFactory.
			On("NewClientSetForApplication", "fake-resource").
			Return(mockClientSet, nil).
			Once()

		fakeCalicoClient.PrependReactor(
			"create",
			"authorizationreviews",
			func(action testing2.Action) (handled bool, ret runtime.Object, err error) {
				createAction, ok := action.(testing2.CreateAction)
				if !ok {
					return true, nil, fmt.Errorf("expected CreateAction, got %T: %v", action, action)
				}

				authorizationReview, ok := createAction.GetObject().(*v3.AuthorizationReview)
				if !ok {
					return true, nil, fmt.Errorf("expected AuthorizationReview, got %T: %v", ret, ret)
				}

				authorizationReview.Status.AuthorizedResourceVerbs = []v3.AuthorizedResourceVerbs{{
					APIGroup: "projectcalico.org",
					Resource: "fake-resource",
					Verbs: []v3.AuthorizedResourceVerb{{
						Verb: "list",
						ResourceGroups: []v3.AuthorizedResourceGroup{{
							Namespace: "fake-namespace",
						}},
					}},
				}}

				return true, authorizationReview, nil
			})

		revalidateAt := time.Now().Add(-1 * time.Hour)
		arbCacheEntry := authorizedResourcesVerbsCacheEntry{
			revalidateAt: revalidateAt,
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
		ctx, fakeCalicoClient, mockClientSetFactory := newUserAuthContext()

		mockClientSet := k8s.NewMockClientSet(t)
		mockClientSet.On("ProjectcalicoV3").Return(fakeCalicoClient)
		mockClientSetFactory.
			On("NewClientSetForApplication", "fake-resource").
			Return(mockClientSet, nil).
			Once()

		fakeCalicoClient.PrependReactor(
			"create",
			"authorizationreviews",
			func(action testing2.Action) (handled bool, ret runtime.Object, err error) {
				return true, nil, errors.New("an expected error")
			})

		revalidateAt := time.Now().Add(-1 * time.Hour)
		arbCacheEntry := authorizedResourcesVerbsCacheEntry{
			revalidateAt: revalidateAt,
		}

		err := arbCacheEntry.Revalidate(ctx, logger, "fake-resource", 5*time.Second, 10*time.Second)
		require.Error(t, err)
		require.ErrorContains(t, err, "an expected error")
	})

	t.Run("performs a single successful AuthorizationReview for concurrent revalidations", func(t *testing.T) {
		ctx, fakeCalicoClient, mockClientSetFactory := newUserAuthContext()

		mockClientSet := k8s.NewMockClientSet(t)
		mockClientSet.On("ProjectcalicoV3").Return(fakeCalicoClient)
		mockClientSetFactory.
			On("NewClientSetForApplication", "fake-resource").
			Return(mockClientSet, nil).
			Once()

		var authorizationReviews []*v3.AuthorizationReview
		fakeCalicoClient.PrependReactor(
			"create",
			"authorizationreviews",
			func(action testing2.Action) (handled bool, ret runtime.Object, err error) {
				createAction, ok := action.(testing2.CreateAction)
				if !ok {
					return true, nil, fmt.Errorf("expected CreateAction, got %T: %v", action, action)
				}

				authorizationReview, ok := createAction.GetObject().(*v3.AuthorizationReview)
				if !ok {
					return true, nil, fmt.Errorf("expected AuthorizationReview, got %T: %v", ret, ret)
				}

				authorizationReview.Status.AuthorizedResourceVerbs = []v3.AuthorizedResourceVerbs{{
					APIGroup: "projectcalico.org",
					Resource: "fake-resource",
					Verbs: []v3.AuthorizedResourceVerb{{
						Verb: "list",
						ResourceGroups: []v3.AuthorizedResourceGroup{{
							Namespace: fmt.Sprintf("fake-namespace%d", 1+len(authorizationReviews)),
						}},
					}},
				}}

				authorizationReviews = append(authorizationReviews, authorizationReview)

				// Delay response so other goroutines can catch up in case there is a bug
				time.Sleep(1 * time.Second)

				return true, authorizationReview, nil
			})

		revalidateAt := time.Now().Add(-1 * time.Hour)
		arbCacheEntry := authorizedResourcesVerbsCacheEntry{
			revalidateAt: revalidateAt,
		}

		ch := make(chan error, 10)
		for i := 0; i < 10; i++ {
			go func() {
				ch <- arbCacheEntry.Revalidate(ctx, logger, "fake-resource", 5*time.Second, 10*time.Second)
			}()
		}

		for i := 0; i < 10; i++ {
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

		require.Len(t, authorizationReviews, 1)
	})
}
