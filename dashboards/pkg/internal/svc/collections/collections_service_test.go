package collections

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/testutils"
)

func TestCollectionsService(t *testing.T) {
	logger := logging.New("TestCollectionsService")

	newSecurityContext := func(authorized bool) security.Context {
		authorizer, err := security.NewAuthorizer(
			t.Context(),
			logger,
			time.Second,
			security.AuthorizerConfig{
				Namespace:                             "default",
				EnableNamespacedRBAC:                  false,
				AuthorizedVerbsCacheHardTTL:           time.Second,
				AuthorizedVerbsCacheSoftTTL:           time.Second,
				AuthorizedVerbsCacheReviewsTimeout:    time.Second,
				AuthorizedVerbsCacheRevalidateTimeout: time.Second,
			},
			nil,
		)
		require.NoError(t, err)

		k8sClient := k8sfake.NewClientset()
		k8sClient.PrependReactor("create", "selfsubjectrulesreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {

			createAction, ok := action.(k8stesting.CreateAction)
			if !ok {
				return false, nil, fmt.Errorf("reactor action failed for %v (%T)", action, action)
			}

			object := createAction.GetObject().DeepCopyObject()
			selfSubjectRulesReview, ok := object.(*authzv1.SelfSubjectRulesReview)
			if !ok {
				return false, nil, fmt.Errorf("invalid reactor object, expecting *SelfSubjectRulesReview but got %v (%T)", object, object)
			}

			selfSubjectRulesReview.Status.ResourceRules = nil
			if authorized {
				selfSubjectRulesReview.Status.ResourceRules = []authzv1.ResourceRule{
					{Verbs: []string{"get"}, APIGroups: []string{security.APIGroupLMATigera}, ResourceNames: []string{"flows", "dns", "l7", "waf"}, Resources: []string{"*"}},
				}
			}
			return true, selfSubjectRulesReview, nil
		})

		return security.NewUserAuthContext(
			t.Context(),
			&user.DefaultInfo{Name: "fake-user"},
			authorizer,
			k8sClient,
			"Bearer fake-token",
			nil,
			"fake-tenant",
			nil,
		)
	}

	subject := NewCollectionsService(logger, collections.Collections(nil))

	t.Run("authorization", func(t *testing.T) {
		t.Run("authorized", func(t *testing.T) {
			_, err := subject.Collections(newSecurityContext(true))

			require.NoError(t, err)
		})
		t.Run("unauthorized", func(t *testing.T) {
			_, err := subject.Collections(newSecurityContext(false))

			require.Equal(t, err, httpreply.ReplyAccessDenied)
		})
	})

	t.Run("collection names", func(t *testing.T) {

		testCases := []struct {
			name                    string
			collections             []collections.Collection
			expectedError           error
			expectedCollectionNames []collections.CollectionName
		}{
			{
				name:        "default",
				collections: collections.Collections(nil),
				expectedCollectionNames: []collections.CollectionName{
					collections.CollectionNameDNS,
					collections.CollectionNameFlows,
					collections.CollectionNameL7,
					collections.CollectionNameWAF,
				},
				expectedError: nil,
			},
			{
				name:        "with a collection disabled",
				collections: collections.Collections([]collections.CollectionName{collections.CollectionNameL7}),
				expectedCollectionNames: []collections.CollectionName{
					collections.CollectionNameDNS,
					collections.CollectionNameFlows,
					collections.CollectionNameWAF,
				},
				expectedError: nil,
			},
			{
				name: "with all collections disabled",
				collections: collections.Collections([]collections.CollectionName{
					collections.CollectionNameL7,
					collections.CollectionNameDNS,
					collections.CollectionNameFlows,
					collections.CollectionNameWAF,
				}),
				expectedCollectionNames: []collections.CollectionName{},
				expectedError:           httpreply.ReplyAccessDenied,
			},
		}

		for _, tc := range testCases {

			t.Run(tc.name, func(t *testing.T) {
				subject := NewCollectionsService(logger, tc.collections)

				collectionsResponse, err := subject.Collections(newSecurityContext(true))
				require.Equal(t, tc.expectedError, err)

				collectionNames := slices.Map(collectionsResponse, func(collection client.Collection) collections.CollectionName {
					return collections.CollectionName(collection.Name)
				})

				require.ElementsMatch(t, collectionNames, tc.expectedCollectionNames)
			})
		}
	})

	t.Run("internal fields are absent from the collection response", func(t *testing.T) {

		flowsCollection, found := slices.Find(collections.Collections(nil), func(collection collections.Collection) bool {
			return collection.Name() == collections.CollectionNameFlows
		})
		require.True(t, found)

		internalFieldNames := slices.MapFiltered(flowsCollection.Fields(), func(field collections.CollectionField) (collections.FieldName, bool) {
			return field.Name(), field.Internal()
		})
		require.NotEmpty(t, internalFieldNames)

		response, err := subject.Collections(newSecurityContext(true))
		require.NoError(t, err)

		responseCollection, found := slices.Find(response, func(collection client.Collection) bool {
			return collections.CollectionName(collection.Name) == collections.CollectionNameFlows
		})
		require.True(t, found)

		require.Empty(t, slices.FilterBy(responseCollection.Fields, func(field client.CollectionField) bool {
			return slices.Contains(internalFieldNames, collections.FieldName(field.Name))
		}))
	})

	t.Run("matches golden files", func(t *testing.T) {

		collectionsResponse, err := subject.Collections(newSecurityContext(true))
		require.NoError(t, err)

		testutils.ExpectMatchesGoldenYaml(t, "collections", collectionsResponse)
	})
}
