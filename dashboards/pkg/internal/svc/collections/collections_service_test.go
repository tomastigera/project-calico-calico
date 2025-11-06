package collections

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security/fake"
)

func TestCollectionsService(t *testing.T) {
	logger := logging.New("TestCollectionsService")

	newSecurityContext := func(authorized bool) security.Context {
		return security.NewUserAuthContext(
			context.Background(),
			&user.DefaultInfo{Name: "fake-user"},
			fake.NewAuthorizer(authorized),
			k8sfake.NewSimpleClientset(),
			"Bearer fake-token",
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
			},
			{
				name:        "with a collection disabled",
				collections: collections.Collections([]collections.CollectionName{collections.CollectionNameL7}),
				expectedCollectionNames: []collections.CollectionName{
					collections.CollectionNameDNS,
					collections.CollectionNameFlows,
					collections.CollectionNameWAF,
				},
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
			},
		}

		for _, tc := range testCases {

			t.Run(tc.name, func(t *testing.T) {
				subject := NewCollectionsService(logger, tc.collections)

				collectionsResponse, err := subject.Collections(newSecurityContext(true))
				require.NoError(t, err)

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

		expectMatchesGoldenYaml(t, "collections", collectionsResponse)
	})
}

func expectMatchesGoldenYaml(t *testing.T, filename string, actual client.CollectionsResponse) {
	var err error
	goldenPath := fmt.Sprintf("testdata/%s-golden.yaml", filename)
	actualPath := fmt.Sprintf("testdata/%s-actual.yaml", filename)

	actualBytes, err := yaml.Marshal(actual)
	require.NoError(t, err)

	expectedBytes, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	actualString := string(actualBytes)
	expectedString := string(expectedBytes)

	// write the actual file only if it is different to the expected, otherwise remove it
	if actualString != expectedString {
		require.NoError(t, os.WriteFile(actualPath, actualBytes, 0755))
	} else {
		_ = os.Remove(actualPath)
	}

	require.Equal(t, expectedString, actualString,
		fmt.Sprintf("goldenFile: %s, actualFile: %s", goldenPath, actualPath),
	)
}
