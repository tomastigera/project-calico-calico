package collections

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security/fake"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
)

func TestCollectionsService(t *testing.T) {
	logger := logging.New("TestCollectionsService")

	ctx := security.NewUserAuthContext(
		context.Background(),
		&user.DefaultInfo{Name: "fake-user"},
		"tigera-labs",
		fake.NewAuthorizer(true),
		k8sfake.NewSimpleClientset(),
	)

	subject := NewCollectionsService(logger)

	t.Run("collection names", func(t *testing.T) {

		collectionsResponse, err := subject.Collections(ctx)
		require.NoError(t, err)

		collectionMap := slices.AssociateBy(collectionsResponse, func(collection client.Collection) client.CollectionName {
			return collection.Name
		})

		require.Len(t, collectionMap, 3)
		require.Contains(t, collectionMap, client.CollectionName(collections.CollectionNameL7))
		require.Contains(t, collectionMap, client.CollectionName(collections.CollectionNameDNS))
		require.Contains(t, collectionMap, client.CollectionName(collections.CollectionNameFlows))
	})

	t.Run("internal fields are absent from the collection response", func(t *testing.T) {

		flowsCollection, found := slices.Find(collections.Collections(), func(collection collections.Collection) bool {
			return collection.Name() == collections.CollectionNameFlows
		})
		require.True(t, found)

		internalFieldNames := slices.MapFiltered(flowsCollection.Fields(), func(field collections.CollectionField) (collections.FieldName, bool) {
			return field.Name(), field.Internal()
		})
		require.NotEmpty(t, internalFieldNames)

		response, err := subject.Collections(ctx)
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

		collectionsResponse, err := subject.Collections(ctx)
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
