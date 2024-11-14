package collections

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"sigs.k8s.io/yaml"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

func TestCollectionsService(t *testing.T) {
	ctx := security.NewUserAuthContext(context.Background(), &user.DefaultInfo{Name: "fake-user"}, security.RBACAuthorizerFunc(
		func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
			return true, nil
		}),
		"",
	)

	logger := logging.New("TestCollectionsService")

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
