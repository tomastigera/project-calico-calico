package collections

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

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
}
