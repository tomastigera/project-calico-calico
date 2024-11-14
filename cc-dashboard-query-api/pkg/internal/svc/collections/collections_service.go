package collections

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/httpreply"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

type CollectionsService struct {
	logger logging.Logger
}

func NewCollectionsService(logger logging.Logger) *CollectionsService {
	return &CollectionsService{
		logger: logger.Named("CollectionsService"),
	}
}

func (s *CollectionsService) Collections(ctx security.AuthContext) (client.CollectionsResponse, error) {
	s.logger.DebugC(ctx, "Collections")

	// Note: collections could be authorized individually using the resourceName field and a bulk SubjectAccessReview
	authorized, err := ctx.IsResourcePermitted(s.logger, "dashboards.calicocloud.io", "collections", "*")
	if err != nil {
		return client.CollectionsResponse{}, err
	} else if !authorized {
		return client.CollectionsResponse{}, httpreply.ReplyAccessDenied
	}
	return slices.Map(collections.Collections(), mapCollection), nil
}

func mapCollection(from collections.Collection) client.Collection {
	return client.Collection{
		Name:                 client.CollectionName(from.Name()),
		Fields:               slices.Map(from.Fields(), mapCollectionFields),
		DefaultTimeFieldName: client.CollectionFieldName(from.DefaultTimeFieldName()),
	}
}

func mapCollectionFields(from collections.CollectionField) client.CollectionField {
	collectionField := client.CollectionField{
		Name: client.CollectionFieldName(from.Name()),
		Type: client.CollectionFieldType(from.DisplayType()),
	}

	if collectionFieldEnum, ok := from.(collections.CollectionFieldEnum); ok {
		collectionField.Values = collectionFieldEnum.Values()
		collectionField.DefaultValue = collectionFieldEnum.DefaultValue()
	}

	return collectionField
}
