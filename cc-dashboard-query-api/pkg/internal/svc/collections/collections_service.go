package collections

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
)

type CollectionsService struct {
	logger logging.Logger
}

func NewCollectionsService(logger logging.Logger) *CollectionsService {
	return &CollectionsService{
		logger: logger.WithName("CollectionsService"),
	}
}

func (s *CollectionsService) Collections(ctx security.Context) (client.CollectionsResponse, error) {
	s.logger.DebugC(ctx, "Collections")

	allCollections := collections.Collections()

	// authorize users with lma rules for any cluster
	authorized, err := ctx.IsAnyPermitted("lma.tigera.io", slices.Map(allCollections, func(c collections.Collection) string {
		// Note: this statement requires c.Name() to match the lma.tigera.io resourceNames (it currently does)
		return string(c.Name())
	}))
	if err != nil {
		return client.CollectionsResponse{}, err
	} else if !authorized {
		return client.CollectionsResponse{}, httpreply.ReplyAccessDenied
	}

	return slices.Map(allCollections, mapCollection), nil
}

func mapCollection(from collections.Collection) client.Collection {
	return client.Collection{
		Name:                 client.CollectionName(from.Name()),
		Fields:               slices.MapFiltered(from.Fields(), mapCollectionField),
		GroupBys:             slices.Map(from.GroupBys(), mapCollectionGroupBy),
		DefaultTimeFieldName: client.CollectionFieldName(from.DefaultTimeFieldName()),
	}
}

func mapCollectionField(from collections.CollectionField) (client.CollectionField, bool) {
	collectionField := client.CollectionField{
		Name:           client.CollectionFieldName(from.Name()),
		Type:           client.CollectionFieldType(from.DisplayType()),
		FilterDisabled: from.FilterDisabled(),
		AggregationFunctionTypes: slices.Map(
			from.AggregationFunctionTypes(),
			func(aggregationFunctionType collections.AggregationFunctionType) client.AggregationFunctionType {
				return client.AggregationFunctionType(aggregationFunctionType)
			},
		),
	}

	if collectionFieldEnum, ok := from.(collections.CollectionFieldEnum); ok {
		collectionField.Values = collectionFieldEnum.Values()
		collectionField.DefaultValue = collectionFieldEnum.DefaultValue()
	}

	return collectionField, !from.Internal()
}

func mapCollectionGroupBy(from collections.GroupBy) client.CollectionGroupBy {
	return client.CollectionGroupBy{
		Field:  client.CollectionFieldName(from.Field()),
		Nested: slices.ToSliceAny(slices.Map(from.Nested(), mapCollectionGroupBy)),
	}
}
