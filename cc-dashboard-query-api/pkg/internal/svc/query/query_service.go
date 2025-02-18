package query

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	validatorv10 "github.com/go-playground/validator/v10"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/filters"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/groups"
	domain "github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/repository"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/svc/managedclusters"
	"github.com/tigera/tds-apiserver/lib/comparators"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
)

type QueryService struct {
	cfg                      Config
	logger                   logging.Logger
	validator                *validatorv10.Validate
	repository               repository.Repository
	collections              []collections.Collection
	managedClusterNameLister managedclusters.NameLister
}

type Config struct {
	QueryTimeout           time.Duration
	MaxRequestFilters      int
	MaxRequestAggregations int
}

const (
	MaxQueryDocumentsLimit   = 500
	MaxQueryDocumentsDefault = 10
)

func NewQueryService(
	logger logging.Logger,
	repository repository.Repository,
	managedClusterNameLister managedclusters.NameLister,
	cfg Config,
) *QueryService {
	return &QueryService{
		cfg:                      cfg,
		logger:                   logger.WithName("QueryService"),
		repository:               repository,
		collections:              collections.Collections(),
		managedClusterNameLister: managedClusterNameLister,
		validator:                validatorv10.New(),
	}
}

func (s *QueryService) Query(ctx security.Context, req client.QueryRequest) (client.QueryResponse, error) {
	s.logger.DebugC(ctx, "Query",
		logging.Intp("maxDocs", req.MaxDocs),
		logging.String("collectionName", string(req.CollectionName)),
		logging.Any("clusterFilter", req.ClusterFilter),
		logging.Any("filters", req.Filters),
		logging.Any("groups", req.GroupBys),
		logging.Any("aggregations", req.Aggregations),
	)

	clusterID := domain.ManagedClusterName(ctx.ClusterID())

	queryCollection, err := s.validateRequest(req)
	if err != nil {
		return client.QueryResponse{}, err
	}

	// Note: this statement requires req.CollectionName to match the lma.tigera.io resourceNames (it currently does)
	authorized, err := ctx.IsResourcePermitted("lma.tigera.io", string(req.CollectionName), string(clusterID))
	if err != nil {
		return client.QueryResponse{}, err
	} else if !authorized {
		return client.QueryResponse{}, httpreply.ReplyAccessDenied
	}

	managedClusterNames, err := s.managedClusterNameLister.List(ctx)
	if err != nil {
		return client.QueryResponse{}, err
	}

	/* TODO: enable this code once linseed supports multi-cluster queries
	if len(req.ClusterFilter) > 0 {
		// filter out non-existing ManagedCluster names.
		// Note that an empty req.ClusterFilter means we'll query all managed clusters logs
		managedClusterNames = slices.FilterBy(managedClusterNames, func(managedClusterName domain.ManagedClusterName) bool {
			return slices.Contains(req.ClusterFilter, client.ManagedClusterName(managedClusterName))
		})
	}

	req.Clusters = managedClusterNames
	*/
	if !slices.Contains(managedClusterNames, clusterID) {
		return client.QueryResponse{}, httpreply.ToBadRequest(fmt.Sprintf("cluster '%s' not found", clusterID))
	}

	maxDocuments := MaxQueryDocumentsDefault

	if req.MaxDocs != nil && *req.MaxDocs >= 0 {
		maxDocuments = min(*req.MaxDocs, MaxQueryDocumentsLimit)
	}

	repositoryRequest := domain.QueryRequest{
		ClusterID:      clusterID,
		Aggregations:   make(aggregations.Aggregations),
		MaxDocuments:   maxDocuments,
		CollectionName: queryCollection.Name(),
	}

	repositoryRequest.Filters, err = slices.MapOrError(req.Filters, func(from client.QueryRequestFilter) (filters.Criterion, error) {
		return s.mapClientCriterion(ctx, from.Criterion, from.Negate, queryCollection)
	})
	if err != nil {
		return client.QueryResponse{}, err
	}

	repositoryRequest.Groups, err = slices.MapOrError(req.GroupBys, func(from client.QueryRequestGroup) (groups.Group, error) {
		return mapClientGroup(queryCollection, from)
	})
	if err != nil {
		return client.QueryResponse{}, err
	}

	for aggName, clientAggregation := range req.Aggregations {
		aggregation, err := mapClientAggregation(clientAggregation)
		if err != nil {
			return client.QueryResponse{}, err
		}

		repositoryRequest.Aggregations[aggregations.AggregationKey(aggName)] = aggregation
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, s.cfg.QueryTimeout)
	defer cancel()

	queryResult, err := s.repository.Query(ctxTimeout, repositoryRequest)
	if err != nil {
		return client.QueryResponse{}, err
	}

	queryResponse := client.QueryResponse{
		Totals: client.QueryResponseTotals{
			Value: queryResult.Hits,
		},
		GroupValues:  mapResultGroupValues(0, repositoryRequest.Groups, queryResult.GroupValues),
		Aggregations: mapResultAggregations(queryResult.Aggregations),
	}

	if len(queryResponse.GroupValues) == 0 && len(req.Aggregations) > 0 {
		// Handle the special case of a count aggregation with no groups set, which results in no elastic aggregations
		// being queried (since the count aggregation relies on document/hit count)
		for aggKey, agg := range req.Aggregations {
			switch agg.Function.Type {
			case client.AggregationFunctionTypeCount:
				if _, found := queryResponse.Aggregations[string(aggKey)]; !found {
					queryResponse.Aggregations[string(aggKey)] = client.QueryResponseValueAsString{
						AsString: strconv.FormatInt(queryResult.Hits, 10),
					}
				}
			}
		}
	}

	queryResponse.Documents = slices.Map(
		slices.SortByComparing( // sort desc by @timestamp
			queryResult.Documents,
			comparators.Func[result.QueryResultDocument](func(doc1, doc2 result.QueryResultDocument) int {
				if doc1.Timestamp.UnixMicro() == doc2.Timestamp.UnixMicro() {
					return 0
				} else if doc1.Timestamp.UnixMicro() > doc2.Timestamp.UnixMicro() {
					return -1
				}
				return 1
			})), func(doc result.QueryResultDocument) any {
			return doc.Content
		})

	if len(queryResponse.Documents) > maxDocuments {
		queryResponse.Documents = queryResponse.Documents[:maxDocuments]
	}

	return queryResponse, nil
}

func (s *QueryService) validateRequest(req client.QueryRequest) (collections.Collection, error) {
	if err := s.validator.Struct(req); err != nil {
		return collections.Collection{}, httpreply.ToBadRequest(fmt.Sprintf("invalid request: %v", err))
	}

	timeRangeSelectors := slices.FilterBy(req.Filters, func(filter client.QueryRequestFilter) bool {
		return filter.Criterion.Type == client.CriterionTypeRelativeTimeRange ||
			filter.Criterion.Type == client.CriterionTypeDateRange
	})

	if len(timeRangeSelectors) == 0 {
		return collections.Collection{}, httpreply.ToBadRequest("no time range filter set")
	} else if len(timeRangeSelectors) > 1 {
		return collections.Collection{}, httpreply.ToBadRequest("multiple time range filters set")
	}

	queryCollection, found := slices.Find(s.collections, func(c collections.Collection) bool {
		return c.Name() == collections.CollectionName(req.CollectionName)
	})
	if !found {
		return collections.Collection{}, httpreply.ToBadRequest(fmt.Sprintf("unknown collection '%s'", req.CollectionName))
	}

	if len(req.Filters) > s.cfg.MaxRequestFilters {
		return collections.Collection{}, httpreply.ToBadRequest("filters limit exceeded")
	}

	if len(req.Aggregations) > s.cfg.MaxRequestAggregations {
		return collections.Collection{}, httpreply.ToBadRequest("aggregations limit exceeded")
	}

	// Enforce collection groupBys combination tree
	collectionGroupBys := queryCollection.GroupBys()
	for _, groupBy := range req.GroupBys {
		collectionGroupBy, found := slices.Find(collectionGroupBys, func(g collections.GroupBy) bool {
			return g.Field() == collections.FieldName(groupBy.FieldName)
		})

		if !found {
			fieldNames := slices.Map(req.GroupBys, func(g client.QueryRequestGroup) string { return g.FieldName })

			return collections.Collection{}, httpreply.ToBadRequest(fmt.Sprintf("invalid group combination: %s", strings.Join(fieldNames, ",")))
		}

		collectionGroupBys = collectionGroupBy.Nested()
	}

	return queryCollection, nil
}

var reRemovePrefix = regexp.MustCompile(`^PT`)

func (s *QueryService) mapClientCriterion(
	ctx context.Context,
	from client.QueryRequestFilterCriterion,
	negate bool,
	queryCollection collections.Collection,
) (filters.Criterion, error) {

	getCollectionField := func(fieldName string) (collections.CollectionField, error) {
		field, found := queryCollection.Field(collections.FieldName(fieldName))
		if !found {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("unknown collection field name '%s' for criterion type '%s'", fieldName, from.Type))
		}
		return field, nil
	}

	errInvalidFieldType := httpreply.ToBadRequest(fmt.Sprintf("invalid collection field '%s' for criterion type '%s'", from.Field, from.Type))

	switch from.Type {
	case client.CriterionTypeEquals:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		return filters.NewEquals(field, from.Value, negate), nil
	case client.CriterionTypeStartsWith:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		value, ok := from.Value.(string)
		if !ok {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid value '%v' for criterion type '%s'", from.Value, from.Type))
		}
		return filters.NewStartsWith(field, value, negate), nil
	case client.CriterionTypeExists:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		if field.Type() != collections.FieldTypeText {
			// Exists field is not supported for non-text fields in linseed atm
			// See https://tigera.atlassian.net/browse/TSLA-8361
			// See https://tigera.atlassian.net/browse/TSLA-8406
			return nil, errInvalidFieldType
		}
		return filters.NewExists(field, negate), nil
	case client.CriterionTypeIn:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		return filters.NewIn(field, from.Values, negate), nil
	case client.CriterionTypeWildcard:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		return filters.NewWildcard(field, from.Pattern, negate), nil
	case client.CriterionTypeOr:
		fromCriteria, err := from.GetCriteria()
		if err != nil {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("failed to parse or criteria: %v", err))
		}
		criteria, err := slices.MapOrError(fromCriteria, func(subCriterion client.QueryRequestFilterCriterion) (filters.Criterion, error) {
			return s.mapClientCriterion(ctx, subCriterion, negate, queryCollection)
		})
		if err != nil {
			return nil, err
		}
		return filters.NewOr(criteria, negate), nil
	case client.CriterionTypeRange:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		if !field.Type().Is(collections.FieldTypeNumber) {
			return nil, errInvalidFieldType
		}

		var gte, lte *int64
		if from.GTE != "" {
			if value, err := strconv.ParseInt(from.GTE, 10, 64); err != nil {
				message := fmt.Sprintf("failed to parse %s gte field: %s", from.Type, from.GTE)
				s.logger.ErrorC(ctx, message, logging.Error(err))
				return nil, httpreply.ToBadRequest(message)
			} else {
				gte = &value
			}
		}

		if from.LTE != "" {
			if value, err := strconv.ParseInt(from.LTE, 10, 64); err != nil {
				message := fmt.Sprintf("failed to parse %s lte field: %s", from.Type, from.LTE)
				s.logger.ErrorC(ctx, message, logging.Error(err))
				return nil, httpreply.ToBadRequest(message)
			} else {
				lte = &value
			}
		}

		if lte == nil && gte == nil ||
			(lte != nil && gte != nil && *lte < *gte) {
			return nil, httpreply.ToBadRequest("invalid gte and lte values for range criterion")
		}
		return filters.NewRange(field, gte, lte, negate), nil
	case client.CriterionTypeIPRange:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		} else if !field.Type().Is(collections.FieldTypeIP) {
			return nil, errInvalidFieldType
		}
		return filters.NewIPRange(field, from.From, from.To, negate), nil
	case client.CriterionTypeDateRange:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		} else if field.Type() != collections.FieldTypeDate {
			return nil, errInvalidFieldType
		}

		gte, err := parseDateRangeTime(from.GTE)
		if err != nil {
			message := fmt.Sprintf("invalid value '%s' for criterion type '%s' gte field", from.GTE, from.Type)
			s.logger.ErrorC(ctx, message, logging.Error(err))
			return nil, httpreply.ToBadRequest(message)
		}

		var lte *time.Time
		if from.LTE != "" {
			value, err := parseDateRangeTime(from.LTE)
			if err != nil {
				message := fmt.Sprintf("invalid value '%s' for criterion type '%s' lte field", from.LTE, from.Type)
				s.logger.ErrorC(ctx, message, logging.Error(err))
				return nil, httpreply.ToBadRequest(message)
			}
			lte = &value
		}

		return filters.NewDateRange(field, gte, lte, negate), nil
	case client.CriterionTypeRelativeTimeRange:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		if field.Type() != collections.FieldTypeDate {
			return nil, errInvalidFieldType
		}

		var gteDuration, lteDuration time.Duration
		if gte := strings.ToLower(reRemovePrefix.ReplaceAllString(from.GTE, "")); gte != "" {
			if gteDuration, err = time.ParseDuration(gte); err != nil {
				message := fmt.Sprintf("invalid value for relativeTimeRange gte field: %s", gte)
				s.logger.ErrorC(ctx, message, logging.Error(err))
				return nil, httpreply.ToBadRequest(message)
			}
		}

		if lte := strings.ToLower(reRemovePrefix.ReplaceAllString(from.LTE, "")); lte != "" {
			if lteDuration, err = time.ParseDuration(lte); err != nil {
				message := fmt.Sprintf("invalid value for relativeTimeRange lte field: %s", lte)
				s.logger.ErrorC(ctx, message, logging.Error(err))
				return nil, httpreply.ToBadRequest(message)
			}
		}

		criterion, err := filters.NewRelativeTimeRange(field, gteDuration, lteDuration, negate)
		if err != nil {
			return nil, httpreply.ToBadRequest(err.Error())
		}
		return criterion, nil
	}

	return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid filter criterion type: %s", from.Type))
}

func mapClientGroup(collection collections.Collection, from client.QueryRequestGroup) (groups.Group, error) {
	sortOrder := groups.GroupSortOrder{
		Asc: true,
	}

	if from.Order != nil {
		sortOrder.Type = groups.GroupSortOrderType(from.Order.Type)
		sortOrder.Asc = from.Order.SortAsc
		sortOrder.AggregationKey = from.Order.AggKey
	}

	collectionField, found := collection.Field(collections.FieldName(from.FieldName))
	if !found {
		return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid field name: %s", from.FieldName))
	}

	if collectionField.Type() == collections.FieldTypeDate {
		if sortOrder.Type == "" {
			sortOrder.Type = groups.GroupSortOrderTypeSelf // default time group sort order is by key
		}
		return groups.NewGroupTime(from.FieldName, from.Interval, from.MaxValues, sortOrder), nil
	}

	if sortOrder.Type == "" {
		sortOrder.Type = groups.GroupSortOrderTypeCount // default discrete group sort order is by count
	}
	return groups.NewGroupDiscrete(from.FieldName, from.MaxValues, sortOrder), nil
}

func mapClientAggregation(from client.QueryRequestAggregation) (aggregations.Aggregation, error) {
	switch from.Function.Type {
	case client.AggregationFunctionTypeCount:
		return aggregations.NewAggregationCount(), nil
	case client.AggregationFunctionTypeSum:
		return aggregations.NewAggregationSum(from.FieldName), nil
	case client.AggregationFunctionTypeAvg:
		return aggregations.NewAggregationAvg(from.FieldName), nil
	case client.AggregationFunctionTypeMin:
		return aggregations.NewAggregationMin(from.FieldName), nil
	case client.AggregationFunctionTypeMax:
		return aggregations.NewAggregationMax(from.FieldName), nil
	case client.AggregationFunctionTypePercentile:
		return aggregations.NewAggregationPercentile(from.FieldName, from.Function.Percentile), nil
	case client.AggregationFunctionTypePercentile50:
		return aggregations.NewAggregationPercentile(from.FieldName, 50), nil
	case client.AggregationFunctionTypePercentile90:
		return aggregations.NewAggregationPercentile(from.FieldName, 90), nil
	case client.AggregationFunctionTypePercentile95:
		return aggregations.NewAggregationPercentile(from.FieldName, 95), nil
	case client.AggregationFunctionTypePercentile100:
		return aggregations.NewAggregationPercentile(from.FieldName, 100), nil
	}

	return nil, fmt.Errorf("unknown aggregation type '%s'", from.Function.Type)
}

func mapResultGroupValues(groupIndex int, repositoryRequestGroups groups.Groups, groupValues groups.GroupValues) []client.QueryResponseGroupValue {
	values := slices.Map(groupValues, func(from *groups.GroupValue) client.QueryResponseGroupValue {
		var nestedValues []any
		if from.SubGroupValues != nil {
			nestedValues = slices.Map(
				mapResultGroupValues(groupIndex+1, repositoryRequestGroups, from.SubGroupValues),
				func(from client.QueryResponseGroupValue) any {
					return from
				})
		}
		return client.QueryResponseGroupValue{
			Key:          from.Key,
			Aggregations: mapResultAggregations(from.Aggregations),
			NestedValues: nestedValues,
		}
	})

	if groupIndex < len(repositoryRequestGroups) {
		maxValues := repositoryRequestGroups[groupIndex].MaxValues()
		if maxValues > 0 && len(values) > maxValues { // NOTE: a max number of group results limit could be implemented here
			values = values[:maxValues]
		}
	}
	return values
}

func mapResultAggregations(resultAggregations aggregations.AggregationValues) client.QueryResponseAggregations {
	clientAggregations := make(client.QueryResponseAggregations)

	for aggKey, aggValue := range resultAggregations {
		responseValue := client.QueryResponseValueAsString{
			AsString: "0",
		}
		value := aggValue.Value()

		if !reflect.ValueOf(value).IsNil() {
			switch v := value.(type) {
			case *float64:
				responseValue.AsString = strconv.FormatFloat(*v, 'f', -1, 64)
			case *int64:
				responseValue.AsString = strconv.FormatInt(*v, 10)
			}
		}

		clientAggregations[aggKey] = responseValue
	}
	return clientAggregations
}

func parseDateRangeTime(dateRangeTime string) (time.Time, error) {
	validDateRangeTimeFormats := []string{
		time.DateOnly,
		"2006-01-02T15:04:05",
		time.RFC3339,
		time.RFC3339Nano,
	}

	var t time.Time
	var err error
	for _, timeFormat := range validDateRangeTimeFormats {
		t, err = time.Parse(timeFormat, dateRangeTime)
		if err == nil {
			return t, nil
		}
	}
	return t, err
}
