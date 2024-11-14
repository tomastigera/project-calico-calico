package query

import (
	"context"
	"fmt"
	"iter"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	validatorv10 "github.com/go-playground/validator/v10"
	"go.uber.org/zap"

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
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/httpreply"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

type QueryService struct {
	logger                   logging.Logger
	timeout                  time.Duration
	validator                *validatorv10.Validate
	repository               repository.Repository
	collections              []collections.Collection
	tenantNamespace          string
	managedClusterNameLister managedclusters.NameLister
}

const (
	MaxQueryDocumentsLimit   = 500
	MaxQueryDocumentsDefault = 10
)

func NewQueryService(
	logger logging.Logger,
	repository repository.Repository,
	managedClusterNameLister managedclusters.NameLister,
	queryTimeout time.Duration,
	tenantNamespace string,
) *QueryService {
	return &QueryService{
		logger:                   logger.Named("QueryService"),
		timeout:                  queryTimeout,
		repository:               repository,
		collections:              collections.Collections(),
		tenantNamespace:          tenantNamespace,
		managedClusterNameLister: managedClusterNameLister,
		validator:                validatorv10.New(),
	}
}

func (s *QueryService) Query(ctx security.AuthContext, req client.QueryRequest) (client.QueryResponse, error) {
	s.logger.DebugC(ctx, "Query",
		zap.Int("maxDocs", req.MaxDocs),
		zap.String("collectionName", string(req.CollectionName)),
		zap.Any("clusterFilter", req.ClusterFilter),
		zap.Any("filters", req.Filters),
		zap.Any("groups", req.GroupBys),
		zap.Any("aggregations", req.Aggregations),
	)

	// Note: this statement requires req.CollectionName to match the lma.tigera.io resourceNames (it currently does)
	authorized, err := ctx.IsResourcePermitted(s.logger, "lma.tigera.io", "*", string(req.CollectionName))
	if err != nil {
		return client.QueryResponse{}, err
	} else if !authorized {
		return client.QueryResponse{}, httpreply.ReplyAccessDenied
	}

	queryCollection, err := s.validateRequest(req)
	if err != nil {
		return client.QueryResponse{}, err
	}

	managedClusterNames, err := s.managedClusterNameLister.List(ctx)
	if err != nil {
		return client.QueryResponse{}, err
	}

	if len(req.ClusterFilter) > 0 {
		// filter out non-existing ManagedCluster names.
		// Note that an empty req.ClusterFilter means we'll query all managed clusters logs
		managedClusterNames = slices.FilterBy(managedClusterNames, func(managedClusterName domain.ManagedClusterName) bool {
			return slices.Contains(req.ClusterFilter, client.ManagedClusterName(managedClusterName))
		})
	}

	maxDocuments := MaxQueryDocumentsDefault
	if req.MaxDocs > 0 {
		maxDocuments = min(req.MaxDocs, MaxQueryDocumentsLimit)
	}

	repositoryRequest := domain.QueryRequest{
		Aggregations:   make(aggregations.Aggregations),
		MaxDocuments:   maxDocuments,
		CollectionName: queryCollection.Name(),
	}

	repositoryRequest.Filters, err = slices.MapOrError(req.Filters, func(from client.QueryRequestFilter) (filters.Criterion, error) {
		return mapClientCriterion(from.Criterion, from.Negate, queryCollection)
	})
	if err != nil {
		return client.QueryResponse{}, err
	}

	repositoryRequest.Groups, err = slices.MapOrError(req.GroupBys, mapClientGroup)
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

	ctxTimeout, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	aggregatedQueryResult := result.QueryResult{
		Aggregations: make(aggregations.AggregationValues),
	}

	// Execute a query for each managed cluster to get results for phase 1
	// TODO: Have a single query executed for multiple managed clusters. (see cc-dashboard-query-api/pkg/internal/domain/aggregations/aggregation_value.go)
	for queryResult := range s.queryClusters(ctxTimeout, managedClusterNames, repositoryRequest) {
		if queryResult.Err != nil {
			return client.QueryResponse{}, queryResult.Err
		}
		s.aggregateSingleClusterResult(&aggregatedQueryResult, queryResult)
	}

	if err := aggregatedQueryResult.Calculate(); err != nil {
		return client.QueryResponse{}, err
	}

	queryResponse := client.QueryResponse{
		Totals: client.QueryResponseTotals{
			Value: aggregatedQueryResult.Hits,
		},
		Aggregations: mapResultAggregations(aggregatedQueryResult.Aggregations),
	}

	queryResponse.GroupValues, err = slices.MapOrError(aggregatedQueryResult.GroupValues, mapResultGroupValue)
	if err != nil {
		return client.QueryResponse{}, err
	}

	queryResponse.Documents = slices.Map(slices.SortBy(aggregatedQueryResult.Documents, func(doc result.QueryResultDocument) int64 {
		// TODO: use sort order from client request
		return doc.Timestamp.UnixMicro()
	}), func(doc result.QueryResultDocument) any {
		return doc.Content
	})

	if len(queryResponse.Documents) > maxDocuments {
		queryResponse.Documents = queryResponse.Documents[:maxDocuments]
	}

	return queryResponse, nil
}

// queryClusters This is a temporary phase 1 quickfix solution for multi cluster queries that will be replaced on
// phase 2 with a linseed/ES multi-cluster aggregation
func (s *QueryService) queryClusters(ctx context.Context, managedClusterNames []domain.ManagedClusterName, req domain.QueryRequest) iter.Seq[result.QueryResult] {
	return func(yield func(result.QueryResult) bool) {

		ch := make(chan result.QueryResult, len(managedClusterNames))
		for _, clusterName := range managedClusterNames {
			go func(req domain.QueryRequest, clusterName domain.ManagedClusterName) {
				req.ClusterID = clusterName
				ch <- s.repository.Query(ctx, req)
			}(req, clusterName)
		}

		for i := 0; i < len(managedClusterNames); i++ {
			if !yield(<-ch) {
				return
			}
		}
	}
}

func (s *QueryService) aggregateSingleClusterResult(aggregatedQueryResult *result.QueryResult, singleClusterResult result.QueryResult) {
	aggregatedQueryResult.Hits += singleClusterResult.Hits
	aggregatedQueryResult.Documents = append(aggregatedQueryResult.Documents, singleClusterResult.Documents...)
	aggregatedQueryResult.GroupValues = s.aggregateSingleClusterResultGroup(aggregatedQueryResult.GroupValues, singleClusterResult.GroupValues)

	for key, agg := range singleClusterResult.Aggregations {
		if _, found := aggregatedQueryResult.Aggregations[key]; !found {
			aggregatedQueryResult.Aggregations[key] = agg
		} else {
			aggregatedQueryResult.Aggregations[key].Append(agg)
		}
	}
}

func (s *QueryService) aggregateSingleClusterResultGroup(aggregatedGroupValues groups.GroupValues, resultGroupValues groups.GroupValues) groups.GroupValues {

	for _, groupValue := range resultGroupValues {
		aggregatedGroup, found := slices.Find(aggregatedGroupValues, func(g *groups.GroupValue) bool {
			return g.Key == groupValue.Key
		})
		if !found {
			aggregatedGroupValues = append(aggregatedGroupValues, groupValue)
		} else {
			aggregatedGroup.DocCount += groupValue.DocCount
			aggregatedGroup.SubGroupValues = s.aggregateSingleClusterResultGroup(aggregatedGroup.SubGroupValues, groupValue.SubGroupValues)
			for key, agg := range groupValue.Aggregations {
				if _, found := aggregatedGroup.Aggregations[key]; !found {
					aggregatedGroup.Aggregations[key] = agg
				} else {
					aggregatedGroup.Aggregations[key].Append(agg)
				}
			}
		}
	}

	return aggregatedGroupValues
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

	return queryCollection, nil
}

var reRemovePrefix = regexp.MustCompile(`^PT`)

func mapClientCriterion(from client.QueryRequestFilterCriterion, negate bool, queryCollection collections.Collection) (filters.Criterion, error) {

	getCollectionField := func(fieldName string) (collections.CollectionField, error) {
		field, found := queryCollection.Field(collections.FieldName(fieldName))
		if !found {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("unknown collection field name '%s'", fieldName))
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
		return filters.NewStartsWith(field, from.Value.(string), negate), nil //TODO: validate this
	case client.CriterionTypeExists:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
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
			return mapClientCriterion(subCriterion, negate, queryCollection)
		})
		if err != nil {
			return nil, err
		}
		return filters.NewOr(criteria, negate), nil
	case client.CriterionTypeRange:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		} else if !field.Type().Is(collections.FieldTypeNumber) {
			return nil, errInvalidFieldType
		}
		gte, err := strconv.ParseInt(from.GTE, 10, 64)
		if err != nil {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("failed to parse %s gte field: %v", from.Type, err))
		}
		lte, err := strconv.ParseInt(from.LTE, 10, 64)
		if err != nil {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("failed to parse %s lte field: %v", from.Type, err))
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
		gte, err := time.Parse(time.RFC3339, from.GTE)
		if err != nil {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid collection field '%s' value for criterion type '%s': %v", from.Field, from.Type, err))
		}
		lte, err := time.Parse(time.RFC3339, from.LTE)
		if err != nil {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid collection field '%s' value for criterion type '%s': %v", from.Field, from.Type, err))
		}
		return filters.NewDateRange(gte, lte, negate), nil
	case client.CriterionTypeRelativeTimeRange:
		criterion, err := filters.NewRelativeTimeRange(
			strings.ToLower(reRemovePrefix.ReplaceAllString(from.GTE, "")),
			strings.ToLower(reRemovePrefix.ReplaceAllString(from.LTE, "")),
			negate,
		)
		if err != nil {
			return nil, httpreply.ToBadRequest(err.Error())
		}
		return criterion, err
	}

	return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid filter criterion type: %s", from.Type))
}

func mapClientGroup(from client.QueryRequestGroup) (groups.Group, error) {
	switch groups.GroupType(from.Type) {
	case groups.GroupTypeDiscrete:
		return groups.NewGroupDiscrete(from.FieldName, from.MaxValues), nil
	case groups.GroupTypeTime:
		return groups.NewGroupTime(from.FieldName, from.Interval), nil
	}
	return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid group type: %s", from.Type))
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
	}

	return nil, fmt.Errorf("unknown aggregation type '%s'", from.Function.Type)
}

func mapResultGroupValue(from *groups.GroupValue) (client.QueryResponseGroupValue, error) {
	nestedValues, err := slices.MapOrError(from.SubGroupValues, func(groupValue *groups.GroupValue) (any, error) {
		return mapResultGroupValue(groupValue)
	})
	if err != nil {
		return client.QueryResponseGroupValue{}, err
	}

	return client.QueryResponseGroupValue{
		Key:          from.Key,
		Aggregations: mapResultAggregations(from.Aggregations),
		NestedValues: nestedValues,
	}, nil
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
