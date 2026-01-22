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
	"github.com/tigera/tds-apiserver/lib/comparators"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/dashboards/pkg/client"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/aggregations"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/filters"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/groups"
	domain "github.com/projectcalico/calico/dashboards/pkg/internal/domain/query"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	"github.com/projectcalico/calico/dashboards/pkg/internal/repository"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	"github.com/projectcalico/calico/dashboards/pkg/internal/svc/managedclusters"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
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
	MaxExportDocumentsLimit  = 10000
	MaxQueryDocumentsDefault = 10
)

func NewQueryService(
	logger logging.Logger,
	repository repository.Repository,
	enabledCollections []collections.Collection,
	managedClusterNameLister managedclusters.NameLister,
	cfg Config,
) *QueryService {
	return &QueryService{
		cfg:                      cfg,
		logger:                   logger.WithName("QueryService"),
		repository:               repository,
		collections:              enabledCollections,
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

	maxDocuments := MaxQueryDocumentsDefault
	limit := MaxQueryDocumentsLimit

	if req.IsExport {
		limit = MaxExportDocumentsLimit
	}

	if req.MaxDocs != nil && *req.MaxDocs >= 0 {
		maxDocuments = min(*req.MaxDocs, limit)
	}

	pageNum := 0
	if req.PageNum != nil && *req.PageNum >= 0 {
		pageNum = *req.PageNum
	}

	queryCollection, err := s.validateRequest(req)
	if err != nil {
		return client.QueryResponse{}, err
	}

	repositoryRequest := domain.QueryRequest{
		MaxDocuments:   maxDocuments,
		PageNum:        pageNum,
		CollectionName: queryCollection.Name(),
		SortFieldName:  queryCollection.DefaultTimeFieldName(),
		ClusterIDs: slices.Map(req.ClusterFilter, func(c client.ManagedClusterName) domain.ManagedClusterName {
			return domain.ManagedClusterName(c)
		}),
	}

	managedClusterNames, err := s.managedClusterNameLister.List(ctx)
	if err != nil {
		return client.QueryResponse{}, err
	}

	// deny access if any request clusterIDs do not match ManagedCluster names
	if slices.AnyMatch(repositoryRequest.ClusterIDs, func(clusterID domain.ManagedClusterName) bool {
		return !slices.Contains(managedClusterNames, clusterID)
	}) {
		return client.QueryResponse{}, httpreply.ReplyAccessDenied
	}

	authorizedManagedClusterNames := repositoryRequest.ClusterIDs
	if len(repositoryRequest.ClusterIDs) == 0 {
		authorized, err := ctx.IsResourcePermitted(security.APIGroupLMATigera, queryCollection.LmaResourceName(), "*")
		if err != nil {
			return client.QueryResponse{}, err
		} else if authorized {
			// authorized to access all managed clusters
			authorizedManagedClusterNames = managedClusterNames
		} else {
			// "all managed clusters" query should select the authorized subset of managed clusters for custom roles
			for _, clusterID := range managedClusterNames {
				authorized, err = ctx.IsResourcePermitted(security.APIGroupLMATigera, queryCollection.LmaResourceName(), string(clusterID))
				if err != nil {
					return client.QueryResponse{}, err
				}

				if authorized {
					repositoryRequest.ClusterIDs = append(repositoryRequest.ClusterIDs, clusterID)
				}
			}

			if len(repositoryRequest.ClusterIDs) == 0 {
				// user is unauthorized for all managed clusters
				return client.QueryResponse{}, httpreply.ReplyAccessDenied
			}

			authorizedManagedClusterNames = repositoryRequest.ClusterIDs
		}
	} else {

		for _, clusterID := range repositoryRequest.ClusterIDs {
			authorized, err := ctx.IsResourcePermitted(security.APIGroupLMATigera, queryCollection.LmaResourceName(), string(clusterID))
			if err != nil {
				return client.QueryResponse{}, err
			} else if !authorized {
				// req.ClusterFilter contains a managed cluster the user is not authorized to access
				return client.QueryResponse{}, httpreply.Reply{
					Key:     httpreply.AccessDenied,
					Status:  httpreply.ReplyAccessDenied.Status,
					Message: fmt.Sprintf("access denied to cluster %s", clusterID),
				}
			}
		}
	}

	// Set query permissions for namespaced RBAC
	permissionsResult, err := ctx.GetPermissions(slices.ToStrings(authorizedManagedClusterNames))
	if err != nil {
		return client.QueryResponse{}, err
	}

	repositoryRequest.Permissions = permissionsResult.AuthorizedResourceVerbs
	s.logger.DebugC(ctx, "Query permissions",
		logging.Any("permissions", repositoryRequest.Permissions),
		logging.Any("permissionsErrors", permissionsResult.Errors))

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

	countAggregations := make(map[string]client.QueryRequestAggregation)
	for aggKey, clientAggregation := range req.Aggregations {
		aggregation, err := mapClientAggregation(aggregations.AggregationKey(aggKey), clientAggregation, queryCollection)
		if err != nil {
			return client.QueryResponse{}, err
		}

		if clientAggregation.Function.Type == client.AggregationFunctionTypeCount {
			countAggregations[string(aggKey)] = clientAggregation
		}

		repositoryRequest.Aggregations = append(repositoryRequest.Aggregations, aggregation)
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
		GroupValues:   mapResultGroupValues(0, repositoryRequest.Groups, queryResult.GroupValues),
		Aggregations:  mapResultAggregations(queryResult.Aggregations),
		ClusterErrors: permissionsResult.Errors,
	}

	if len(req.GroupBys) == 0 {
		// Handle the special case of a count aggregation with no groups set, which results in no elastic aggregations
		// being queried (since the count aggregation relies on document/hit count)
		for aggKey := range countAggregations {
			queryResponse.Aggregations[aggKey] = client.QueryResponseValueAsString{
				AsString: strconv.FormatInt(queryResult.Hits, 10),
			}
		}
	}

	queryResponse.Documents, err = slices.MapOrError(
		slices.SortByComparing( // sort desc by start_time
			queryResult.Documents,
			comparators.Func[result.QueryResultDocument](func(doc1, doc2 result.QueryResultDocument) int {
				if doc1.Timestamp.UnixMicro() == doc2.Timestamp.UnixMicro() {
					return 0
				} else if doc1.Timestamp.UnixMicro() > doc2.Timestamp.UnixMicro() {
					return -1
				}
				return 1
			})), mapResultDocument)
	if err != nil {
		return client.QueryResponse{}, err
	}

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

	// Enforce collection groupBys combination tree using backtracking
	// This allows multiple groupBy trees with the same root field to coexist
	if !validateGroupByPath(queryCollection.GroupBys(), req.GroupBys) {
		fieldNames := slices.Map(req.GroupBys, func(g client.QueryRequestGroup) string { return g.FieldName })
		return collections.Collection{}, httpreply.ToBadRequest(fmt.Sprintf("invalid group combination: %s", strings.Join(fieldNames, ",")))
	}

	return queryCollection, nil
}

// validateGroupByPath recursively validates that the requested groupBy fields
// form a valid path through the collection's groupBy tree. It uses backtracking
// to handle cases where multiple groupBy trees share the same root field.
func validateGroupByPath(collectionGroupBys []collections.GroupBy, requestedGroupBys []client.QueryRequestGroup) bool {
	// Base case: all requested groupBys have been matched
	if len(requestedGroupBys) == 0 {
		return true
	}

	currentField := collections.FieldName(requestedGroupBys[0].FieldName)
	remainingGroupBys := requestedGroupBys[1:]

	// Try all matching groupBys at the current level (backtracking)
	for _, groupBy := range collectionGroupBys {
		if groupBy.Field() == currentField {
			// Found a match, recursively validate the remaining fields
			if validateGroupByPath(groupBy.Nested(), remainingGroupBys) {
				return true
			}
			// If this path didn't work, continue trying other matches
		}
	}

	// No valid path found
	return false
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
		return filters.NewEquals(field, from.Value.Value(), negate), nil
	case client.CriterionTypeStartsWith:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		value, ok := from.Value.Value().(string)
		if !ok {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid value '%v' for criterion type '%s'", from.Value.Value(), from.Type))
		}
		return filters.NewStartsWith(field, value, negate), nil
	case client.CriterionTypeExists:
		field, err := getCollectionField(from.Field)
		if err != nil {
			return nil, err
		}
		if !field.SupportsExists() {
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
		criteria, err := slices.MapOrError(from.Criteria, func(subCriterion client.QueryRequestFilterCriterion) (filters.Criterion, error) {
			// negate is not applied to sub-criteria of an "or" criterion
			// e.g. { "negate": "true", "criterion": { "type": "or", "criteria": [ { "type": "equals", ...}, ... ] } }
			// means NOT (criterion1 OR criterion2 ...)
			return s.mapClientCriterion(ctx, subCriterion, false, queryCollection)
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
	collectionField, found := collection.Field(collections.FieldName(from.FieldName))
	if !found {
		return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid field name: %s", from.FieldName))
	}

	if collectionField.Type() == collections.FieldTypeDate {
		return groups.NewGroupTime(from.FieldName, from.Interval, from.MaxValues), nil
	}

	return groups.NewGroupDiscrete(from.FieldName, from.MaxValues), nil
}

func mapClientAggregation(
	aggKey aggregations.AggregationKey,
	from client.QueryRequestAggregation,
	collection collections.Collection,
) (aggregations.Aggregation, error) {

	if from.Function.Type != client.AggregationFunctionTypeCount {
		// skip count aggregation function, which does not require a FieldName
		collectionField, found := collection.Field(collections.FieldName(from.FieldName))
		if !found {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid field name: %s", from.FieldName))
		}

		if !slices.Contains(collectionField.AggregationFunctionTypes(), collections.AggregationFunctionType(from.Function.Type)) {
			return nil, httpreply.ToBadRequest(fmt.Sprintf("invalid aggregation function %s for field %s", from.Function.Type, from.FieldName))
		}
	}

	switch from.Function.Type {
	case client.AggregationFunctionTypeCount:
		return aggregations.NewAggregationCount(aggKey, from.Order, false), nil
	case client.AggregationFunctionTypeSum:
		return aggregations.NewAggregationSum(aggKey, from.Order, from.FieldName, false), nil
	case client.AggregationFunctionTypeAvg:
		return aggregations.NewAggregationAvg(aggKey, from.Order, from.FieldName, false), nil
	case client.AggregationFunctionTypeMin:
		return aggregations.NewAggregationMin(aggKey, from.Order, from.FieldName, true), nil
	case client.AggregationFunctionTypeMax:
		return aggregations.NewAggregationMax(aggKey, from.Order, from.FieldName, false), nil
	case client.AggregationFunctionTypePercentile50:
		return aggregations.NewAggregationPercentile(aggKey, from.Order, from.FieldName, 50, false), nil
	case client.AggregationFunctionTypePercentile90:
		return aggregations.NewAggregationPercentile(aggKey, from.Order, from.FieldName, 90, false), nil
	case client.AggregationFunctionTypePercentile95:
		return aggregations.NewAggregationPercentile(aggKey, from.Order, from.FieldName, 95, false), nil
	case client.AggregationFunctionTypePercentile100:
		return aggregations.NewAggregationPercentile(aggKey, from.Order, from.FieldName, 100, false), nil
	}

	return nil, fmt.Errorf("unknown aggregation type '%s'", from.Function.Type)
}

func mapResultGroupValues(groupIndex int, repositoryRequestGroups groups.Groups, groupValues groups.GroupValues) []client.QueryResponseGroupValue {
	values := slices.Map(groupValues, func(from *groups.GroupValue) client.QueryResponseGroupValue {
		var nestedValues []client.QueryResponseGroupValue
		if from.SubGroupValues != nil {
			nestedValues = mapResultGroupValues(groupIndex+1, repositoryRequestGroups, from.SubGroupValues)
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

func mapResultDocument(doc result.QueryResultDocument) (client.QueryResponseDocument, error) {
	jsonRepr, err := json.Marshal(doc.Content)
	if err != nil {
		return client.QueryResponseDocument{}, err
	}

	queryResponseDoc := make(client.QueryResponseDocument)
	if err = json.Unmarshal(jsonRepr, &queryResponseDoc); err != nil {
		return client.QueryResponseDocument{}, err
	}

	return queryResponseDoc, nil
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
