package linseed

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/aggregations"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	"github.com/projectcalico/calico/dashboards/pkg/internal/repository"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

type LinseedRepository struct {
	url     string
	clients map[collections.CollectionName]linseedCollectionClient

	logger logging.Logger
}

var (
	_ repository.Repository = &LinseedRepository{}

	reForbiddenErr               = `[status 500] server error: Forbidden`
	reUnauthorizedErr            = `[status 401] server error: Unauthorized`
	reInvalidSelectorValueErr    = regexp.MustCompile(`Invalid selector .*in request: (invalid value for.*)`)
	reUnexpectedSelectorTokenErr = regexp.MustCompile(`Invalid selector (.*) in request:.* unexpected token.*`)
)

func NewLinseedRepository(logger logging.Logger, tenantID, url, caCertPath, clientCert, clientKey, tokenPath string) (*LinseedRepository, error) {
	linseedClient, err := lsclient.NewClient(tenantID, rest.Config{
		URL:            url,
		CACertPath:     caCertPath,
		ClientKeyPath:  clientKey,
		ClientCertPath: clientCert,
	}, rest.WithTokenPath(tokenPath))
	if err != nil {
		return nil, err
	}

	return NewLinseedRepositoryWithClient(logger, url, linseedClient), nil
}

func NewLinseedRepositoryWithClient(logger logging.Logger, url string, linseedClient lsclient.Client) *LinseedRepository {
	return &LinseedRepository{
		url:    url,
		logger: logger,
		clients: map[collections.CollectionName]linseedCollectionClient{
			collections.CollectionNameL7:    newLinseedCollectionClientL7(logger, linseedClient),
			collections.CollectionNameDNS:   newLinseedCollectionClientDNS(logger, linseedClient),
			collections.CollectionNameFlows: newLinseedCollectionClientFlows(logger, linseedClient),
			collections.CollectionNameWAF:   newLinseedCollectionClientWAF(logger, linseedClient),
		},
	}
}

func (r *LinseedRepository) Query(ctx context.Context, req query.QueryRequest) (result.QueryResult, error) {
	collectionClient, found := r.clients[req.CollectionName]
	if !found {
		return result.QueryResult{}, httpreply.ToBadRequest(fmt.Sprintf("unknown collection name '%s", req.CollectionName))
	}

	linseedQueryParams, err := newQueryParams(req.MaxDocuments, req.PageNum, string(req.SortFieldName), slices.ToStrings(req.ClusterIDs), req.Permissions)
	if err != nil {
		return result.QueryResult{}, httpreply.ToBadRequest(err.Error())
	}

	err = linseedQueryParams.setCriteria(req.Filters, time.Now().UTC())
	if err != nil {
		return result.QueryResult{}, httpreply.ToBadRequest(err.Error())
	}

	// Sort aggregations by order
	sortedAggregations := slices.SortBy(req.Aggregations, func(a aggregations.Aggregation) int {
		return a.Order()
	})

	// Build elastic aggregations from req.Aggregations
	// If no groups are present in QueryRequest.Groups, these are defined as a root-level aggregations
	// If at least 1 group is present in the QueryRequest.Groups, these are defined as aggregations for the last group
	var subAggregations []aggregation
	for _, agg := range sortedAggregations {
		elasticAggregation, err := queryAggregationToElastic(agg)
		if err != nil {
			return result.QueryResult{}, err
		}

		subAggregations = append(subAggregations, aggregation{
			agg:                agg,
			elasticAggregation: elasticAggregation,
		})
	}

	var elasticGroups groupAggregations
	repositoryAggregations := make(map[string]json.RawMessage)
	if len(req.Groups) > 0 {
		elasticGroups, err = queryGroupsToElastic(req.Groups, subAggregations, linseedQueryParams.requestedPeriod)
		if err != nil {
			return result.QueryResult{}, err
		}

		/* Each elastic group aggregation must be identified by an arbitrary key that does not conflict with existing
		 * aggregations. For groups, this key is the group numeric index in the req.Groups slice, prefixed with "g".
		 *
		 * Only the elastic aggregation for the group at index 0 ("g0") must be set in repositoryAggregations because
		 * each subsequent group is set as an elastic sub-aggregation of the previous-index group, so groups beyond
		 * index 0 are already included in aggJson.
		 */
		repositoryAggregations[elasticGroups[0].aggregationKey] = elasticGroups[0].aggJson
	} else {
		// Set root level aggregations
		for _, agg := range subAggregations {
			if agg.elasticAggregation == nil {
				continue
			}
			aggJson, err := elasticAggregationToJSON(agg.elasticAggregation)
			if err != nil {
				return result.QueryResult{}, err
			}

			repositoryAggregations[agg.elasticKey()] = aggJson
		}
	}

	params, err := collectionClient.Params(
		linseedQueryParams,
		repositoryAggregations)
	if err != nil {
		return result.QueryResult{}, err
	}

	var queryResult result.QueryResult
	if len(repositoryAggregations) > 0 {
		resultAggregations, err := collectionClient.Aggregations(ctx, params)
		if err != nil {
			return result.QueryResult{}, handleQueryResultError(err)
		}

		queryResult.Aggregations = make(aggregations.AggregationValues)
		for _, agg := range subAggregations {
			err := elasticAggregationToQueryResult(agg, 0, queryResult.Aggregations, resultAggregations)
			if err != nil {
				return result.QueryResult{}, err
			}
		}

		if len(elasticGroups) > 0 {
			err := elasticGroups.fromElastic(0, resultAggregations, subAggregations, &queryResult)
			if err != nil {
				return result.QueryResult{}, err
			}

			for _, groupValue := range queryResult.GroupValues {
				queryResult.Hits += groupValue.DocCount
			}
		}

	} else {
		queryResult, err = collectionClient.List(ctx, params)
		if err != nil {
			return result.QueryResult{}, handleQueryResultError(err)
		}
	}

	return queryResult, nil
}

func handleQueryResultError(err error) error {
	if err.Error() == reUnauthorizedErr || err.Error() == reForbiddenErr {
		return httpreply.ReplyAccessDenied
	} else if m := reInvalidSelectorValueErr.FindStringSubmatch(err.Error()); len(m) == 2 {
		// Handle invalid selector value errors as a Bad Request
		return httpreply.ToBadRequest(m[1])
	} else if m := reUnexpectedSelectorTokenErr.FindStringSubmatch(err.Error()); len(m) == 2 {
		// Handle invalid selector value errors as a Bad Request
		return httpreply.ToBadRequest(fmt.Sprintf("invalid criterion filter: %s", m[1]))
	}
	return err
}

func queryAggregationToElastic(queryAggregation aggregations.Aggregation) (elastic.Aggregation, error) {
	var elasticAggregation elastic.Aggregation

	switch agg := queryAggregation.(type) {
	case aggregations.AggregationSum:
		elasticAggregation = elastic.NewSumAggregation().Field(agg.FieldName())
	case aggregations.AggregationAvg:
		elasticAggregation = elastic.NewAvgAggregation().Field(agg.FieldName())
	case aggregations.AggregationMin:
		elasticAggregation = elastic.NewMinAggregation().Field(agg.FieldName())
	case aggregations.AggregationMax:
		elasticAggregation = elastic.NewMaxAggregation().Field(agg.FieldName())
	case aggregations.AggregationPercentile:
		elasticAggregation = elastic.NewPercentilesAggregation().Field(agg.FieldName()).Percentiles(agg.Percentile())
	case aggregations.AggregationCount:
		// count has no elastic aggregation because it returns the total document count
		return nil, nil

	default:
		return nil, fmt.Errorf("unknown aggregation type %T", agg)
	}

	return elasticAggregation, nil
}

func elasticAggregationToQueryResult(
	agg aggregation,
	docCount int64,
	resultAggregations aggregations.AggregationValues,
	elasticAggregations elastic.Aggregations,
) error {
	var found bool
	var value *elastic.AggregationValueMetric

	aggKey := string(agg.agg.Key())

	switch a := agg.agg.(type) {
	case aggregations.AggregationCount:
		resultAggregations[aggKey] = aggregations.NewAggregationValue(&docCount)
		return nil
	case aggregations.AggregationSum:
		value, found = elasticAggregations.Sum(agg.elasticKey())
	case aggregations.AggregationAvg:
		value, found = elasticAggregations.Avg(agg.elasticKey())
	case aggregations.AggregationMin:
		value, found = elasticAggregations.Min(agg.elasticKey())
	case aggregations.AggregationMax:
		value, found = elasticAggregations.Max(agg.elasticKey())
	case aggregations.AggregationPercentile:
		var percentiles *elastic.AggregationPercentilesMetric
		percentiles, found = elasticAggregations.Percentiles(agg.elasticKey())
		if found {
			value = &elastic.AggregationValueMetric{}
			key := strconv.FormatFloat(a.Percentile(), 'f', -1, 64)
			if !strings.Contains(key, ".") {
				key += ".0" // elastic returns "N.0" for a percentile "N" key with 0 decimals
			}
			if floatValue, ok := percentiles.Values[key]; ok {
				value.Value = &floatValue
			}
		}
	default:
		return fmt.Errorf("unknown aggregation type %T", agg)
	}

	if found {
		resultAggregations[aggKey] = aggregations.NewAggregationValue(value.Value)
	}
	return nil
}

func elasticAggregationToJSON(elasticAggregation elastic.Aggregation) (json.RawMessage, error) {
	aggSource, err := elasticAggregation.Source()
	if err != nil {
		return nil, err
	}

	aggJson, err := json.Marshal(aggSource)
	if err != nil {
		return nil, err
	}

	return aggJson, nil
}
