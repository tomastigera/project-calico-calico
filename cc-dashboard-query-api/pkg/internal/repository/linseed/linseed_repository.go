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

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/aggregations"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/repository"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/httpreply"
)

type LinseedRepository struct {
	url     string
	client  lsclient.Client
	clients map[collections.CollectionName]linseedCollectionClient

	logger logging.Logger
}

var (
	_ repository.Repository = &LinseedRepository{}

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
		},
	}
}

func (r *LinseedRepository) Query(ctx context.Context, req query.QueryRequest) (result.QueryResult, error) {
	collectionClient, found := r.clients[req.CollectionName]
	if !found {
		return result.QueryResult{}, httpreply.ToBadRequest(fmt.Sprintf("unknown collection name '%s", req.CollectionName))
	}

	linseedQueryParams := newQueryParams(req.MaxDocuments)

	err := linseedQueryParams.setCriteria(req.Filters, time.Now().UTC())
	if err != nil {
		return result.QueryResult{}, httpreply.ToBadRequest(err.Error())
	}

	// Build elastic aggregations from req.Aggregations
	// If no groups are present in QueryRequest.Groups, these are defined as a root-level aggregations
	// If at least 1 group is present in the QueryRequest.Groups, these are defined as aggregations for the last group
	elasticAggregations := make(map[string]elastic.Aggregation)
	for aggKey, agg := range req.Aggregations {
		elasticAggregation, err := queryAggregationToElastic(agg)
		if err != nil {
			return result.QueryResult{}, err
		}

		if elasticAggregation != nil {
			elasticAggregations["a_"+string(aggKey)] = elasticAggregation
		}
	}

	repositoryAggregations := make(map[string]json.RawMessage)
	if len(req.Groups) > 0 {
		elasticAggregation, err := queryGroupsToElastic(0, req.Groups, elasticAggregations, linseedQueryParams.requestedPeriod)
		if err != nil {
			return result.QueryResult{}, err
		}

		aggJson, err := elasticAggregationToJSON(elasticAggregation)
		if err != nil {
			return result.QueryResult{}, err
		}

		/* Each elastic group aggregation must be identified by an arbitrary key that does not conflict with existing
		 * aggregations. For groups, this key is the group numeric index in the req.Groups slice, prefixed with "g".
		 *
		 * Only the elastic aggregation for the group at index 0 ("g0") must be set in repositoryAggregations because
		 * each subsequent group is set as an elastic subaggregation of the previous-index group, so groups beyond
		 * index 0 are already included in aggJson.
		 */
		repositoryAggregations["g0"] = aggJson
	} else {
		// Set root level aggregations
		for aggKey, elasticAggregation := range elasticAggregations {
			aggJson, err := elasticAggregationToJSON(elasticAggregation)
			if err != nil {
				return result.QueryResult{}, err
			}

			repositoryAggregations[aggKey] = aggJson
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
		resultAggregations, err := collectionClient.Aggregations(ctx, req.ClusterID, params)
		if err != nil {
			return result.QueryResult{}, handleQueryResultError(err)
		}

		queryResult.Aggregations = make(aggregations.AggregationValues)
		for aggKey, agg := range req.Aggregations {
			err := elasticAggregationToQueryResult(string(aggKey), agg, 0, queryResult.Aggregations, resultAggregations)
			if err != nil {
				return result.QueryResult{}, err
			}
		}

		if len(req.Groups) > 0 {
			if err := queryGroupsFromElastic(0, req.Groups, req.Aggregations, resultAggregations, &queryResult); err != nil {
				return result.QueryResult{}, err
			}

			for _, groupValue := range queryResult.GroupValues {
				queryResult.Hits += groupValue.DocCount
			}
		}

	} else {
		queryResult, err = collectionClient.List(ctx, req.ClusterID, params)
		if err != nil {
			return result.QueryResult{}, handleQueryResultError(err)
		}
	}

	return queryResult, nil
}

func handleQueryResultError(err error) error {

	if m := reInvalidSelectorValueErr.FindStringSubmatch(err.Error()); m != nil && len(m) == 2 {
		// Handle invalid selector value errors as a Bad Request
		return httpreply.ToBadRequest(m[1])
	} else if m := reUnexpectedSelectorTokenErr.FindStringSubmatch(err.Error()); m != nil && len(m) == 2 {
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

func elasticAggregationToQueryResult(aggKey string, aggregation aggregations.Aggregation, docCount int64, resultAggregations aggregations.AggregationValues, elasticAggregations elastic.Aggregations) error {
	var found bool
	var value *elastic.AggregationValueMetric

	elasticKey := "a_" + string(aggKey)

	switch agg := aggregation.(type) {
	case aggregations.AggregationCount:
		resultAggregations[aggKey] = aggregations.NewAggregationValue(&docCount)
		return nil
	case aggregations.AggregationSum:
		value, found = elasticAggregations.Sum(elasticKey)
	case aggregations.AggregationAvg:
		value, found = elasticAggregations.Avg(elasticKey)
	case aggregations.AggregationMin:
		value, found = elasticAggregations.Min(elasticKey)
	case aggregations.AggregationMax:
		value, found = elasticAggregations.Max(elasticKey)
	case aggregations.AggregationPercentile:
		var percentiles *elastic.AggregationPercentilesMetric
		percentiles, found = elasticAggregations.Percentiles(elasticKey)
		if found {
			value = &elastic.AggregationValueMetric{}
			key := strconv.FormatFloat(agg.Percentile(), 'f', -1, 64)
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
