package linseed

import (
	"context"
	"encoding/json"

	"github.com/olivere/elastic/v7"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query/result"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
)

type collectionClientDNS struct {
	logger logging.Logger
	client lsclient.Client
}

// TODO: This document should contain relevant fields instead of the entirety of the DNSLog
type dnsLogDocument struct {
	lsv1.DNSLog
	ClientIP string `json:"client_ip"`
}

var _ linseedCollectionClient = &collectionClientDNS{}

func newLinseedCollectionClientDNS(logger logging.Logger, client lsclient.Client) linseedCollectionClient {
	return &collectionClientDNS{
		logger: logger,
		client: client,
	}
}

func (c *collectionClientDNS) Params(params *queryParams, aggregations map[string]json.RawMessage) (lsv1.Params, error) {

	dnsLogParams := &lsv1.DNSLogParams{
		QueryParams:        params.linseedQueryParams,
		QuerySortParams:    params.linseedQuerySortParams,
		LogSelectionParams: params.linseedLogSelectionParams,
	}

	// Set linseed dns fields that have a particular domain match
	for domainMatchType, domains := range params.domainMatches {
		if len(domains) > 0 {
			dnsLogParams.DomainMatches = append(dnsLogParams.DomainMatches, lsv1.DomainMatch{Type: domainMatchType, Domains: domains})
		}
	}

	if len(aggregations) > 0 {
		return &lsv1.DNSAggregationParams{
			DNSLogParams: *dnsLogParams,
			Aggregations: aggregations,
		}, nil
	}

	return dnsLogParams, nil
}

func (c *collectionClientDNS) List(ctx context.Context, params lsv1.Params) (result.QueryResult, error) {
	c.logger.DebugC(ctx, "DNSLogs.List",
		logging.Any("params", params))

	listResult, err := c.client.DNSLogs(lsv1.QueryMultipleClusters).List(ctx, params)
	if err != nil {
		return result.QueryResult{}, err
	}

	return result.QueryResult{
		Hits: listResult.TotalHits,
		Documents: slices.Map(listResult.Items, func(item lsv1.DNSLog) result.QueryResultDocument {
			return result.QueryResultDocument{
				Content: &dnsLogDocument{
					DNSLog:   item,
					ClientIP: result.QueryResultDocumentContentIP(item.ClientIP),
				},
				Timestamp: item.StartTime.UTC()}
		}),
	}, nil
}

func (c *collectionClientDNS) Aggregations(ctx context.Context, params lsv1.Params) (elastic.Aggregations, error) {
	c.logger.DebugC(ctx, "DNSLogs.Aggregations",
		logging.Any("params", params))

	return c.client.DNSLogs(lsv1.QueryMultipleClusters).Aggregations(ctx, params)
}
