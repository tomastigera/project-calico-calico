package linseed

import (
	"context"
	"encoding/json"

	"github.com/olivere/elastic/v7"
	"go.uber.org/zap"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/query/result"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

type collectionClientDNS struct {
	logger logging.Logger
	client lsclient.Client
}

// TODO: This document should contain relevant fields instead of the entirety of the DNSLog
type dnsLogDocument struct {
	lsv1.DNSLog
	Cluster  query.ManagedClusterName `json:"cluster"`
	ClientIP string                   `json:"client_ip"`
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
		QueryParams: params.QueryParams,
		LogSelectionParams: lsv1.LogSelectionParams{
			Selector: params.selector,
		},
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

func (c *collectionClientDNS) List(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (result.QueryResult, error) {
	c.logger.DebugC(ctx, "DNSLogs.List",
		zap.String("clusterName", string(clusterName)),
		zap.Any("params", params))

	listResult, err := c.client.DNSLogs(string(clusterName)).List(ctx, params)
	if err != nil {
		return result.QueryResult{}, err
	}

	return result.QueryResult{
		Hits: listResult.TotalHits,
		Documents: slices.Map(listResult.Items, func(i lsv1.DNSLog) result.QueryResultDocument {
			return result.QueryResultDocument{
				Content: dnsLogDocument{
					DNSLog:   i,
					Cluster:  clusterName,
					ClientIP: result.QueryResultDocumentContentIP(i.ClientIP),
				},
				Timestamp: i.StartTime.UTC()}
		}),
	}, nil
}

func (c *collectionClientDNS) Aggregations(ctx context.Context, clusterName query.ManagedClusterName, params lsv1.Params) (elastic.Aggregations, error) {
	c.logger.DebugC(ctx, "DNSLogs.Aggregations",
		zap.String("clusterName", string(clusterName)),
		zap.Any("params", params))

	return c.client.DNSLogs(string(clusterName)).Aggregations(ctx, params)
}
