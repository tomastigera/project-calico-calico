// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package processes

import (
	"context"
	"fmt"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/logtools"
	lmaindex "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic/index"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

const (
	defaultAggregationSize = 1000

	clusterKey        = "agg-cluster"
	sourceNameAggrKey = "agg-source_name_aggr"
	processNameKey    = "agg-process_name"
	processIDKey      = "agg-process_id"
)

// processBackend implements the Backend interface for flows stored
// in elasticsearch in the legacy storage model.
type processBackend struct {
	// Elasticsearch client.
	lmaclient   lmaelastic.Client
	index       bapi.Index
	queryHelper lmaindex.Helper
}

func NewBackend(c lmaelastic.Client) bapi.ProcessBackend {
	return &processBackend{
		lmaclient:   c,
		index:       index.FlowLogMultiIndex,
		queryHelper: lmaindex.MultiIndexFlowLogs(),
	}
}

func NewSingleIndexBackend(c lmaelastic.Client, options ...index.Option) bapi.ProcessBackend {
	return &processBackend{
		lmaclient:   c,
		index:       index.FlowLogIndex(options...),
		queryHelper: lmaindex.SingleIndexFlowLogs(),
	}
}

// Used for testing.
type BucketConverter interface {
	ConvertElasticResult(log *logrus.Entry, results *elastic.SearchResult) ([]v1.ProcessInfo, error)
}

// List returns all flows which match the given options.
func (b *processBackend) List(ctx context.Context, i bapi.ClusterInfo, opts *v1.ProcessParams) (*v1.List[v1.ProcessInfo], error) {
	log := bapi.ContextLogger(i)

	if err := i.Valid(); err != nil {
		return nil, err
	}

	// Build the query.
	query, err := b.buildQuery(i, opts)
	if err != nil {
		return nil, err
	}

	// Get aggregation parameters.
	aggregation, err := getAggregation(b.lmaclient.Backend())
	if err != nil {
		return nil, err
	}

	// Get the startFrom param, if any.
	startFrom, err := logtools.StartFrom(opts)
	if err != nil {
		return nil, err
	}

	// Perform the search.
	search := b.lmaclient.Backend().Search(b.index.Index(i)).
		Query(query).
		From(startFrom).
		Aggregation(clusterKey, aggregation).
		Size(0)

	results, err := search.Do(ctx)
	if err != nil {
		return nil, err
	}

	processes, err := b.ConvertElasticResult(log, results)
	if err != nil {
		return nil, err
	}

	// Determine the AfterKey to return.
	var ak map[string]any
	if numHits := len(results.Hits.Hits); numHits < opts.GetMaxPageSize() {
		// We fully satisfied the request, no afterkey.
		ak = nil
	} else {
		// There are more hits, return an afterKey the client can use for pagination.
		// We add the number of hits to the start from provided on the request, if any.
		ak = map[string]any{
			"startFrom": startFrom + len(results.Hits.Hits),
		}
	}

	return &v1.List[v1.ProcessInfo]{
		AfterKey: ak,
		Items:    processes,
	}, nil
}

func (b *processBackend) ConvertElasticResult(log *logrus.Entry, results *elastic.SearchResult) ([]v1.ProcessInfo, error) {
	// Handle the results.
	aggItems, found := results.Aggregations.Terms(clusterKey)
	if !found {
		err := fmt.Errorf("failed to get key %s in aggregation from search results", clusterKey)
		return nil, err
	}

	processes := []v1.ProcessInfo{}
	for _, bucket := range aggItems.Buckets {
		process := b.convertBucket(log, bucket)
		if process != nil {
			processes = append(processes, process...)
		}
	}
	return processes, nil
}

// convertBucket turns a composite aggregation bucket into one or more ProcessInfos.
func (b *processBackend) convertBucket(log *logrus.Entry, bucket *elastic.AggregationBucketKeyItem) []v1.ProcessInfo {

	if srcNameAggrItems, found := bucket.Terms(sourceNameAggrKey); !found {
		log.Warnf("failed to get bucket key %s in sub-aggregation", sourceNameAggrKey)
		return nil
	} else {
		cluster, ok := bucket.Key.(string)
		if !ok {
			log.Warnf("failed to convert bucket key %v to string", bucket.Key)
			return nil
		}
		// Each endpoint may have one or more processes present, each with one or more process IDs.
		procs := []v1.ProcessInfo{}
		for _, srcNameAggrBucket := range srcNameAggrItems.Buckets {
			endpoint, ok := srcNameAggrBucket.Key.(string)
			if !ok {
				log.Warnf("failed to convert bucket key %v to string", srcNameAggrBucket.Key)
				return nil
			}

			if processNameItems, found := srcNameAggrBucket.Terms(processNameKey); !found {
				log.Warnf("failed to get bucket key %s in sub-aggregation", processNameKey)
				return nil
			} else {
				for _, bb := range processNameItems.Buckets {
					if processName, ok := bb.Key.(string); !ok {
						log.Warnf("failed to convert bucket key %v to string", bb.Key)
						continue
					} else {
						if processIDItems, found := bb.Terms(processIDKey); !found {
							log.Warnf("failed to get bucket key %s in sub-aggregation", processIDKey)
							continue
						} else {
							process := v1.ProcessInfo{
								Cluster:  cluster,
								Name:     processName,
								Endpoint: endpoint,
								Count:    len(processIDItems.Buckets),
							}
							procs = append(procs, process)
						}
					}
				}
			}

		}
		return procs
	}
}

// buildQuery builds an elastic query using the given parameters.
func (b *processBackend) buildQuery(i bapi.ClusterInfo, opts *v1.ProcessParams) (elastic.Query, error) {
	// Start with the base flow log query using common fields.
	query, err := logtools.BuildQuery(b.queryHelper, i, opts)
	if err != nil {
		return nil, err
	}

	// Exclude process_name in ["-", "*"] and process_id in "*"
	excludes := []elastic.Query{
		elastic.NewTermsQuery("process_name", "-", "*"),
		elastic.NewTermQuery("process_id", "*"),
	}
	query = query.MustNot(excludes...)

	// For process queries, we must always match on resporter = src, since they
	// are the only logs with process information present.
	query.Must(elastic.NewTermQuery("reporter", "src"))

	return query, nil
}

// getAggregation returns the aggregations for flow log elastic search.
func getAggregation(esClient *elastic.Client) (*elastic.TermsAggregation, error) {
	// aggregation
	// "aggs": {
	//     "agg-source_name_aggr": {
	//       "terms": {
	//         "field": "source_name_aggr",
	//         "size": 1000
	//       },
	//       "aggs": {
	//         "agg-process_name": {
	//           "terms": {
	//             "field": "process_name",
	//             "size": 1000
	//           },
	//           "aggs": {
	//             "agg-process_id": {
	//               "terms": {
	//                 "field": "process_id",
	//                 "size": 1000
	//               }
	//             }
	//           }
	//         }
	//       }
	//     }
	//   }
	aggCluster := elastic.NewTermsAggregation()
	aggCluster.Field("cluster")
	aggCluster.Size(defaultAggregationSize)

	aggSourceNameAggr := elastic.NewTermsAggregation()
	aggSourceNameAggr.Field("source_name_aggr")
	aggSourceNameAggr.Size(defaultAggregationSize)
	aggCluster.SubAggregation(sourceNameAggrKey, aggSourceNameAggr)

	aggProcessName := elastic.NewTermsAggregation()
	aggProcessName.Field("process_name")
	aggProcessName.Size(defaultAggregationSize)
	aggSourceNameAggr.SubAggregation(processNameKey, aggProcessName)

	aggProcessID := elastic.NewTermsAggregation()
	aggProcessID.Field("process_id")
	aggProcessID.Size(defaultAggregationSize)
	aggProcessName.SubAggregation(processIDKey, aggProcessID)

	return aggCluster, nil
}
