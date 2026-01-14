// Copyright (c) 2020, 2023 Tigera, Inc. All rights reserved.
package elastic

import (
	"context"
	"fmt"
	"sort"

	"github.com/olivere/elastic/v7"
	log "github.com/sirupsen/logrus"
)

const (
	resultBucketSize = 1000
)

// Structure encapsulating info about a composite source query.
type AggCompositeSourceInfo struct {
	// The source name.
	Name string

	// The underlying field for terms or histogram sources.
	Field string

	// Histogram intervals.
	HistogramInterval     float64
	HistogramDateInterval string

	// For scripted source.
	ScriptName   string
	ScriptParams map[string]interface{}

	// Sort order
	Order string

	// Allow missing.
	AllowMissingBucket bool
}

// Structure encapsulating info about a aggregated term query.
type AggNestedTermInfo struct {
	Name  string
	Path  string
	Term  string
	Field string
}

// Structure encapsulating info about a aggregated sum query.
type AggSumInfo struct {
	Name  string
	Field string
}

// Structure encapsulating info about a aggregated max/min query.
type AggMaxMinInfo struct {
	Name  string
	Field string
}

// Structure encapsulating info about a aggregated mean query.
type AggMeanInfo struct {
	Name        string
	Field       string
	WeightField string
}

// Structure encapsulating info about an aggregated standard term query.
type AggTermInfo struct {
	Name  string
	Field string
}

// CompositeAggregationQuery encapsulates and provides helper functions for a composite aggregation query. This
// assumes we require a very specific type of query which means we can simplify the otherwise richer Elasticsearch API
// into something a little easier to process.
//
// This simpler API assumes queries of the following format:
//
// GET tigera_secure_ee_flows*/_search
//
//	{
//	 "size": 0,
//	 "query": "<.Query>",                                          <- Populated from Query
//	 "aggs": {
//	   "flog_buckets": {                                           <- Populated from Name
//	     "composite": {
//	       "size": 1000,
//	       "sources": [                                            <- Populated from AggCompositeSourceInfos
//	         {
//	           "<.AggCompositeSourceInfo.Name>": {
//	             "terms": {
//	               "field": "<.AggCompositeSourceInfo.Field>"
//	             }
//	           }
//	         },
//	         ...
//	       ]
//	     },
//	     "aggs": {
//	       "<.AggNestedTermInfo.Name>": {                          <- Populated from AggNestedTermInfos
//	         "nested": { "path": "<.AggNestedTermInfo.Path>" },
//	         "aggregations": {
//	           "<.AggNestedTermInfo.Term>": {                      <- Note: Only a single term is supported which means
//	             "terms": {                                                 the results can discard some additional
//	               "field": "<.AggNestedTermInfo.Field>"                    hierarchy.
//	             }
//	           }
//	         }
//	       },
//	       ...
//	       "<.AggSumInfo.Name>": {                                 <- Populated from AggSumInfo
//	         "sum": {
//	           "field": "<.AggSumInfo.Field>"
//	         }
//	       },
//	       ...
//	     }
//	   }
//	 }
//	}
type CompositeAggregationQuery struct {
	// The document index to search. For flow logs this could be "tigera_secure_ee_flows.cluster.*".
	DocumentIndex string

	// The elastic-formatted query.
	Query elastic.Query

	// The name of the aggregation. For flow logs this would be "flog_buckets"
	Name string

	// The sources for the composite aggregation.
	AggCompositeSourceInfos []AggCompositeSourceInfo

	// The nested terms aggregation info.
	AggNestedTermInfos []AggNestedTermInfo

	// The aggregated term info.
	AggTermInfos []AggTermInfo

	// The aggregated sums info.
	AggSumInfos []AggSumInfo

	// The aggregated max info.
	AggMaxInfos []AggMaxMinInfo

	// The aggregated min info.
	AggMinInfos []AggMaxMinInfo

	// The aggregated means info.
	AggMeanInfos []AggMeanInfo

	// The max buckets each iteration. Defaults to resultsBucketSize. Generally this should not need to be modified
	// but it may become necessary to query smaller buckets if the amount of data is large, or could be incremented
	// if there are no sub aggregations.
	MaxBucketsPerQuery int
}

// getCompositeAggregation returns the CompositeAggregation associated with the query parameters.
func (q *CompositeAggregationQuery) getCompositeAggregation() *elastic.CompositeAggregation {
	// Aggregate documents and fetch results based on Elasticsearch recommended batches of "resultBucketSize".
	compiledCompositeSources := []elastic.CompositeAggregationValuesSource{}
	for _, c := range q.AggCompositeSourceInfos {
		var vs elastic.CompositeAggregationValuesSource
		if c.HistogramDateInterval != "" {
			vs = elastic.NewCompositeAggregationDateHistogramValuesSource(c.Name).Field(c.Field).
				CalendarInterval(c.HistogramDateInterval).Order(c.Order).MissingBucket(c.AllowMissingBucket)
		} else if c.HistogramInterval != 0 {
			vs = elastic.NewCompositeAggregationHistogramValuesSource(c.Name, c.HistogramInterval).
				Field(c.Field).Order(c.Order).MissingBucket(c.AllowMissingBucket)
		} else if c.Field != "" {
			vs = elastic.NewCompositeAggregationTermsValuesSource(c.Name).Field(c.Field).Order(c.Order).MissingBucket(c.AllowMissingBucket)
		} else if c.ScriptName != "" {
			vs = elastic.NewCompositeAggregationTermsValuesSource(c.Name).
				Script(elastic.NewScriptStored(c.ScriptName).Params(c.ScriptParams)).Order(c.Order).MissingBucket(c.AllowMissingBucket)
		}

		compiledCompositeSources = append(compiledCompositeSources, vs)
	}
	compiledCompositeAgg := elastic.NewCompositeAggregation().
		Sources(compiledCompositeSources...).
		Size(q.getMaxBuckets())

	// Add the aggregated sums, max, min and means.
	for _, a := range q.AggSumInfos {
		compiledCompositeAgg.SubAggregation(a.Name, elastic.NewSumAggregation().Field(a.Field))
	}
	for _, a := range q.AggMaxInfos {
		compiledCompositeAgg.SubAggregation(a.Name, elastic.NewMaxAggregation().Field(a.Field))
	}
	for _, a := range q.AggMinInfos {
		compiledCompositeAgg.SubAggregation(a.Name, elastic.NewMinAggregation().Field(a.Field))
	}
	for _, a := range q.AggMeanInfos {
		if a.WeightField != "" {
			compiledCompositeAgg.SubAggregation(a.Name, elastic.NewWeightedAvgAggregation().
				Value(&elastic.MultiValuesSourceFieldConfig{FieldName: a.Field}).
				Weight(&elastic.MultiValuesSourceFieldConfig{FieldName: a.WeightField}))
		} else {
			compiledCompositeAgg.SubAggregation(a.Name, elastic.NewAvgAggregation().Field(a.Field))
		}
	}

	// Add the aggregated terms.
	for _, a := range q.AggNestedTermInfos {
		compiledCompositeAgg.SubAggregation(
			a.Name,
			elastic.NewNestedAggregation().Path(a.Path).SubAggregation(a.Term, elastic.NewTermsAggregation().Field(a.Field)),
		)
	}

	// Add the aggregated top-level terms.
	for _, a := range q.AggTermInfos {
		field := a.Field
		if field == "" {
			field = a.Name
		}
		compiledCompositeAgg.SubAggregation(a.Name, elastic.NewTermsAggregation().Field(field))
	}

	return compiledCompositeAgg
}

func (q *CompositeAggregationQuery) getMaxBuckets() int {
	if q.MaxBucketsPerQuery > 0 {
		return q.MaxBucketsPerQuery
	}
	return resultBucketSize
}

// ConvertBucket converts the aggregation bucket result to a CompositeAggregationBucket using the query parameters.
//
// Wire format of response:
//
//	{
//	 "aggregations": {
//	   "flog_buckets": {                                        <- Name
//	     "buckets": [
//	       {
//	         "doc_count": 3,
//	         "key": {
//	           "flow_impacted": true,
//	           "action": "allow",
//	           "dest_name": "calico-apiserver-65954bfd46-*",
//	           "dest_namespace": "kube-system",
//	           "dest_type": "wep",
//	           "reporter": "src",
//	           "source_name": "calico-apiclient-65954bfd46-*",
//	           "source_namespace": "compliance",
//	           "source_type": "wep"
//	         },
//	         "dest_labels": {
//	           "by_kvpair": {
//	             "buckets": [
//	               {
//	                 "doc_count": 3,
//	                 "key": "apiserver=true"
//	               },
//	               {
//	                 "doc_count": 3,
//	                 "key": "k8s-app=calico-apiserver"
//	               },
//	               {
//	                 "doc_count": 3,
//	                 "key": "pod-template-hash=65954bfd46"
//	               }
//	             ],
//	             "doc_count_error_upper_bound": 0,
//	             "sum_other_doc_count": 0
//	           },
//	           "doc_count": 3
//	         },
//	         "sum_bytes_in": {
//	           "value": 10000
//	         }
//	       },
//	     ]
//	   }
//	 }
//	}
func (q *CompositeAggregationQuery) ConvertBucket(item *elastic.AggregationBucketCompositeItem) (*CompositeAggregationBucket, error) {
	return q.ConvertBucketHelper(item, false)
}

func (q *CompositeAggregationQuery) ConvertBucketHelper(item *elastic.AggregationBucketCompositeItem, allowMissing bool) (*CompositeAggregationBucket, error) {
	// Extract the data from the response.
	cab := NewCompositeAggregationBucket(item.DocCount)

	// Extract the key data.
	for i := range q.AggCompositeSourceInfos {
		// Get the composite value to construct our key. Error out if it isn't there.
		name := q.AggCompositeSourceInfos[i].Name
		val, ok := item.Key[name]
		if !ok {
			if allowMissing {
				cab.CompositeAggregationKey = append(cab.CompositeAggregationKey, CompositeAggregationSourceValue{Name: name, Value: ""})
				continue
			}
			log.Errorf("Error fetching composite results: %s", name)
			return nil, fmt.Errorf("error fetching composite results: %s missing from response", name)
		}
		cab.CompositeAggregationKey = append(cab.CompositeAggregationKey, CompositeAggregationSourceValue{Name: name, Value: val})
	}

	// Extract the aggregated sum, max, min and mean data.
	for i := range q.AggSumInfos {
		name := q.AggSumInfos[i].Name
		val, ok := item.Sum(name)
		if !ok || val.Value == nil {
			// We don't need the sum value, so if not present log and continue.
			log.Debugf("Error fetching aggregated sum results: %s", name)
			continue
		}
		cab.AggregatedSums[name] = *val.Value
	}
	for i := range q.AggMaxInfos {
		name := q.AggMaxInfos[i].Name
		val, ok := item.Max(name)
		if !ok || val.Value == nil {
			// We don't need the value, so if not present log and continue.
			log.Debugf("Error fetching aggregated max results: %s", name)
			continue
		}
		cab.AggregatedMax[name] = *val.Value
	}
	for i := range q.AggMinInfos {
		name := q.AggMinInfos[i].Name
		val, ok := item.Min(name)
		if !ok || val.Value == nil {
			// We don't need the value, so if not present log and continue.
			log.Debugf("Error fetching aggregated min results: %s", name)
			continue
		}
		cab.AggregatedMin[name] = *val.Value
	}
	for i := range q.AggMeanInfos {
		name := q.AggMeanInfos[i].Name
		val, ok := item.Avg(name)
		if !ok || val.Value == nil {
			// We don't need the value, so if not present log and continue.
			log.Debugf("Error fetching aggregated mean results: %s", name)
			continue
		}
		cab.AggregatedMean[name] = *val.Value
	}

	// Extract the aggregated terms.
	for i := range q.AggNestedTermInfos {
		name := q.AggNestedTermInfos[i].Name
		nested, ok := item.Nested(name)
		if !ok {
			// We don't need the terms value, so if not present log and continue.
			log.Errorf("Error fetching aggregated terms: %s", name)
			continue
		}

		term := q.AggNestedTermInfos[i].Term
		buckets, ok := nested.Terms(term)
		if !ok {
			// We don't need the terms buckets, so if not present log and continue.
			log.Errorf("Error fetching aggregated terms buckets: %s/%s; %#v", name, term, nested.Aggregations[term])
			continue
		}
		t, exists := cab.AggregatedTerms[name]
		if !exists {
			t = NewAggregatedTerm(nested.DocCount)
			cab.AggregatedTerms[name] = t
		}

		if t.MultiTermBuckets == nil {
			t.MultiTermBuckets = make(map[string]map[interface{}]int64)
		}

		termBuckets := make(map[interface{}]int64)
		// Reset legacy buckets to ensure "last one wins" behavior for legacy field
		t.Buckets = make(map[interface{}]int64)

		for _, b := range buckets.Buckets {
			termBuckets[b.Key] = b.DocCount
			t.Buckets[b.Key] = b.DocCount
		}
		t.MultiTermBuckets[term] = termBuckets
	}

	// Extract the aggregated top-level terms.
	for i := range q.AggTermInfos {
		name := q.AggTermInfos[i].Name

		buckets, ok := item.Terms(name)
		if !ok {
			// We don't need the terms buckets, so if not present log and continue.
			log.Errorf("Error fetching aggregated terms buckets: %s", name)
			continue
		}
		t := NewAggregatedTerm(int64(len(buckets.Buckets)))
		for _, b := range buckets.Buckets {
			t.Buckets[b.Key] = b.DocCount
		}

		cab.AggregatedTerms[name] = t
	}

	return cab, nil
}

// NewCompositeAggregationBucket returns a new CompositeAggregationBucket.
func NewCompositeAggregationBucket(dc int64) *CompositeAggregationBucket {
	return &CompositeAggregationBucket{
		DocCount:        dc,
		AggregatedTerms: make(map[string]*AggregatedTerm),
		AggregatedSums:  make(map[string]float64),
		AggregatedMax:   make(map[string]float64),
		AggregatedMin:   make(map[string]float64),
		AggregatedMean:  make(map[string]float64),
	}
}

// CompositeAggregationBucket is a structure containing a single result from a composite aggregation query. The
// structure loosely resembles the json structure on the wire, but is more easily arranged to perform additional
// aggregation, in particular we lose some of the hierarchy which is not required due to imposed limitations on the
// scope of the query.
type CompositeAggregationBucket struct {
	// The number of documents included in the aggregation.
	DocCount int64

	// Ordered set of source values that make up the composite key. The order of the key-value pairs is important as it
	// follows the natural ordering of results from ES. This is important when we want to limit a query to the first
	// <n> unique keys.
	// Wire format:
	//          "key": {
	//            "source_type": "wep",
	//            "source_namespace": "calico-monitoring",
	//            "source_name_aggr": "alertmanager-calico-node-alertmanager-*",
	//            "dest_type": "wep",
	//            "dest_namespace": "calico-monitoring",
	//            "dest_name_aggr": "alertmanager-calico-node-alertmanager-*",
	//          }
	CompositeAggregationKey CompositeAggregationKey `json:"key"`

	// The set of aggregated terms.
	// Wire format:
	//          "policies": {          <- This is the map key
	//            "doc_count": 34,
	//            "by_tiered_policy": {
	//              "doc_count_error_upper_bound": 0,
	//              "sum_other_doc_count": 0,
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",
	//                  "doc_count": 34
	//                }
	//              ]
	//            }
	//            "by_tiered_enforced_policy": {
	//              "doc_count_error_upper_bound": 0,
	//              "sum_other_doc_count": 0,
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",
	//                  "doc_count": 34
	//                }
	//              ]
	//            }
	//            "by_tiered_pending_policy": {
	//              "doc_count_error_upper_bound": 0,
	//              "sum_other_doc_count": 0,
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",
	//                  "doc_count": 34
	//                }
	//              ]
	//            }
	//            "by_tiered_transit_policy": {
	//              "doc_count_error_upper_bound": 0,
	//              "sum_other_doc_count": 0,
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",
	//                  "doc_count": 34
	//                }
	//              ]
	//            }
	//          },
	AggregatedTerms map[string]*AggregatedTerm

	// The set of aggregated sums, max, min and means.
	// Wire format:
	//          "sum_bytes_out": {
	//            "value": 1858761
	//          },
	AggregatedSums map[string]float64
	AggregatedMax  map[string]float64
	AggregatedMin  map[string]float64
	AggregatedMean map[string]float64
}

// Aggregate aggregates in the values from cin. Both cout and cin should represent the same aggregation bucket, but
// no checks are actually made to ensure this is the case. The value of cin is guaranteed not to be updated directly
// or indirectly as a result of this operation (i.e. no references/slices etc are ever transferred unsafely).
func (cout *CompositeAggregationBucket) Aggregate(cin *CompositeAggregationBucket) {
	// Agg overall doc count.
	cout.DocCount += cin.DocCount

	// Aggregated each of the nested term aggregations.
	for kin, vin := range cin.AggregatedTerms {
		vout, ok := cout.AggregatedTerms[kin]
		if !ok {
			vout = NewAggregatedTerm(0)
			cout.AggregatedTerms[kin] = vout
		}
		vout.DocCount += vin.DocCount
		for kinB, vinB := range vin.Buckets {
			vout.Buckets[kinB] += vinB
		}

		if len(vin.MultiTermBuckets) > 0 {
			if vout.MultiTermBuckets == nil {
				vout.MultiTermBuckets = make(map[string]map[interface{}]int64)
			}
			for term, buckets := range vin.MultiTermBuckets {
				if vout.MultiTermBuckets[term] == nil {
					vout.MultiTermBuckets[term] = make(map[interface{}]int64)
				}
				for k, v := range buckets {
					vout.MultiTermBuckets[term][k] += v
				}
			}
		}
	}

	// Aggregated each of the sum aggregations.
	for kin, vin := range cin.AggregatedSums {
		cout.AggregatedSums[kin] += vin
	}
}

// SetAggregatedTermsFromStringSlice replaces the specified terms (or creates if it doesn't exist) with the ones
// specified in the string slice.
//   - If the entry exists, the DocCount from the term aggregation is used to populate each of the buckets.
//   - If the entry does not exist, the DocCount from the CompositeAggregationBucket is used to populate the
//     term aggregation and each bucket.
func (cout *CompositeAggregationBucket) SetAggregatedTermsFromStringSlice(name string, vals []string) {
	terms, ok := cout.AggregatedTerms[name]
	if !ok {
		terms = NewAggregatedTerm(cout.DocCount)
		cout.AggregatedTerms[name] = terms
	} else {
		terms.Buckets = make(map[interface{}]int64)
	}
	for _, val := range vals {
		terms.Buckets[val] = terms.DocCount
	}
}

// CompositeAggregationKey contains the enumerated composite aggregation key (set of source/value pairs)
type CompositeAggregationKey []CompositeAggregationSourceValue

// SameBucket returns true if other has the same set of indices as this key. The `other` key should have the same or
// more indices than c.
func (c CompositeAggregationKey) SameBucket(other CompositeAggregationKey) bool {
	for i := range c {
		if c[i].Value != other[i].Value {
			return false
		}
	}
	return true
}

// CompositeAggregationSourceValue contains the name and value of a source in a composite aggregation key.
// TODO(rlb): I'm not sure we need the name in this structure since it can be inferred from the Query and we aren't
// using it for self-consistency checks when comparing sets of keys.
type CompositeAggregationSourceValue struct {
	Name  string
	Value interface{}
}

// String returns the value as a string. If the value is not a string, an empty string will be returned.
func (c CompositeAggregationSourceValue) String() string {
	v, _ := c.Value.(string)
	return v
}

// Float64 returns the value as a float64. If the value is not a float64, 0 will be returned.
func (c CompositeAggregationSourceValue) Float64() float64 {
	v, _ := c.Value.(float64)
	return v
}

// NewAggregatedTerm creates a new AggregatedTerm
func NewAggregatedTerm(dc int64) *AggregatedTerm {
	return &AggregatedTerm{
		DocCount: dc,
		Buckets:  make(map[interface{}]int64),
	}
}

// AggregatedTerm contains the results of an aggregated term query.
type AggregatedTerm struct {
	DocCount int64

	// The aggregated term buckets.
	// Wire format:
	//            "by_tiered_policy": {                 <- We "swallow" this key because we only allow a single term
	//              "doc_count_error_upper_bound": 0,   <- We don't track this
	//              "sum_other_doc_count": 0,           <- We don't track this
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",  <- This is the map key
	//                  "doc_count": 34                       <- This is the map value
	//                }
	//              ]
	//            }
	//            "by_tiered_enforced_policy": {        <- We "swallow" this key because we only allow a single term
	//              "doc_count_error_upper_bound": 0,   <- We don't track this
	//              "sum_other_doc_count": 0,           <- We don't track this
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",  <- This is the map key
	//                  "doc_count": 34                       <- This is the map value
	//                }
	//              ]
	//            }
	//            "by_tiered_pending_policy": {         <- We "swallow" this key because we only allow a single term
	//              "doc_count_error_upper_bound": 0,   <- We don't track this
	//              "sum_other_doc_count": 0,           <- We don't track this
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",  <- This is the map key
	//                  "doc_count": 34                       <- This is the map value
	//                }
	//              ]
	//            }
	//            "by_tiered_transit_policy": {         <- We "swallow" this key because we only allow a single term
	//              "doc_count_error_upper_bound": 0,   <- We don't track this
	//              "sum_other_doc_count": 0,           <- We don't track this
	//              "buckets": [
	//                {
	//                  "key": "0|default|calico-monito...",  <- This is the map key
	//                  "doc_count": 34                       <- This is the map value
	//                }
	//              ]
	//            }
	Buckets map[interface{}]int64

	// MultiTermBuckets contains the buckets for multiple terms under the same nested aggregation.
	// The key is the term name.
	MultiTermBuckets map[string]map[interface{}]int64
}

// TimedOutError is returned when the response indicates a timeout.
type TimedOutError string

func (e TimedOutError) Error() string {
	return string(e)
}

// SearchCompositeAggregations queries ES for the requested composite aggregations.
//
// Caller should enumerate results and then check for error once channel is closed. All errors are terminating.
func (c *client) SearchCompositeAggregations(
	ctx context.Context,
	query *CompositeAggregationQuery,
	startAfterKey CompositeAggregationKey,
) (<-chan *CompositeAggregationBucket, <-chan error) {
	return searchCompositeAggregationsHelper(ctx, query, startAfterKey, c)
}

// SearchCompositeAggregations queries ES for the requested composite aggregations.
//
// Caller should enumerate results and then check for error once channel is closed. All errors are terminating.
func (c *mockComplianceClient) SearchCompositeAggregations(
	ctx context.Context,
	query *CompositeAggregationQuery,
	startAfterKey CompositeAggregationKey,
) (<-chan *CompositeAggregationBucket, <-chan error) {
	return searchCompositeAggregationsHelper(ctx, query, startAfterKey, c)
}

// PagedSearch returns a page of items. If there are more items to retrieve, a key will also be returned
// which can be used on subsequent calls to retrive the next page.
func PagedSearch[T any](ctx context.Context,
	c Client,
	query *CompositeAggregationQuery,
	log *log.Entry,
	convert func(*log.Entry, *CompositeAggregationBucket) *T,
	resultsAfter map[string]interface{},
) ([]T, map[string]interface{}, error) {
	// Query the document index. We aren't interested in the actual search results but rather only the aggregated
	// results.
	searchQuery := c.Backend().Search().
		Index(query.DocumentIndex).
		Size(0).
		Query(query.Query)

	// Construct the Aggregation for the query.
	compiledCompositeAgg := query.getCompositeAggregation()

	if resultsAfter != nil {
		log.Debugf("Enumerating after key %+v", resultsAfter)
		compiledCompositeAgg = compiledCompositeAgg.AggregateAfter(resultsAfter)
	}

	log.Debugf("Performing composite aggregation against index %s", query.DocumentIndex)
	queryAgg := searchQuery.Aggregation(query.Name, compiledCompositeAgg)
	searchResult, err := c.Do(ctx, queryAgg)
	if err != nil {
		// We hit an error, exit. This may be a context done error, but that's fine, pass the error on.
		log.WithError(err).Debugf("Error searching %s", query.DocumentIndex)
		return nil, nil, err
	}

	// Exit if the search timed out. We return a very specific error type that can be recognized by the
	// consumer - this is useful in propagating the timeout up the stack when we are doing server side
	// aggregation.
	if searchResult.TimedOut {
		log.Errorf("Elastic query timed out: %s", query.DocumentIndex)
		return nil, nil, TimedOutError(fmt.Sprintf("timed out querying %s", query.DocumentIndex))
	}

	// Extract the buckets from the search results. If there are no results the buckets item will not be
	// present.
	// TODO(rlb): If this processing proves to be too slow we may need to use a streaming json unserializer and
	//           hook directly into the HTTP client.
	rawResults, ok := searchResult.Aggregations.Composite(query.Name)
	if !ok {
		log.Infof("No results for composite query of %s", query.DocumentIndex)
		return nil, nil, nil
	}

	// Loop through each of the items in the buckets and convert to a page of objects.
	page := []T{}
	for _, item := range rawResults.Buckets {
		log.Debugf("Processing bucket built from %d logs", item.DocCount)
		cab, err := query.ConvertBucket(item)
		if err != nil {
			log.WithError(err).Error("error processing ES composite aggregation bucket")
			return nil, nil, err

		}

		// Now convert to the desired output type.
		if obj := convert(log, cab); obj != nil {
			page = append(page, *obj)
		}
	}

	// If we get fewer than the requested number of buckets, or if there is no AfterKey, it means that there are no more
	// pages to be queried. So, just return the page without any continuation key.
	if len(rawResults.Buckets) < query.getMaxBuckets() || rawResults.AfterKey == nil || len(rawResults.AfterKey) == 0 {
		log.Debugf("Completed processing %s", query.DocumentIndex)
		return page, nil, nil
	}

	// There's another page after this one - return the AfterKey so that callers can
	// use it to query the next page.
	return page, rawResults.AfterKey, nil
}

func PagedCount(ctx context.Context,
	c Client,
	query *CompositeAggregationQuery,
	logger *log.Entry,
	maxCount *int64,
	process func(*log.Entry, *CompositeAggregationBucket),
) (int64, bool, error) {
	var afterKey map[string]interface{}
	var count int64
	var truncated bool
	var err error
	for {
		// Wrap the function that processes each bucket in a function that respects the conversion function interface.
		// We are only interested in counting buckets, not assembling pages from converted buckets. Therefore, we
		// return nil and count the buckets ourselves.
		convert := func(l *log.Entry, c *CompositeAggregationBucket) *any {
			count++
			process(l, c)
			return nil
		}

		_, afterKey, err = PagedSearch(ctx, c, query, logger, convert, afterKey)
		if err != nil {
			return 0, false, err
		}

		if afterKey == nil {
			break
		}

		if maxCount != nil && count >= *maxCount {
			truncated = true
			break
		}
	}

	return count, truncated, nil
}

func searchCompositeAggregationsHelper(
	ctx context.Context,
	query *CompositeAggregationQuery,
	startAfterKey CompositeAggregationKey,
	c Client,
) (<-chan *CompositeAggregationBucket, <-chan error) {
	// Create the results and errs channel.
	results := make(chan *CompositeAggregationBucket, resultBucketSize)
	errs := make(chan error, 1)

	// Perform the ES query on a go-routine.
	go func() {
		// Close the two channels when the go routine completes.
		defer func() {
			close(results)
			close(errs)
		}()

		// Query the document index. We aren't interested in the actual search results but rather only the aggregated
		// results.
		searchQuery := c.Backend().Search().
			Index(query.DocumentIndex).
			Size(0).
			Query(query.Query)

		// If a start after key was supplied then convert to the appropriate format for the client.
		var resultsAfter map[string]interface{}
		if startAfterKey != nil {
			resultsAfter = make(map[string]interface{})
			for _, k := range startAfterKey {
				resultsAfter[k.Name] = k.Value
			}
		}

		// Construct the Aggregation for the query.
		compiledCompositeAgg := query.getCompositeAggregation()

		// Issue the query to Elasticsearch and send results out through the results channel. We terminate the search if:
		// - there are no more "buckets" returned by Elasticsearch or the equivalent no-or-empty "after_key" in the
		//   aggregated search results,
		// - we hit an error, or
		// - the context indicates "done"
		for {
			if resultsAfter != nil {
				log.Debugf("Enumerating after key %+v", resultsAfter)
				compiledCompositeAgg = compiledCompositeAgg.AggregateAfter(resultsAfter)
			}

			log.Debug("Issuing search query")
			queryAgg := searchQuery.Aggregation(query.Name, compiledCompositeAgg)

			searchResult, err := c.Do(ctx, queryAgg)
			if err != nil {
				// We hit an error, exit. This may be a context done error, but that's fine, pass the error on.
				log.WithError(err).Debugf("Error searching %s", query.DocumentIndex)
				errs <- err
				return
			}

			// Exit if the search timed out. We return a very specific error type that can be recognized by the
			// consumer - this is useful in propagating the timeout up the stack when we are doing server side
			// aggregation.
			if searchResult.TimedOut {
				log.Errorf("Elastic query timed out: %s", query.DocumentIndex)
				errs <- TimedOutError(fmt.Sprintf("timed out querying %s", query.DocumentIndex))
			}

			// Extract the buckets from the search results. If there are no results the buckets item will not be
			// present.
			// TODO(rlb): If this processing proves to be too slow we may need to use a streaming json unserializer and
			//           hook directly into the HTTP client.
			rawResults, ok := searchResult.Aggregations.Composite(query.Name)
			if !ok {
				log.Debugf("No results for composite query of %s", query.DocumentIndex)
				return
			}
			// Loop through each of the items in the buckets and convert to a result bucket.
			for _, item := range rawResults.Buckets {
				log.Debugf("aggregation bucket: %v", item.Key)
				cab, err := query.ConvertBucket(item)
				if err != nil {
					log.WithError(err).Error("error processing ES composite aggregation bucket")
					errs <- err
					return

				}
				select {
				case results <- cab:
					// Result successfully in channel.
				case <-ctx.Done():
					// Context indicates done, exit immediately.
					log.WithError(ctx.Err()).Debug("Context done")
					errs <- ctx.Err()
					return
				}
			}

			// If we get the requested number of buckets then there may be more results to obtain.
			if len(rawResults.Buckets) < query.getMaxBuckets() || rawResults.AfterKey == nil || len(rawResults.AfterKey) == 0 {
				return
			}

			resultsAfter = rawResults.AfterKey
		}
	}()

	return results, errs
}

// CompositeAggregationBucketsToMap converts the slice to CompositeAggregationBucket into a map that can easily be
// json serialized.
func CompositeAggregationBucketsToMap(
	buckets []*CompositeAggregationBucket,
	query *CompositeAggregationQuery,
) map[string]interface{} {
	// Determine the mapping from Name to Term for the nested term aggregations.
	nameTermMappings := make(map[string]string)
	for i := range query.AggNestedTermInfos {
		nameTermMappings[query.AggNestedTermInfos[i].Name] = query.AggNestedTermInfos[i].Term
	}

	bucketMaps := make([]map[string]interface{}, len(buckets))
	for i, bucket := range buckets {
		bucketMaps[i] = compositeAggregationBucketToMap(bucket, nameTermMappings)
	}

	return map[string]interface{}{
		query.Name: map[string]interface{}{
			"buckets": bucketMaps,
		},
	}
}

// compositeAggregationBucketToMap converts a CompositeAggregationBucket into a map that can easily be json serialized.
func compositeAggregationBucketToMap(
	bucket *CompositeAggregationBucket,
	nameTermMappings map[string]string,
) map[string]interface{} {
	// Calculate the key.
	key := make(map[string]interface{})
	for _, cak := range bucket.CompositeAggregationKey {
		key[cak.Name] = cak.Value
	}

	// Create the bucket map.
	bucketMap := map[string]interface{}{
		"doc_count": bucket.DocCount,
		"key":       key,
	}

	// Add in the aggregated sums, max, min and means.
	for name, value := range bucket.AggregatedSums {
		bucketMap[name] = map[string]interface{}{
			"value": value,
		}
	}
	for name, value := range bucket.AggregatedMax {
		bucketMap[name] = map[string]interface{}{
			"value": value,
		}
	}
	for name, value := range bucket.AggregatedMin {
		bucketMap[name] = map[string]interface{}{
			"value": value,
		}
	}
	for name, value := range bucket.AggregatedMean {
		bucketMap[name] = map[string]interface{}{
			"value": value,
		}
	}

	// Add in the aggregated terms.
	for name, value := range bucket.AggregatedTerms {
		if len(value.MultiTermBuckets) > 0 {
			nestedMap := map[string]interface{}{
				"doc_count": value.DocCount,
			}
			for term, buckets := range value.MultiTermBuckets {
				termBuckets := make(sortedTermBucketMaps, 0, len(buckets))
				for key, count := range buckets {
					termBuckets = append(termBuckets, map[string]interface{}{
						"doc_count": count,
						"key":       key,
					})
				}
				sort.Sort(sort.Reverse(termBuckets))
				nestedMap[term] = map[string]interface{}{
					"buckets": termBuckets,
				}
			}
			bucketMap[name] = nestedMap
		} else {
			termBuckets := make(sortedTermBucketMaps, 0, len(value.Buckets))
			for key, count := range value.Buckets {
				termBuckets = append(termBuckets, map[string]interface{}{
					"doc_count": count,
					"key":       key,
				})
			}

			// Sort the term buckets in order of doc count. We need this for our UTs.
			// TODO(rlb): We should also sort on the natural order of the key, but we don't yet have a use case.
			sort.Sort(sort.Reverse(termBuckets))

			bucketMap[name] = map[string]interface{}{
				"doc_count": value.DocCount,
				nameTermMappings[name]: map[string]interface{}{
					"buckets": termBuckets,
				},
			}
		}
	}

	return bucketMap
}

// CompositeAggregationResults encapsulates a single set of composite aggregation results. It is used for remarshaling
// the data into json.
type CompositeAggregationResults struct {
	Took         int64                  `json:"took"` // milliseconds
	TimedOut     bool                   `json:"timed_out"`
	Aggregations map[string]interface{} `json:"aggregations"`
}

// sortedTermBucketMaps is used to sort the nested term buckets when we marshal the data from an internal map structure
// to an ordered slice.
type sortedTermBucketMaps []map[string]interface{}

func (s sortedTermBucketMaps) Len() int {
	return len(s)
}

func (s sortedTermBucketMaps) Less(i, j int) bool {
	// Order by doc_count.
	if bmi, ok := s[i]["doc_count"]; !ok {
		return false
	} else if bmj, ok := s[j]["doc_count"]; !ok {
		return true
	} else {
		return bmi.(int64) < bmj.(int64)
	}
}

func (s sortedTermBucketMaps) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
