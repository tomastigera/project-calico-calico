package client

import (
	"strconv"
)

// QueryRequest A query request
type QueryRequest struct {
	// MaxDocs maximum number of documents in the response of non-aggregated requests
	MaxDocs *int `json:"maxDocs"`

	// PageNum specifies which page of results to return. Indexed from 0. [Default: 0]
	PageNum *int `json:"pageNum"`

	// CollectionName The collection being queried
	CollectionName CollectionName `json:"collectionName"`

	// ClusterFilter An array of cluster names to query documents by
	ClusterFilter []ManagedClusterName `json:"clusterFilter"`

	// Filters An array of document filters
	Filters []QueryRequestFilter `json:"filters" validate:"dive"`

	// GroupBys Document grouping aggregations
	GroupBys []QueryRequestGroup `json:"groupBys" validate:"dive"`

	// Aggregations Subaggregations for each group in GroupBys
	Aggregations QueryRequestAggregations `json:"aggregations"`

	// IsExport indicates if the request is for an export
	IsExport bool `json:"-"`
}

// QueryRequestFilter A document filter
type QueryRequestFilter struct {
	// Negate Match the opposite of the Criterion if true. Default to false
	Negate bool `json:"negate" default:"false"`

	// Criterion A document filter criterion
	Criterion QueryRequestFilterCriterion `json:"criterion"`
}

type ManagedClusterName string
type CriterionType string

const (
	CriterionTypeIn                = CriterionType("in")
	CriterionTypeOr                = CriterionType("or")
	CriterionTypeRange             = CriterionType("range")
	CriterionTypeEquals            = CriterionType("equals")
	CriterionTypeExists            = CriterionType("exists")
	CriterionTypeIPRange           = CriterionType("ipRange")
	CriterionTypeWildcard          = CriterionType("wildcard")
	CriterionTypeDateRange         = CriterionType("dateRange")
	CriterionTypeStartsWith        = CriterionType("startsWith")
	CriterionTypeRelativeTimeRange = CriterionType("relativeTimeRange")
)

type QueryRequestFilterCriterionValue struct {
	value any
}

// QueryRequestFilterCriterion A document filter criterion
type QueryRequestFilterCriterion struct {

	// Type criterion type
	Type CriterionType `json:"type" validate:"required,oneof=dateRange equals exists in ipRange or range relativeTimeRange startsWith wildcard"`

	// Field Document field for the filter criterion
	Field string `json:"field,omitempty"`

	// Pattern Wildcard criterion match Pattern for the Field value
	Pattern string `json:"pattern,omitempty"`

	// Value Expected document Field value for the equals criterion
	Value QueryRequestFilterCriterionValue `json:"value"`

	// Values Expected document values for the in criterion
	Values []string `json:"values,omitempty"`

	// GTE The lower bound time duration for the relativeTimeRange criterion in the format PT{value}{unit}, e.g. PT15M, PT1H
	GTE string `json:"gte,omitempty"`

	// LTE The upper bound time duration for the relative relativeTimeRange criterion in the format PT{value}{unit}, e.g. PT15M, PT1H
	LTE string `json:"lte,omitempty"`

	// From The lower bound ip for the ipRange criterion
	From string `json:"from,omitempty"`

	// To The upper bound ip for the ipRange criterion
	To string `json:"to,omitempty"`

	// Criteria A list of QueryRequestFilterCriterion for CriterionType that support child criteria
	Criteria []QueryRequestFilterCriterion `json:"criteria,omitempty"`
}

// QueryRequestGroup An aggregation group
type QueryRequestGroup struct {
	Interval  string                  `json:"interval"`
	FieldName string                  `json:"fieldName"`
	MaxValues int                     `json:"maxValues"`
	Order     *QueryRequestGroupOrder `json:"orderBy"`
}

type QueryRequestGroupOrderType string

// QueryRequestGroupOrder Group results sort order
type QueryRequestGroupOrder struct {
	SortAsc bool                       `json:"sortAsc"`
	Type    QueryRequestGroupOrderType `json:"type"`
	AggKey  string                     `json:"aggKey"`
}

type QueryRequestAggregationKey string
type QueryRequestAggregations map[QueryRequestAggregationKey]QueryRequestAggregation

type QueryRequestAggregation struct {
	Order     int                             `json:"order"`
	FieldName string                          `json:"fieldName"`
	Function  QueryRequestAggregationFunction `json:"function"`
}

type AggregationFunctionType string

const (
	AggregationFunctionTypeCount         = AggregationFunctionType("count")
	AggregationFunctionTypeSum           = AggregationFunctionType("sum")
	AggregationFunctionTypeAvg           = AggregationFunctionType("avg")
	AggregationFunctionTypeMin           = AggregationFunctionType("min")
	AggregationFunctionTypeMax           = AggregationFunctionType("max")
	AggregationFunctionTypePercentile50  = AggregationFunctionType("p50")
	AggregationFunctionTypePercentile90  = AggregationFunctionType("p90")
	AggregationFunctionTypePercentile95  = AggregationFunctionType("p95")
	AggregationFunctionTypePercentile100 = AggregationFunctionType("p100")
)

type QueryRequestAggregationFunction struct {
	Type AggregationFunctionType `json:"type"`
}

func NewQueryRequestFilterCriterionValue(value any) QueryRequestFilterCriterionValue {
	return QueryRequestFilterCriterionValue{value: value}
}

func (v *QueryRequestFilterCriterionValue) UnmarshalJSON(data []byte) error {

	var valueString string
	if val, err := strconv.ParseInt(string(data), 10, 64); err == nil {
		v.value = val
	} else if val, err := strconv.ParseFloat(string(data), 64); err == nil {
		v.value = val
	} else if err := json.Unmarshal(data, &valueString); err == nil {
		v.value = valueString
	} else {
		return err
	}

	return nil
}

func (v QueryRequestFilterCriterionValue) Value() any {
	return v.value
}
