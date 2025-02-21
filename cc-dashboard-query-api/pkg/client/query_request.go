package client

import (
	"github.com/tigera/tds-apiserver/lib/slices"
)

// QueryRequest A query request
type QueryRequest struct {
	// MaxDocs maximum number of documents in the response of non-aggregated requests
	MaxDocs *int `json:"maxDocs"`

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

// QueryRequestFilterCriterion A document filter criterion
type QueryRequestFilterCriterion struct {

	// Type criterion type
	Type CriterionType `json:"type" validate:"required,oneof=dateRange equals exists in ipRange or range relativeTimeRange startsWith wildcard"`

	// Field Document field for the filter criterion
	Field string `json:"field,omitempty"`

	// Pattern Wildcard criterion match Pattern for the Field value
	Pattern string `json:"pattern,omitempty"`

	// Value Expected document Field value for the equals criterion
	Value any `json:"value,omitempty"`

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
	// TODO: set type to []QueryRequestFilterCriterion once tds-apiserver/pkg/http/handleradapters/openapi.go gets
	// fixed to not panic with a slice field of the same type as the parent struct
	Criteria []any `json:"criteria,omitempty"`
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

// GetCriteria returns a QueryRequestFilterCriterion criteria field
func (c QueryRequestFilterCriterion) GetCriteria() ([]QueryRequestFilterCriterion, error) {
	// See QueryRequestFilterCriterion.Criteria definition, this may be removed once QueryRequestFilterCriterion.Criteria
	// type is changed
	return slices.MapOrError(c.Criteria, func(criterionAny any) (QueryRequestFilterCriterion, error) {
		jsonCriterion, err := json.Marshal(criterionAny)
		if err != nil {
			return QueryRequestFilterCriterion{}, err
		}
		var criterion QueryRequestFilterCriterion
		if err := json.Unmarshal(jsonCriterion, &criterion); err != nil {
			return QueryRequestFilterCriterion{}, err
		}
		return criterion, nil
	})
}
