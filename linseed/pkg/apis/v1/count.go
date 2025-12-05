package v1

type CountResponse struct {
	// The total non-namespaced count of the resource
	GlobalCount *int64 `json:"global_count,omitempty"`

	// If true, the global count was truncated as a result of the MaxGlobalCount parameter.
	GlobalCountTruncated bool `json:"global_count_truncated,omitempty"`

	// The namespaced counts of the resource. Set to nil if not requested or if truncation prevented computation.
	NamespacedCounts map[string]int64 `json:"namespaced_counts"`
}

type FlowLogCountParams struct {
	FlowLogParams `json:",inline" validate:"required"`

	// Specify which counts should be computed and returned.
	CountType CountType `json:"count_type"  validate:"required"`
}

type L3FlowCountParams struct {
	L3FlowParams `json:",inline"`

	// If specified, the handler stops processing the count when this global limit is reached.
	// The returned count may exceed this value as a result of the page size used.
	MaxGlobalCount *int64 `json:"max_global_count,omitempty"`
}

type CountType string

const (
	// CountTypeGlobal - only the global count will be computed.
	CountTypeGlobal CountType = "global"

	// CountTypeNamespaced - only namespaced counts will be computed.
	CountTypeNamespaced CountType = "namespaced"

	// CountTypeGlobalAndNamespaced - both global and namespaced counts will be computed.
	CountTypeGlobalAndNamespaced CountType = "global_and_namespaced"
)
