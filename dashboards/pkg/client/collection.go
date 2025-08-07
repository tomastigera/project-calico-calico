package client

type CollectionsResponse []Collection

type CollectionName string
type CollectionFieldType string
type CollectionFieldName string

// Collection A document collection
type Collection struct {
	Name                 CollectionName      `json:"name"`
	Fields               []CollectionField   `json:"fields"`
	GroupBys             []CollectionGroupBy `json:"groupBys"`
	DefaultTimeFieldName CollectionFieldName `json:"defaultTimeFieldName"`
}

type CollectionField struct {
	Type         CollectionFieldType `json:"type"`
	Name         CollectionFieldName `json:"name"`
	Values       []string            `json:"values,omitempty"`
	DefaultValue string              `json:"defaultValue,omitempty"`

	// FilterDisabled disables the use of a field on filters if set to true
	FilterDisabled bool `json:"filterDisabled,omitempty"`

	// DisplayDisabled disables the use of a field on cards if set to true
	DisplayDisabled bool `json:"displayDisabled,omitempty"`

	// AggregationFunctionTypes a slice of valid aggregation function types for this collection field
	AggregationFunctionTypes []AggregationFunctionType `json:"aggregationFunctionTypes,omitempty"`
}

type CollectionGroupBy struct {
	Field CollectionFieldName `json:"field"`

	// Nested A slice of nested CollectionGroupBy
	Nested []CollectionGroupBy `json:"nested,omitempty"`
}
