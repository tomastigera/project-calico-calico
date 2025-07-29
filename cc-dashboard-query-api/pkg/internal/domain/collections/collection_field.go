package collections

type CollectionField interface {
	Name() FieldName
	Type() FieldType
	Internal() bool
	FilterDisabled() bool
	DisplayType() FieldType
	SupportsExists() bool
	AggregationFunctionTypes() []AggregationFunctionType
}
