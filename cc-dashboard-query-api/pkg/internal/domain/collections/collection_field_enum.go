package collections

type CollectionFieldEnum struct {
	fieldName                FieldName
	fieldValues              []string
	defaultValue             string
	internal                 bool
	filterDisabled           bool
	aggregationFunctionTypes []AggregationFunctionType
}

func (c CollectionFieldEnum) Name() FieldName {
	return c.fieldName
}

func (c CollectionFieldEnum) Type() FieldType {
	return FieldTypeEnum
}

func (c CollectionFieldEnum) Internal() bool {
	return c.internal
}

func (c CollectionFieldEnum) FilterDisabled() bool {
	return c.filterDisabled
}

func (c CollectionFieldEnum) DisplayType() FieldType {
	return c.Type()
}

func (c CollectionFieldEnum) Values() []string {
	return c.fieldValues
}

func (c CollectionFieldEnum) DefaultValue() string {
	return c.defaultValue
}

func (c CollectionFieldEnum) AggregationFunctionTypes() []AggregationFunctionType {
	return c.aggregationFunctionTypes
}
