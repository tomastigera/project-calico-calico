package collections

type CollectionFieldEnum struct {
	fieldName    FieldName
	fieldValues  []string
	defaultValue string
}

func NewCollectionFieldEnum(fieldName FieldName, fieldValues []string, defaultValue string) CollectionFieldEnum {
	return CollectionFieldEnum{
		fieldName:    fieldName,
		fieldValues:  fieldValues,
		defaultValue: defaultValue,
	}
}

func (c CollectionFieldEnum) Name() FieldName {
	return c.fieldName
}

func (c CollectionFieldEnum) Type() FieldType {
	return FieldTypeEnum
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
