package collections

type CollectionField interface {
	Name() FieldName
	Type() FieldType
	DisplayType() FieldType
}
