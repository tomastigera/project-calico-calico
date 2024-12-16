package collections

type CollectionField interface {
	Name() FieldName
	Type() FieldType
	Internal() bool
	DisplayType() FieldType
}
