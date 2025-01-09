package collections

type collectionFieldGeneric struct {
	// Type The collection field internal type
	fieldType FieldType

	// displayFieldType The collection field public type
	displayFieldType FieldType

	// Name The collection field name
	fieldName FieldName

	// internal indicates a field is not returned in the collections endpoint response
	internal bool

	// filterDisabled indicate a field must not be used for filtering if set to true
	filterDisabled bool
}

func NewCollectionFieldGeneric(fieldName FieldName, fieldType FieldType, displayFieldType FieldType) CollectionField {
	return collectionFieldGeneric{
		fieldName:        fieldName,
		fieldType:        fieldType,
		displayFieldType: displayFieldType,
	}
}

func (c collectionFieldGeneric) Name() FieldName {
	return c.fieldName
}

func (c collectionFieldGeneric) Type() FieldType {
	return c.fieldType
}

func (c collectionFieldGeneric) Internal() bool {
	return c.internal
}

func (c collectionFieldGeneric) FilterDisabled() bool {
	return c.filterDisabled
}

func (c collectionFieldGeneric) DisplayType() FieldType {
	if c.displayFieldType != "" {
		return c.displayFieldType
	}
	return c.fieldType
}
