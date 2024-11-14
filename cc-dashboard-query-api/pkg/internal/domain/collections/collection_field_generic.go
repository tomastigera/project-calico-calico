package collections

type collectionFieldGeneric struct {
	// Type The collection field internal type
	fieldType FieldType

	// displayFieldType The collection field public type
	displayFieldType FieldType

	// Name The collection field name
	fieldName FieldName
}

func (c collectionFieldGeneric) Name() FieldName {
	return c.fieldName
}

func (c collectionFieldGeneric) Type() FieldType {
	return c.fieldType
}

func (c collectionFieldGeneric) DisplayType() FieldType {
	if c.displayFieldType != "" {
		return c.displayFieldType
	}
	return c.fieldType
}
