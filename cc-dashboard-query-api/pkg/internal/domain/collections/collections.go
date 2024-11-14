package collections

import "github.com/tigera/tds-apiserver/lib/slices"

type FieldName string
type FieldType string
type CollectionName string

const (
	CollectionNameL7    = CollectionName("l7")
	CollectionNameDNS   = CollectionName("dns")
	CollectionNameFlows = CollectionName("flows")

	FieldTypeIP     = FieldType("ip")
	FieldTypeText   = FieldType("text")
	FieldTypeDate   = FieldType("date")
	FieldTypeNumber = FieldType("number")

	FieldTypeQName      = FieldType("qname")
	FieldTypeRRSetsData = FieldType("rrsets.data")
	FieldTypeRRSetsName = FieldType("rrsets.name")
)

// Collection A document collection
type Collection struct {
	name                 CollectionName
	fields               []CollectionField
	defaultTimeFieldName FieldType
}

type CollectionField struct {
	// Type The collection field internal type
	fieldType FieldType

	// displayFieldType The collection field public type
	displayFieldType FieldType

	// Name The collection field name
	fieldName FieldName
}

var allCollections = []Collection{collectionDNS, collectionFlows, collectionL7}

func Collections() []Collection {
	return slices.Clone(allCollections)
}

func (c Collection) Name() CollectionName {
	return c.name
}

func (c Collection) Fields() []CollectionField {
	return slices.Clone(c.fields)
}

func (c Collection) DefaultTimeFieldName() FieldType {
	return c.defaultTimeFieldName
}

func (c Collection) Field(fieldName FieldName) (CollectionField, bool) {
	return slices.Find(c.fields, func(field CollectionField) bool {
		return field.fieldName == fieldName
	})
}

func (t FieldType) Is(fieldType FieldType) bool {
	return t == fieldType
}

func (cf CollectionField) Name() FieldName {
	return cf.fieldName
}

func (cf CollectionField) Type() FieldType {
	return cf.fieldType
}

func (cf CollectionField) DisplayType() FieldType {
	if cf.displayFieldType != "" {
		return cf.displayFieldType
	}
	return cf.fieldType
}
