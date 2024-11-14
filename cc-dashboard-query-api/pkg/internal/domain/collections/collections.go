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
	FieldTypeEnum   = FieldType("enum")
	FieldTypeNumber = FieldType("number")

	FieldTypeQName      = FieldType("qname")
	FieldTypeRRSetsData = FieldType("rrsets.data")
	FieldTypeRRSetsName = FieldType("rrsets.name")

	FieldNamePolicyType = FieldName("policy.type")

	FieldPolicyStaged   = "staged"
	FieldPolicyEnforced = "enforced"
)

// Collection A document collection
type Collection struct {
	name                 CollectionName
	fields               []CollectionField
	defaultTimeFieldName FieldType
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
		return field.Name() == fieldName
	})
}

func (t FieldType) Is(fieldType FieldType) bool {
	return t == fieldType
}
