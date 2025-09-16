package collections

import "github.com/tigera/tds-apiserver/lib/slices"

type FieldName string
type FieldType string
type CollectionName string

const (
	CollectionNameL7    = CollectionName("l7")
	CollectionNameDNS   = CollectionName("dns")
	CollectionNameFlows = CollectionName("flows")
	CollectionNameWAF   = CollectionName("waf")

	FieldTypeIP   = FieldType("ip")
	FieldTypeText = FieldType("text")
	// FieldTypeTextExact restricts text fields to the EQUALS and IN filter operators
	FieldTypeTextExact = FieldType("text-exact")
	FieldTypeDate      = FieldType("date")
	FieldTypeEnum      = FieldType("enum")
	FieldTypeNumber    = FieldType("number")

	FieldTypeQName       = FieldType("qname")
	FieldTypeDestDomains = FieldType("dest_domains")
	FieldTypeLabels      = FieldType("labels")

	FieldNamePolicyType = FieldName("policy.type")

	FieldPolicyStaged   = "staged"
	FieldPolicyEnforced = "enforced"
)

// Collection A document collection
type Collection struct {
	name                 CollectionName
	fields               []CollectionField
	groupBys             []GroupBy
	defaultTimeFieldName FieldType
}

var allCollections = []Collection{collectionDNS, collectionFlows, collectionL7, collectionWAF}

func Collections() []Collection {
	return slices.Clone(allCollections)
}

func (c Collection) Name() CollectionName {
	return c.name
}

func (c Collection) Fields() []CollectionField {
	return slices.Clone(c.fields)
}

func (c Collection) GroupBys() []GroupBy {
	return slices.Clone(c.groupBys)
}

func (c Collection) DefaultTimeFieldName() FieldType {
	return c.defaultTimeFieldName
}

func (c Collection) Field(fieldName FieldName) (CollectionField, bool) {
	return slices.Find(c.fields, func(field CollectionField) bool {
		return field.Name() == fieldName
	})
}

func (c Collection) LmaResourceName() string {
	// Note: this statement requires c.name to match the lma.tigera.io resourceNames (it currently does)
	return string(c.name)
}

func (t FieldType) Is(fieldType FieldType) bool {
	return t == fieldType
}
