package client

type CollectionsResponse []Collection

type CollectionName string
type CollectionFieldType string
type CollectionFieldName string

// Collection A document collection
type Collection struct {
	Name                 CollectionName      `json:"name"`
	Fields               []CollectionField   `json:"fields"`
	GroupBys             []CollectionGroupBy `json:"groupBys"`
	DefaultTimeFieldName CollectionFieldName `json:"defaultTimeFieldName"`
}

type CollectionField struct {
	Type         CollectionFieldType `json:"type"`
	Name         CollectionFieldName `json:"name"`
	Values       []string            `json:"values,omitempty"`
	DefaultValue string              `json:"defaultValue,omitempty"`

	// FilterDisabled disables the use of this particular field in filters if set to true
	FilterDisabled bool `json:"filterDisabled,omitempty"`
}

type CollectionGroupBy struct {
	Field CollectionFieldName `json:"field"`

	// Nested A slice of nested CollectionGroupBy
	// TODO: set type to []CollectionGroupBy once tds-apiserver/pkg/http/handleradapters/openapi.go gets
	// fixed to not panic with a slice field of the same type as the parent struct
	Nested []any `json:"nested,omitempty"`
}
