package collections

type GroupBy interface {
	Field() FieldName
	Nested() []GroupBy
}
