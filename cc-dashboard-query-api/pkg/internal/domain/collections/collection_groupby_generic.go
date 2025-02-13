package collections

type groupBy struct {
	field  FieldName
	nested []GroupBy
}

func (g groupBy) Field() FieldName { return g.field }

func (g groupBy) Nested() []GroupBy { return g.nested }
