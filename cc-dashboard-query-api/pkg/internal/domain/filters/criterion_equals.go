package filters

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionEquals struct {
	field collections.CollectionField
	value any

	negate bool
}

var _ Criterion = (*CriterionEquals)(nil)

func NewEquals(field collections.CollectionField, value any, negate bool) Criterion {
	return &CriterionEquals{
		field:  field,
		value:  value,
		negate: negate,
	}
}

func (c *CriterionEquals) Negate() bool {
	return c.negate
}

func (c *CriterionEquals) Field() collections.CollectionField {
	return c.field
}

func (c *CriterionEquals) Value() any {
	return c.value
}
