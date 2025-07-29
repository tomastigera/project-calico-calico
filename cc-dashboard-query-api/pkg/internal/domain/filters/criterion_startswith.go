package filters

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionStartsWith struct {
	field collections.CollectionField
	value string

	negate bool
}

var _ Criterion = (*CriterionStartsWith)(nil)

func NewStartsWith(field collections.CollectionField, value string, negate bool) Criterion {
	return &CriterionStartsWith{
		field:  field,
		value:  value,
		negate: negate,
	}
}

func (c *CriterionStartsWith) Negate() bool {
	return c.negate
}

func (c *CriterionStartsWith) Field() collections.CollectionField {
	return c.field
}

func (c *CriterionStartsWith) Value() string {
	return c.value
}
