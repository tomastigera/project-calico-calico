package filters

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionIn struct {
	field  collections.CollectionField
	values []string

	negate bool
}

var _ Criterion = (*CriterionIn)(nil)

func NewIn(field collections.CollectionField, values []string, negate bool) Criterion {
	return &CriterionIn{
		field:  field,
		values: values,
		negate: negate,
	}
}

func (c *CriterionIn) Negate() bool {
	return c.negate
}

func (c *CriterionIn) Field() collections.CollectionField {
	return c.field
}

func (c *CriterionIn) Values() []string {
	return c.values
}
