package filters

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionIPRange struct {
	field collections.CollectionField
	from  string
	to    string

	negate bool
}

var _ Criterion = (*CriterionIPRange)(nil)

func NewIPRange(field collections.CollectionField, from, to string, negate bool) Criterion {
	return &CriterionIPRange{
		to:     to,
		from:   from,
		field:  field,
		negate: negate,
	}
}

func (c *CriterionIPRange) Negate() bool {
	return c.negate
}

func (c *CriterionIPRange) Field() collections.CollectionField {
	return c.field
}

func (c *CriterionIPRange) From() string {
	return c.from
}

func (c *CriterionIPRange) To() string {
	return c.to
}
