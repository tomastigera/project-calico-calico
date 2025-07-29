package filters

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionExists struct {
	field collections.CollectionField

	negate bool
}

var _ Criterion = (*CriterionExists)(nil)

func NewExists(field collections.CollectionField, negate bool) Criterion {
	return &CriterionExists{
		field:  field,
		negate: negate,
	}
}

func (c *CriterionExists) Negate() bool {
	return c.negate
}

func (c *CriterionExists) Field() collections.CollectionField {
	return c.field
}
