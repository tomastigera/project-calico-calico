package filters

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionRange struct {
	field collections.CollectionField
	gte   int64
	lte   int64

	negate bool
}

var _ Criterion = (*CriterionRange)(nil)

func NewRange(field collections.CollectionField, gte, lte int64, negate bool) Criterion {
	return &CriterionRange{
		field: field,
		gte:   gte,
		lte:   lte,

		negate: negate,
	}
}

func (c *CriterionRange) Negate() bool {
	return c.negate
}

func (c *CriterionRange) Field() collections.CollectionField {
	return c.field
}

func (c *CriterionRange) Gte() int64 {
	return c.gte
}

func (c *CriterionRange) Lte() int64 {
	return c.lte
}
