package filters

import (
	"time"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionDateRange struct {
	gte time.Time
	lte *time.Time

	field  collections.CollectionField
	negate bool
}

var _ Criterion = (*CriterionDateRange)(nil)

func NewDateRange(field collections.CollectionField, gte time.Time, lte *time.Time, negate bool) Criterion {
	return &CriterionDateRange{
		gte:    gte,
		lte:    lte,
		field:  field,
		negate: negate,
	}
}

func (c *CriterionDateRange) Negate() bool {
	return c.negate
}

func (c *CriterionDateRange) Gte() time.Time {
	return c.gte
}

func (c *CriterionDateRange) Lte() *time.Time {
	return c.lte
}

func (c *CriterionDateRange) Field() collections.CollectionField {
	return c.field
}
