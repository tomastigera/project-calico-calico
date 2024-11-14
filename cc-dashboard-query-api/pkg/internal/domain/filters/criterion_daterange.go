package filters

import (
	"time"
)

type CriterionDateRange struct {
	gte time.Time
	lte time.Time

	negate bool
}

var _ Criterion = (*CriterionDateRange)(nil)

func NewDateRange(gte, lte time.Time, negate bool) Criterion {
	return &CriterionDateRange{
		gte: gte,
		lte: lte,

		negate: negate,
	}
}

func (c *CriterionDateRange) Negate() bool {
	return c.negate
}

func (c *CriterionDateRange) Gte() time.Time {
	return c.gte
}

func (c *CriterionDateRange) Lte() time.Time {
	return c.lte
}
