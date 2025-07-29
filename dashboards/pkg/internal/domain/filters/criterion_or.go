package filters

type CriterionOr struct {
	criteria Criteria

	negate bool
}

var _ Criterion = (*CriterionOr)(nil)

func NewOr(criteria Criteria, negate bool) Criterion {
	return &CriterionOr{
		negate:   negate,
		criteria: criteria,
	}
}

func (c *CriterionOr) Negate() bool {
	return c.negate
}

func (c *CriterionOr) SubCriteria() Criteria {
	return c.criteria
}
