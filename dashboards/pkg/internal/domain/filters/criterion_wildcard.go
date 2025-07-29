package filters

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionWildcard struct {
	field   collections.CollectionField
	pattern string

	negate bool
}

var _ Criterion = (*CriterionWildcard)(nil)

func NewWildcard(field collections.CollectionField, pattern string, negate bool) Criterion {
	return &CriterionWildcard{
		field:   field,
		pattern: pattern,
		negate:  negate,
	}
}

func (c *CriterionWildcard) Negate() bool {
	return c.negate
}

func (c *CriterionWildcard) Field() collections.CollectionField {
	return c.field
}

func (c *CriterionWildcard) Pattern() string {
	return c.pattern
}
