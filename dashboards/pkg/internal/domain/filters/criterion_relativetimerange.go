package filters

import (
	"fmt"
	"time"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
)

type CriterionRelativeTimeRange struct {
	gte time.Duration
	lte time.Duration

	field  collections.CollectionField
	negate bool
}

var _ Criterion = (*CriterionRelativeTimeRange)(nil)

func NewRelativeTimeRange(field collections.CollectionField, gteDuration, lteDuration time.Duration, negate bool) (Criterion, error) {
	if gteDuration < 0 || lteDuration < 0 ||
		(lteDuration > gteDuration) ||
		(gteDuration == 0 && lteDuration == 0) {
		return nil, fmt.Errorf("invalid relativeTimeRange duration")
	}

	return &CriterionRelativeTimeRange{
		gte:    gteDuration,
		lte:    lteDuration,
		field:  field,
		negate: negate,
	}, nil
}

func (c *CriterionRelativeTimeRange) Negate() bool {
	return c.negate
}

func (c *CriterionRelativeTimeRange) Gte() time.Duration {
	return c.gte
}

func (c *CriterionRelativeTimeRange) Lte() time.Duration {
	return c.lte
}

func (c *CriterionRelativeTimeRange) Field() collections.CollectionField {
	return c.field
}
