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

func NewRelativeTimeRange(field collections.CollectionField, gte, lte string, negate bool) (Criterion, error) {
	var err error
	var gteDuration, lteDuration time.Duration

	if gte != "" {
		if gteDuration, err = time.ParseDuration(gte); err != nil {
			return nil, fmt.Errorf("failed to parse relativeTimeRange gte field: %v", err)
		}
	}

	if lte != "" {
		if lteDuration, err = time.ParseDuration(lte); err != nil {
			return nil, fmt.Errorf("failed to parse relativeTimeRange lte field: %v", err)
		}
	}

	if gteDuration == 0 && lteDuration == 0 {
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
