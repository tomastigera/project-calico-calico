package filters

import (
	"fmt"
	"time"
)

type CriterionRelativeTimeRange struct {
	gte time.Duration
	lte time.Duration

	negate bool
}

var _ Criterion = (*CriterionRelativeTimeRange)(nil)

func NewRelativeTimeRange(gte, lte string, negate bool) (Criterion, error) {
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
