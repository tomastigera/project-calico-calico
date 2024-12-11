package linseed

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"time"

	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/collections"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/domain/filters"
	"github.com/tigera/tds-apiserver/lib/slices"
	"github.com/tigera/tds-apiserver/pkg/httpreply"
)

type queryParams struct {
	linseedQueryParams     lsv1.QueryParams
	linseedQuerySortParams lsv1.QuerySortParams

	selector        string
	domainMatches   map[lsv1.DomainMatchType][]string
	policyMatches   []lsv1.PolicyMatch
	requestedPeriod time.Duration
}

func newQueryParams(maxDocuments int) *queryParams {
	return &queryParams{
		linseedQueryParams: lsv1.QueryParams{MaxPageSize: maxDocuments},
		domainMatches: map[lsv1.DomainMatchType][]string{
			lsv1.DomainMatchQname:  nil,
			lsv1.DomainMatchRRSet:  nil,
			lsv1.DomainMatchRRData: nil,
		},
		linseedQuerySortParams: lsv1.QuerySortParams{
			Sort: []lsv1.SearchRequestSortBy{
				{Field: "@timestamp", Descending: true},
			},
		},
	}
}

func (p *queryParams) setCriteria(criteria filters.Criteria, now time.Time) error {
	selectors, err := p.getSelectors(criteria, now)
	if err != nil {
		return err
	}

	p.selector = strings.Join(selectors, " AND ")
	return nil
}

func (p *queryParams) getSelectors(criteria filters.Criteria, now time.Time) ([]string, error) {
	var selectors []string
	for _, criterion := range criteria {
		sel, err := p.getSelector(criterion, now)
		if err != nil {
			return nil, err
		}
		if sel != "" {
			selectors = append(selectors, sel)
		}
	}
	return selectors, nil
}

func (p *queryParams) getSelector(criterion filters.Criterion, now time.Time) (string, error) {
	switch c := criterion.(type) {
	case *filters.CriterionRelativeTimeRange:
		if c.Negate() {
			return "", fmt.Errorf("negated relativeTimeRange criterion is not supported")
		}

		p.setTimeRange(now, now.Add(-c.Gte()), now.Add(-c.Lte()), c.Gte()-c.Lte(), c.Field())
		return "", nil
	case *filters.CriterionDateRange:
		if c.Negate() {
			return "", fmt.Errorf("negated dateRange criterion is not supported")
		}

		p.setTimeRange(now, c.Gte(), c.Lte(), c.Lte().Sub(c.Gte()), c.Field())
		return "", nil
	case *filters.CriterionEquals:
		// handle linseed client special params
		switch c.Field().Type() {
		case collections.FieldTypeQName:
			if domain, ok := c.Value().(string); ok {
				p.domainMatches[lsv1.DomainMatchQname] = append(p.domainMatches[lsv1.DomainMatchQname], domain)
			}
			return "", nil
		case collections.FieldTypeRRSetsName:
			if domain, ok := c.Value().(string); ok {
				p.domainMatches[lsv1.DomainMatchRRSet] = append(p.domainMatches[lsv1.DomainMatchRRSet], domain)
			}
			return "", nil
		case collections.FieldTypeRRSetsData:
			if domain, ok := c.Value().(string); ok {
				p.domainMatches[lsv1.DomainMatchRRData] = append(p.domainMatches[lsv1.DomainMatchRRData], domain)
			}
			return "", nil
		case collections.FieldTypeEnum:
			if c.Field().Name() == collections.FieldNamePolicyType {
				collectionFieldEnum, ok := c.Field().(collections.CollectionFieldEnum)
				if !ok {
					return "", fmt.Errorf("incorrect collection field type '%s' for field '%s'", c.Field().Type(), c.Field().Name())
				}

				value, ok := c.Value().(string)
				if !ok || !slices.Contains(collectionFieldEnum.Values(), value) {
					return "", fmt.Errorf("invalid collection field '%s' value: '%v'", c.Field().Name(), c.Value())
				}

				if (value == collections.FieldPolicyStaged && !c.Negate()) ||
					(value != collections.FieldPolicyStaged && c.Negate()) {
					p.policyMatches = append(p.policyMatches, lsv1.PolicyMatch{Staged: true})
				}
				return "", nil
			}
			return "", fmt.Errorf("unknown collection enum field '%s'", c.Field().Name())
		}
		return selectorEquals(c)
	case *filters.CriterionOr:
		selectors, err := p.getSelectors(c.SubCriteria(), now)
		if err != nil {
			return "", err
		}

		prefix := ""
		if c.Negate() {
			prefix = "NOT "
		}

		return prefix + "( " + strings.Join(selectors, " OR ") + " )", nil
	case *filters.CriterionRange:
		field := c.Field()
		if c.Negate() {
			return fmt.Sprintf(`%s < %d AND %s > %d`, field.Name(), c.Gte(), field.Name(), c.Lte()), nil
		}
		return fmt.Sprintf(`%s >= %d AND %s <= %d`, field.Name(), c.Gte(), field.Name(), c.Lte()), nil
	case *filters.CriterionExists:
		// This selector does not match ES' exists exactly. TODO: Implement a linseed exists selector
		field := c.Field()
		if c.Negate() {
			return fmt.Sprintf(`%s NOTIN {"*"}`, field.Name()), nil
		} else {
			return fmt.Sprintf(`%s IN {"*"}`, field.Name()), nil
		}
	case *filters.CriterionIn:
		var selectors []string
		for _, value := range c.Values() {
			// TODO: this is only handling string values for now. If it will handle any, refactor selectorEquals
			selector, err := selectorEqualsString(c, c.Field().Name(), value)
			if err != nil {
				return "", err
			}
			selectors = append(selectors, selector)
		}

		if c.Negate() {
			return "( " + strings.Join(selectors, " AND ") + " )", nil
		}
		return "( " + strings.Join(selectors, " OR ") + " )", nil
	case *filters.CriterionIPRange:
		from, err := escapeSelectorValue(c.From())
		if err != nil {
			return "", err
		}

		to, err := escapeSelectorValue(c.To())
		if err != nil {
			return "", err
		}

		field := c.Field()
		if c.Negate() {
			return fmt.Sprintf(`%s < %s AND %s > %s`, field.Name(), from, field.Name(), to), nil
		}
		return fmt.Sprintf(`%s >= %s AND %s <= %s`, field.Name(), from, field.Name(), to), nil
	case *filters.CriterionStartsWith:
		value := strings.ReplaceAll(strings.ReplaceAll(c.Value(), `*`, `\*`), `?`, `\?`)
		return selectorWildcard(c, c.Field().Name(), value+"*")
	case *filters.CriterionWildcard:
		return selectorWildcard(c, c.Field().Name(), c.Pattern())
	}

	return "", fmt.Errorf("invalid criterion %T", criterion)
}

func (p *queryParams) setTimeRange(now, from, to time.Time, requestPeriod time.Duration, field collections.CollectionField) {
	var timeField lmav1.TimeField

	if field != nil {
		// Linseed only support lmav1.FieldDefault and lmav1.FieldGeneratedTime
		// See https://tigera.atlassian.net/browse/TSLA-8329?focusedCommentId=75852
		// See https://tigera.atlassian.net/browse/TSLA-8376

		if lmav1.TimeField(field.Name()) == lmav1.FieldGeneratedTime || lmav1.TimeField(field.Name()) == lmav1.FieldDefault {
			timeField = lmav1.TimeField(field.Name())
		}
	}

	p.requestedPeriod = requestPeriod
	p.linseedQueryParams.SetTimeRange(&lmav1.TimeRange{
		From:  from,
		To:    to,
		Now:   &now,
		Field: timeField,
	})
}

func selectorEquals(c *filters.CriterionEquals) (string, error) {
	if c.Field().Type().Is(collections.FieldTypeNumber) {
		criterionValue := c.Value()
		if valueString, ok := criterionValue.(string); ok {
			if valueInt, err := strconv.ParseInt(valueString, 10, 64); err == nil {
				criterionValue = valueInt
			} else if valueFloat, err := strconv.ParseFloat(valueString, 64); err == nil {
				criterionValue = valueFloat
			}
		}
		value := reflect.ValueOf(criterionValue)

		if value.CanInt() {
			v := value.Int()
			if c.Negate() {
				return fmt.Sprintf(`%s != %d`, c.Field().Name(), v), nil
			}
			return fmt.Sprintf(`%s = %d`, c.Field().Name(), v), nil
		} else if value.CanFloat() {
			if v := value.Float(); v > float64(math.MaxInt) || v < float64(math.MinInt) {
				return "", httpreply.ToBadRequest(fmt.Sprintf(`invalid equals criterion value "%v" `, c.Value()))
			}
			v := int64(value.Float()) // TODO: investigate if we need to support float64 querying with getSelectorFloat64
			/*
				if c.Negate() {
					return fmt.Sprintf(`%s != %f`, c.Field().Name(), v), nil
				}
				return fmt.Sprintf(`%s = %f`, c.Field().Name(), v), nil
			*/
			if c.Negate() {
				return fmt.Sprintf(`%s != %d`, c.Field().Name(), v), nil
			}
			return fmt.Sprintf(`%s = %d`, c.Field().Name(), v), nil
		}
		return "", httpreply.ToBadRequest(fmt.Sprintf("equals criterion value is not a number: %v %T", c.Value(), c.Value()))
	}

	if valueString, ok := c.Value().(string); ok {
		return selectorEqualsString(c, c.Field().Name(), valueString)
	}

	return "", fmt.Errorf("equals criterion value '%v' is not a string", c.Value())
}

func selectorEqualsString(c filters.Criterion, fieldName collections.FieldName, value string) (string, error) {
	value, err := escapeSelectorValue(value)
	if err != nil {
		return "", err
	}

	if c.Negate() {
		return fmt.Sprintf(`%s != %s`, fieldName, value), nil
	}
	return fmt.Sprintf(`%s = %s`, fieldName, value), nil
}

func selectorWildcard(c filters.Criterion, fieldName collections.FieldName, pattern string) (string, error) {
	value, err := escapeSelectorValue(pattern)
	if err != nil {
		return "", err
	}

	if c.Negate() {
		return fmt.Sprintf(`%s NOTIN {%s}`, fieldName, value), nil
	}
	return fmt.Sprintf(`%s IN {%s}`, fieldName, value), nil
}

func escapeSelectorValue(value string) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
