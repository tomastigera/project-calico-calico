package linseed

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/collections"
	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/filters"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

var (
	reMatchLabel     = regexp.MustCompile(`^[^=]+=[^=]+$`)
	reEnclosedQuotes = regexp.MustCompile(`^"(.*?)"$`)
)

type queryParams struct {
	linseedQueryParams        lsv1.QueryParams
	linseedQuerySortParams    lsv1.QuerySortParams
	linseedLogSelectionParams lsv1.LogSelectionParams

	domainMatches   map[lsv1.DomainMatchType][]string
	requestedPeriod time.Duration

	enforcedPolicyMatches []lsv1.PolicyMatch
	pendingPolicyMatches  []lsv1.PolicyMatch
}

func newQueryParams(maxDocuments, pageNum int, sortFieldName string, clusterIDs []string, permissions []v3.AuthorizedResourceVerbs) (*queryParams, error) {
	params := &queryParams{
		linseedQueryParams: lsv1.QueryParams{
			MaxPageSize: maxDocuments,
			Clusters:    clusterIDs,
			AllClusters: len(clusterIDs) == 0,
			AfterKey: map[string]any{
				"startFrom": pageNum * maxDocuments,
			},
		},
		domainMatches: map[lsv1.DomainMatchType][]string{
			lsv1.DomainMatchQname:  nil,
			lsv1.DomainMatchRRSet:  nil,
			lsv1.DomainMatchRRData: nil,
		},
		linseedQuerySortParams: lsv1.QuerySortParams{
			Sort: []lsv1.SearchRequestSortBy{
				{Field: sortFieldName, Descending: true},
			},
		},
		linseedLogSelectionParams: lsv1.LogSelectionParams{
			Permissions: permissions,
		},
	}

	return params, nil
}

func (p *queryParams) setCriteria(criteria filters.Criteria, now time.Time) error {
	// Extract policy type filters first. They populate separate PolicyMatch fields on the linseed
	// request rather than selector strings, so they must be handled at the top level — they cannot
	// be composed inside OR expressions.
	remaining, err := p.extractPolicyTypeMatches(criteria)
	if err != nil {
		return err
	}

	selectors, err := p.getSelectors(remaining, now)
	if err != nil {
		return err
	}

	p.linseedLogSelectionParams.Selector = strings.Join(selectors, " AND ")
	return nil
}

// extractPolicyTypeMatches removes policy type criteria from the top-level list, populates the
// pendingPolicyMatches/enforcedPolicyMatches fields, and returns the remaining criteria. Policy type
// values in CriterionIn are split out; if the CriterionIn contains non-policy-type values too,
// it is kept (with only those values) in the returned criteria.
func (p *queryParams) extractPolicyTypeMatches(criteria filters.Criteria) (filters.Criteria, error) {
	var remaining filters.Criteria
	for _, criterion := range criteria {
		switch c := criterion.(type) {
		case *filters.CriterionEquals:
			if c.Field().Name() == collections.FieldNamePolicyType {
				if err := p.addPolicyTypeMatch(c.Value().(string), c.Negate()); err != nil {
					return nil, err
				}
				continue
			}
		case *filters.CriterionIn:
			if c.Field().Name() == collections.FieldNamePolicyType {
				for _, value := range c.Values() {
					if err := p.addPolicyTypeMatch(value, c.Negate()); err != nil {
						return nil, err
					}
				}
				continue
			}
		}
		remaining = append(remaining, criterion)
	}
	return remaining, nil
}

// addPolicyTypeMatch converts a policy type filter ("staged"/"enforced") into a linseed PolicyMatch
// and appends it to the appropriate match list. Negation inverts the semantics: "not staged" becomes
// an enforced match and vice versa.
func (p *queryParams) addPolicyTypeMatch(value string, negate bool) error {
	if negate {
		switch value {
		case collections.FieldPolicyStaged:
			p.enforcedPolicyMatches = append(p.enforcedPolicyMatches, lsv1.PolicyMatch{Staged: false})
			return nil
		case collections.FieldPolicyEnforced:
			p.pendingPolicyMatches = append(p.pendingPolicyMatches, lsv1.PolicyMatch{Staged: true})
			return nil
		}
	}

	switch value {
	case collections.FieldPolicyStaged:
		p.pendingPolicyMatches = append(p.pendingPolicyMatches, lsv1.PolicyMatch{Staged: true})
		return nil
	case collections.FieldPolicyEnforced:
		p.enforcedPolicyMatches = append(p.enforcedPolicyMatches, lsv1.PolicyMatch{Staged: false})
		return nil
	}

	return fmt.Errorf("invalid policy.type value: %s", value)
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

		errGTEGreaterThanLTE := fmt.Errorf("invalid value for dateRange: gte is greater than lte")

		gte := c.Gte()
		lte := c.Lte()
		if lte == nil {
			lte = &now
			errGTEGreaterThanLTE = fmt.Errorf("invalid value for dateRange gte")
		}

		if gte.After(*lte) {
			return "", errGTEGreaterThanLTE
		}

		p.setTimeRange(now, gte, *lte, lte.Sub(gte), c.Field())
		return "", nil
	case *filters.CriterionEquals:
		// handle linseed client special params
		switch c.Field().Type() {
		case collections.FieldTypeQName:
			if domain, ok := c.Value().(string); ok {
				p.domainMatches[lsv1.DomainMatchQname] = append(p.domainMatches[lsv1.DomainMatchQname], domain)
			}
			return "", nil
		case collections.FieldTypeEnum:
			collectionFieldEnum, ok := c.Field().(collections.CollectionFieldEnum)
			if !ok {
				return "", fmt.Errorf("incorrect collection field type '%s' for field '%s'", c.Field().Type(), c.Field().Name())
			}

			value, ok := c.Value().(string)
			if !ok || !slices.Contains(collectionFieldEnum.Values(), value) {
				return "", fmt.Errorf("invalid value for field '%s': %v", c.Field().Name(), c.Value())
			}

			if c.Field().Name() == collections.FieldNamePolicyType {
				return "", fmt.Errorf("policy.type filter is only supported at the top level")
			}
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
		gte := c.Gte()
		fieldName := escapeFieldName(c.Field().Name())

		selector := ""
		if gte != nil {
			selector += fmt.Sprintf(`%s >= %d`, fieldName, *gte)
		}
		if lte := c.Lte(); lte != nil {
			if gte != nil {
				selector += " AND "
			}
			selector += fmt.Sprintf(`%s <= %d`, fieldName, *lte)
		}

		if selector == "" {
			return "", fmt.Errorf("invalid range criterion for field '%s'", c.Field().Name())
		}

		if c.Negate() {
			return fmt.Sprintf(`NOT (%s)`, selector), nil
		}
		return selector, nil
	case *filters.CriterionExists:
		fieldName := escapeFieldName(c.Field().Name())

		// Unlike other fields, dest_domains requires matching null/non-existing-field instead of empty values since it
		// might not always be available in the elasticsearch log document.
		// Use the EMPTY operator to match dest_domains against null/non-existing-field values
		if c.Field().Type() == collections.FieldTypeDestDomains {
			if c.Negate() {
				// A negated "exists dest_domains" filter means dest_domains value must be empty
				return fmt.Sprintf(`%s EMPTY`, fieldName), nil
			}

			// An "exists dest_domains" filter means dest_domains value must not be empty
			return fmt.Sprintf(`NOT %s EMPTY`, fieldName), nil
		}

		if c.Negate() {
			return fmt.Sprintf(`%s NOTIN {"*"}`, fieldName), nil
		} else {
			return fmt.Sprintf(`%s IN {"*"}`, fieldName), nil
		}
	case *filters.CriterionIn:
		var selectors []string
		for _, value := range c.Values() {
			if c.Field().Name() == collections.FieldNamePolicyType {
				return "", fmt.Errorf("policy.type filter is only supported at the top level")
			}

			// TODO: this is only handling string values for now. If it will handle any, refactor selectorEquals
			selector, err := selectorEqualsString(c, c.Field().Name(), value)
			if err != nil {
				return "", err
			}
			selectors = append(selectors, selector)
		}

		if len(selectors) == 0 {
			return "", nil
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

		fieldName := escapeFieldName(c.Field().Name())
		if c.Negate() {
			return fmt.Sprintf(`%s < %s AND %s > %s`, fieldName, from, fieldName, to), nil
		}
		return fmt.Sprintf(`%s >= %s AND %s <= %s`, fieldName, from, fieldName, to), nil
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
		switch ltFieldName := lmav1.TimeField(field.Name()); ltFieldName {
		case lmav1.FieldGeneratedTime, lmav1.FieldStartTime, lmav1.FieldDefault:
			timeField = ltFieldName
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
			return selectorEqualsInt(c, value.Int())
		} else if value.CanFloat() {
			if v := value.Float(); v > float64(math.MaxInt) || v < float64(math.MinInt) {
				return "", fmt.Errorf(`invalid equals criterion value "%v" `, c.Value())
			}
			v := int64(value.Float()) // TODO: investigate if we need to support float64 querying with getSelectorFloat64
			/*
				if c.Negate() {
					return fmt.Sprintf(`%s != %f`, c.Field().Name(), v), nil
				}
				return fmt.Sprintf(`%s = %f`, c.Field().Name(), v), nil
			*/
			return selectorEqualsInt(c, v)
		}
		return "", fmt.Errorf("equals criterion value is not a number: %v (%T)", c.Value(), c.Value())
	} else if c.Field().Type().Is(collections.FieldTypeLabels) {
		if valueString, ok := c.Value().(string); ok {
			if !reMatchLabel.MatchString(valueString) {
				return "", fmt.Errorf(`invalid value for "%v": expected format is labelName=labelValue`, c.Field().Name())
			}
		}
	}

	if valueString, ok := c.Value().(string); ok {
		if m := reEnclosedQuotes.FindStringSubmatch(valueString); len(m) > 1 {
			valueString = m[1]
		}
		return selectorEqualsString(c, c.Field().Name(), valueString)
	}

	return "", fmt.Errorf("equals criterion value '%v' is not a string", c.Value())
}

func selectorEqualsInt(c *filters.CriterionEquals, value int64) (string, error) {
	if value < 0 {
		// Note: Linseed parser does not support negative numbers and returns
		// HTTP 500: Invalid selector (<field> = <negative-value>) in request: unexpected token \"-\" (expected <ident> | <string> | <int> | <float>)
		return "", fmt.Errorf(`invalid equals criterion value "%v"`, c.Value())
	}

	fieldName := escapeFieldName(c.Field().Name())

	if c.Negate() {
		return fmt.Sprintf(`%s != %d`, fieldName, value), nil
	}
	return fmt.Sprintf(`%s = %d`, fieldName, value), nil
}

func selectorEqualsString(c filters.Criterion, fieldName collections.FieldName, value string) (string, error) {
	value, err := escapeSelectorValue(value)
	if err != nil {
		return "", err
	}

	if c.Negate() {
		if strings.ContainsRune(string(fieldName), '.') {
			// Nested fields require the linseed es boolean query must_not to be set before the nested query to
			// correctly filter out logs, which can be achieved with a "NOT field = value" selector
			return fmt.Sprintf(`NOT %s = %s`, escapeFieldName(fieldName), value), nil
		}
		return fmt.Sprintf(`%s != %s`, escapeFieldName(fieldName), value), nil
	}
	return fmt.Sprintf(`%s = %s`, escapeFieldName(fieldName), value), nil
}

func selectorWildcard(c filters.Criterion, fieldName collections.FieldName, pattern string) (string, error) {
	value, err := escapeSelectorValue(pattern)
	if err != nil {
		return "", err
	}

	if c.Negate() {
		return fmt.Sprintf(`%s NOTIN {%s}`, escapeFieldName(fieldName), value), nil
	}
	return fmt.Sprintf(`%s IN {%s}`, escapeFieldName(fieldName), value), nil
}

func escapeSelectorValue(value string) (string, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func escapeFieldName(fieldName collections.FieldName) string {
	if strings.ContainsRune(string(fieldName), '.') {
		return fmt.Sprintf(`"%s"`, fieldName)
	}

	return string(fieldName)
}
