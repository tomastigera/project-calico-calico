// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package v3

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	validator "gopkg.in/go-playground/validator.v9"

	"github.com/projectcalico/calico/libcalico-go/lib/validator/v3/query"
)

func validateGlobalAlert(structLevel validator.StructLevel) {
	globalAlert := getGlobalAlert(structLevel)
	validateGlobalAlertSpec(structLevel, globalAlert.Name, globalAlert.Spec)
}

func validateGlobalAlertSpec(structLevel validator.StructLevel, globalAlertName string, globalAlertSpec api.GlobalAlertSpec) {
	validateGlobalAlertPeriod(structLevel, globalAlertSpec)
	validateGlobalAlertLookback(structLevel, globalAlertSpec)
	validateGlobalAlertDataSet(structLevel, globalAlertSpec)
	validateGlobalAlertQuery(structLevel, globalAlertSpec)
	validateGlobalAlertDescriptionAndSummary(structLevel, globalAlertSpec)
	validateGlobalAlertAggregateBy(structLevel, globalAlertSpec)
	validateGlobalAlertMetric(structLevel, globalAlertSpec)
}

func getGlobalAlert(structLevel validator.StructLevel) api.GlobalAlert {
	return structLevel.Current().Interface().(api.GlobalAlert)
}

func validateGlobalAlertDataSet(structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	if (len(s.Type) == 0 || s.Type == api.GlobalAlertTypeRuleBased) && len(s.DataSet) == 0 {
		structLevel.ReportError(
			reflect.ValueOf(s.DataSet),
			"DataSet",
			"",
			reason(fmt.Sprintf("empty DataSet for GlobalAlert of Type %s", api.GlobalAlertTypeRuleBased)),
			"",
		)
	}
}

func validateGlobalAlertPeriod(structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	if s.Period != nil && s.Period.Duration != 0 && s.Period.Duration < api.GlobalAlertMinPeriod {
		structLevel.ReportError(
			reflect.ValueOf(s.Period),
			"Period",
			"",
			reason(fmt.Sprintf("period %s < %s", s.Period, api.GlobalAlertMinPeriod)),
			"",
		)
	}
}

func validateGlobalAlertLookback(structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	if s.Lookback != nil && s.Lookback.Duration != 0 && s.Lookback.Duration < api.GlobalAlertMinLookback {
		structLevel.ReportError(
			reflect.ValueOf(s.Lookback),
			"Lookback",
			"",
			reason(fmt.Sprintf("lookback %s < %s", s.Period, api.GlobalAlertMinLookback)),
			"",
		)
	}
}

// substituteVariables finds variables in the query string and replace them with values from GlobalAlertSpec.Substitutions.
func substituteVariables(s api.GlobalAlertSpec) (string, error) {
	out := s.Query
	variables, err := extractVariablesFromTemplate(out)
	if err != nil {
		return out, err
	}

	if len(variables) > 0 {
		for _, variable := range variables {
			sub, err := findSubstitutionByVariableName(s, variable)
			if err != nil {
				return out, err
			}

			// Translate Substitution.Values into the set notation.
			patterns := []string{}
			for _, v := range sub.Values {
				if v != "" {
					patterns = append(patterns, strconv.Quote(v))
				}
			}
			if len(patterns) > 0 {
				out = strings.Replace(out, fmt.Sprintf("${%s}", variable), "{"+strings.Join(patterns, ",")+"}", 1)
			}
		}
	}
	return out, nil
}

// validateGlobalAlertQuery substitutes all variables in the query string and validates it by the query parser.
func validateGlobalAlertQuery(structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	if qs, err := substituteVariables(s); err != nil {
		structLevel.ReportError(
			reflect.ValueOf(s.Query),
			"Query",
			"",
			reason("invalid query: "+err.Error()),
			"",
		)
	} else if q, err := query.ParseQuery(qs); err != nil {
		structLevel.ReportError(
			reflect.ValueOf(s.Query),
			"Query",
			"",
			reason("invalid query: "+err.Error()),
			"",
		)
	} else {
		switch s.DataSet {
		case api.GlobalAlertDataSetAudit:
			if err := query.Validate(q, query.IsValidAuditAtom); err != nil {
				structLevel.ReportError(
					reflect.ValueOf(s.Query),
					"Query",
					"",
					reason("invalid query: "+err.Error()),
					"",
				)
			}
		case api.GlobalAlertDataSetDNS:
			if err := query.Validate(q, query.IsValidDNSAtom); err != nil {
				structLevel.ReportError(
					reflect.ValueOf(s.Query),
					"Query",
					"",
					reason("invalid query: "+err.Error()),
					"",
				)
			}
		case api.GlobalAlertDataSetFlows:
			if err := query.Validate(q, query.IsValidFlowsAtom); err != nil {
				structLevel.ReportError(
					reflect.ValueOf(s.Query),
					"Query",
					"",
					reason("invalid query: "+err.Error()),
					"",
				)
			}
		case api.GlobalAlertDataSetWAF:
			if err := query.Validate(q, query.IsValidWAFAtom); err != nil {
				structLevel.ReportError(
					reflect.ValueOf(s.Query),
					"Query",
					"",
					reason("invalid query: "+err.Error()),
					"",
				)
			}
		case api.GlobalAlertDataSetVulnerability:
			if err := query.Validate(q, query.IsValidVulnerabilityAtom); err != nil {
				structLevel.ReportError(
					reflect.ValueOf(s.Query),
					"Query",
					"",
					reason("invalid query: "+err.Error()),
					"",
				)
			}
		}
	}
}

// validateGlobalAlertDescriptionAndSummary validates that there are no unreferenced fields in the description and summary
func validateGlobalAlertDescriptionAndSummary(structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	validateGlobalAlertDescriptionOrSummaryContents(s.Description, "Description", structLevel, s)
	if s.Summary != "" {
		validateGlobalAlertDescriptionOrSummaryContents(s.Summary, "Summary", structLevel, s)
	}
}

func validateGlobalAlertDescriptionOrSummaryContents(description, fieldName string, structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	if variables, err := extractVariablesFromTemplate(description); err != nil {
		structLevel.ReportError(
			reflect.ValueOf(s.DataSet),
			fieldName,
			"",
			reason(fmt.Sprintf("invalid %s: %s: %s", strings.ToLower(fieldName), description, err)),
			"",
		)
	} else {
		for _, key := range variables {
			if key == "" {
				structLevel.ReportError(
					reflect.ValueOf(description),
					fieldName,
					"",
					reason("empty variable name"),
					"",
				)
				break
			}

			if key == s.Metric {
				continue
			}
			var found bool
			if slices.Contains(s.AggregateBy, key) {
				found = true
			}
			if !found {
				structLevel.ReportError(
					reflect.ValueOf(description),
					fieldName,
					"",
					reason(fmt.Sprintf("invalid %s: %s", strings.ToLower(fieldName), description)),
					"",
				)
			}
		}
	}
}

func validateGlobalAlertAggregateBy(structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	// We intentionally do not validate field or aggregation names. Fields do need to be numeric for most of the
	// metrics and aggregation keys do need to exist for them to make sense.
	if s.DataSet == api.GlobalAlertDataSetVulnerability {
		if len(s.AggregateBy) > 0 {
			structLevel.ReportError(
				reflect.ValueOf(s.AggregateBy),
				"AggregateBy",
				"",
				reason("vulnerability dataset doesn't support aggregateBy field"),
				"",
			)
		}
	}
}

func validateGlobalAlertMetric(structLevel validator.StructLevel, s api.GlobalAlertSpec) {
	switch s.Metric {
	case api.GlobalAlertMetricAvg, api.GlobalAlertMetricMax, api.GlobalAlertMetrixMin, api.GlobalAlertMetricSum:
		if s.Field == "" {
			structLevel.ReportError(
				reflect.ValueOf(s.Field),
				"Field",
				"",
				reason(fmt.Sprintf("metric %s requires a field", s.Metric)),
				"",
			)
		}
	case api.GlobalAlertMetricCount:
		if s.Field != "" {
			structLevel.ReportError(
				reflect.ValueOf(s.Field),
				"Field",
				"",
				reason(fmt.Sprintf("metric %s cannot be applied to a field", s.Metric)),
				"",
			)
		}
	case "":
		if s.Field != "" {
			structLevel.ReportError(
				reflect.ValueOf(s.Field),
				"Field",
				"",
				reason("field without metric is invalid"),
				"",
			)
		}
	default:
		structLevel.ReportError(
			reflect.ValueOf(s.Metric),
			"Metric",
			"",
			reason(fmt.Sprintf("invalid metric: %s", s.Metric)),
			"",
		)
	}

	if s.Metric != "" && s.Condition == "" {
		structLevel.ReportError(
			reflect.ValueOf(s.Metric),
			"Metric",
			"",
			reason(fmt.Sprintf("metric %s without condition", s.Metric)),
			"",
		)
	}
}

// extractVariablesFromTemplate extracts variables from a template string.
// Variables are defined by starting with a dollar sign and enclosed by curly braces.
func extractVariablesFromTemplate(s string) ([]string, error) {
	var res []string
	for s != "" {
		start := strings.Index(s, "${")
		if start < 0 {
			break
		}
		s = s[start+2:]
		end := strings.Index(s, "}")
		if end < 0 {
			return nil, errors.New("unterminated }")
		}
		res = append(res, s[:end])
		s = s[end+1:]
	}
	return res, nil
}

// findSubstitutionByVariableName finds the substitution from GlobalAlertSpec.Substitutions by the variable name.
// Only one substitution will be returned. If no substitution or more than one substitution is found,
// an error will be returned.
func findSubstitutionByVariableName(s api.GlobalAlertSpec, variable string) (*api.GlobalAlertSubstitution, error) {
	var substitution *api.GlobalAlertSubstitution
	for _, sub := range s.Substitutions {
		if strings.EqualFold(variable, sub.Name) {
			if substitution != nil {
				return nil, fmt.Errorf("found more than one substitution for variable %s", variable)
			} else {
				substitution = sub.DeepCopy()
			}
		}
	}

	if substitution != nil {
		return substitution, nil
	}
	return nil, fmt.Errorf("substition not found for variable %s", variable)
}
