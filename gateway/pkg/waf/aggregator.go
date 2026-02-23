// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package waf

import (
	"fmt"
	"reflect"
	"strings"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// Aggregator aggregates WAF logs based on configurable must-keep fields.
// Fields not in must-keep are aggregated away using sentinel values ("-" for strings, 0 for ints).
type Aggregator struct {
	store          []*v1.WAFLog
	mustKeepFields []string
}

// validMustKeepFields defines which fields can be used for aggregation keys.
// Extend this map if you add more must-keep fields.
// TODO: Add geoip support
var validMustKeepFields = map[string]struct{}{
	"path":   {},
	"method": {},
	"rules":  {},
}

// NewAggregator creates a new Aggregator with the given must-keep fields.
// Returns an error if any field is not valid.
func NewAggregator(mustKeepFields []string) (*Aggregator, error) {
	for _, f := range mustKeepFields {
		if _, ok := validMustKeepFields[strings.ToLower(f)]; !ok {
			return nil, fmt.Errorf("unknown mustKeepField: %s", f)
		}
	}
	return &Aggregator{
		store:          []*v1.WAFLog{},
		mustKeepFields: mustKeepFields,
	}, nil
}

// EndAggregationPeriod returns the current aggregated logs and resets the store.
func (a *Aggregator) EndAggregationPeriod() []*v1.WAFLog {
	aggregatedLogs := a.store
	a.store = []*v1.WAFLog{}
	return aggregatedLogs
}

// AddLog adds a WAF log to the aggregator, aggregating with existing logs if possible.
func (a *Aggregator) AddLog(log *v1.WAFLog) {
	// Make sure log count is set to 1
	log.Count = 1

	if len(a.mustKeepFields) == 0 {
		a.store = append(a.store, log)
		return
	}
	for _, agg := range a.store {
		if a.match(agg, log) {
			a.aggregateFields(agg, log)
			return
		}
	}
	a.store = append(a.store, log)
}

// match returns true if the log matches the aggregated log on all must-keep fields.
func (a *Aggregator) match(agg *v1.WAFLog, log *v1.WAFLog) bool {
	for _, field := range a.mustKeepFields {
		switch strings.ToLower(field) {
		case "path":
			if agg.Path != log.Path {
				return false
			}
		case "method":
			if agg.Method != log.Method {
				return false
			}
		case "rules":
			if !equalRuleSets(agg.Rules, log.Rules) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// aggregateFields aggregates away non-must-keep fields if they differ.
// For Rules, merge unique rules by Id if not aggregating by rules.
// For any non-must-keep string field, if values differ, set to "-".
// For pointer-to-struct fields (e.g., Source/Destination), recursively aggregate their fields.
func (a *Aggregator) aggregateFields(agg *v1.WAFLog, log *v1.WAFLog) {
	// Increment count when aggregating
	agg.Count++

	// Special case for rules
	if !a.hasMustKeep("rules") {
		existing := make(map[string]struct{})
		for _, rule := range agg.Rules {
			existing[rule.Id] = struct{}{}
		}
		for _, rule := range log.Rules {
			if _, found := existing[rule.Id]; !found {
				agg.Rules = append(agg.Rules, rule)
				existing[rule.Id] = struct{}{}
			}
		}
	}

	aggVal := reflect.ValueOf(agg).Elem()
	logVal := reflect.ValueOf(log).Elem()
	typ := aggVal.Type()

	var aggregateField func(aggField, logField reflect.Value, field reflect.StructField, fieldName string)
	aggregateField = func(aggField, logField reflect.Value, field reflect.StructField, fieldName string) {
		// Special case for Count: skip aggregation, always sum in aggregateFields
		if fieldName == "count" {
			return
		}
		// Skip must-keep fields and Rules (already handled)
		if a.hasMustKeep(fieldName) || fieldName == "rules" {
			return
		}
		if !aggField.CanSet() {
			return
		}
		switch aggField.Kind() {
		case reflect.String:
			if aggField.String() != logField.String() {
				aggField.SetString("-")
			}
		case reflect.Int, reflect.Int32, reflect.Int64:
			if aggField.Int() != logField.Int() {
				aggField.SetInt(0)
			}
		case reflect.Pointer:
			if aggField.IsNil() && logField.IsNil() {
				return
			}
			if aggField.IsNil() || logField.IsNil() {
				// If one is nil and the other is not, set to default
				if aggField.Type().Elem().Kind() == reflect.Struct {
					newVal := reflect.New(aggField.Type().Elem())
					for j := 0; j < newVal.Elem().NumField(); j++ {
						switch newVal.Elem().Field(j).Kind() {
						case reflect.String:
							newVal.Elem().Field(j).SetString("-")
						case reflect.Int, reflect.Int32, reflect.Int64:
							newVal.Elem().Field(j).SetInt(0)
						}
					}
					aggField.Set(newVal)
				}
				return
			}
			// Both non-nil, recurse into struct fields
			elemAgg := aggField.Elem()
			elemLog := logField.Elem()
			for j := 0; j < elemAgg.NumField(); j++ {
				f := elemAgg.Type().Field(j)
				aggregateField(elemAgg.Field(j), elemLog.Field(j), f, strings.ToLower(f.Name))
			}
			// Add more types as needed
		}
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldName := strings.ToLower(field.Name)
		aggregateField(aggVal.Field(i), logVal.Field(i), field, fieldName)
	}
}

// hasMustKeep returns true if the field is in mustKeepFields.
func (a *Aggregator) hasMustKeep(field string) bool {
	for _, f := range a.mustKeepFields {
		if strings.ToLower(f) == field {
			return true
		}
	}
	return false
}

// equalRuleSets returns true if the two rule slices have the same set of rule Ids (order and content matters).
// The identical ordering is not an issue, as they will always be generated in the same order.
func equalRuleSets(a, b []v1.WAFRuleHit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Id != b[i].Id {
			return false
		}
	}
	return true
}
