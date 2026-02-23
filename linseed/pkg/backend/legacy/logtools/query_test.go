// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package logtools

import (
	"reflect"
	"testing"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

func TestNextStartFromAfterKey(t *testing.T) {
	const pageSize = 100
	const maxTotalHits = 10000

	tests := []struct {
		name          string
		params        v1.Params
		numHits       int
		prevStartFrom int
		totalHits     int64
		want          map[string]any
	}{
		{
			name:      "should return a starting point for the second page",
			params:    &v1.AuditLogParams{QueryParams: v1.QueryParams{MaxPageSize: pageSize}},
			numHits:   pageSize,
			totalHits: maxTotalHits,
			want:      map[string]any{"startFrom": pageSize},
		},
		{
			name:          "should return a starting point for the third page",
			params:        &v1.AuditLogParams{QueryParams: v1.QueryParams{MaxPageSize: pageSize}},
			numHits:       pageSize,
			prevStartFrom: pageSize,
			totalHits:     maxTotalHits,
			want:          map[string]any{"startFrom": 2 * pageSize},
		},

		{
			name:          "should NOT return a starting point for the last page when the query returns hits less than the page size",
			params:        &v1.AuditLogParams{QueryParams: v1.QueryParams{MaxPageSize: pageSize}},
			numHits:       3,
			prevStartFrom: maxTotalHits - pageSize,
			totalHits:     maxTotalHits,
		},
		{
			name:          "should NOT return a starting point for the last page when the query returns hits equal to the page size",
			params:        &v1.AuditLogParams{QueryParams: v1.QueryParams{MaxPageSize: pageSize}},
			numHits:       pageSize,
			prevStartFrom: maxTotalHits - pageSize,
			totalHits:     maxTotalHits,
		},
		{
			name:      "should NOT return a starting point if the entire request is satisfied in a single page that matches the total hits",
			params:    &v1.AuditLogParams{QueryParams: v1.QueryParams{MaxPageSize: maxTotalHits}},
			numHits:   maxTotalHits,
			totalHits: maxTotalHits,
		},
		{
			name:      "should NOT return a starting point if there are no hits",
			params:    &v1.AuditLogParams{QueryParams: v1.QueryParams{MaxPageSize: pageSize}},
			totalHits: maxTotalHits,
		},
		{
			name:          "should NOT return a starting point for the last page when starting from an arbitrary point in the page before last",
			params:        &v1.AuditLogParams{QueryParams: v1.QueryParams{MaxPageSize: pageSize}},
			numHits:       pageSize - 3,
			prevStartFrom: maxTotalHits - pageSize + 3,
			totalHits:     maxTotalHits,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NextStartFromAfterKey(tt.params, tt.numHits, tt.prevStartFrom, tt.totalHits); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NextStartFromAfterKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
