// Copyright (c) 2026 Tigera, Inc. All rights reserved.
package l3

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/olivere/elastic/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/api"
)

func TestFlowLogs_Aggregate_PoliciesTransformation(t *testing.T) {
	// 1. Definition of the raw request body with a "nested" policies aggregation.
	// We wrap it in a parent bucket because the transformer currently looks for "policies"
	// as a sub-aggregation.
	reqBody := `{
		"aggregations": {
			"wrapper": {
				"filter": { "match_all": {} },
				"aggregations": {
					"policies": {
						"nested": { "path": "policies" },
						"aggregations": {
							"by_policy": { "terms": { "field": "policies.all_policies" } }
						}
					}
				}
			}
		}
	}`

	// 2. Setup mocks
	mockFlowBackend := &api.MockFlowBackend{}
	mockLogBackend := &api.MockFlowLogBackend{}
	flowsHandler := New(mockFlowBackend, mockLogBackend)

	// 3. Define the expectation.
	// The generic handler should have transformed the aggregation BEFORE calling the backend.
	mockLogBackend.On("Aggregations",
		mock.Anything,
		mock.AnythingOfType("api.ClusterInfo"),
		mock.MatchedBy(func(params *v1.FlowLogAggregationParams) bool {
			// Convert the received Aggregations map back to string/json to inspect it easily
			wrapperRaw, ok := params.Aggregations["wrapper"]
			if !ok {
				t.Logf("Expected wrapper aggregation to be present")
				return false
			}

			var wrapperMap map[string]interface{}
			if err := json.Unmarshal(wrapperRaw, &wrapperMap); err != nil {
				t.Logf("Failed to unmarshal wrapper aggregation: %v", err)
				return false
			}

			// Helper to look up nested keys in map[string]interface{}
			getNested := func(m map[string]interface{}, keys ...string) (interface{}, bool) {
				var current interface{} = m
				for _, key := range keys {
					currentMap, ok := current.(map[string]interface{})
					if !ok {
						return nil, false
					}
					current, ok = currentMap[key]
					if !ok {
						return nil, false
					}
				}
				return current, true
			}

			// 1. Verify 'policies' aggregation exists inside wrapper
			// Note: different ES clients/versions might use "aggs" or "aggregations"
			policies, ok := getNested(wrapperMap, "aggregations", "policies")
			if !ok {
				policies, ok = getNested(wrapperMap, "aggs", "policies")
			}
			if !ok {
				t.Logf("Expected nested 'policies' aggregation not found")
				return false
			}
			policiesMap, ok := policies.(map[string]interface{})
			if !ok {
				t.Logf("Expected 'policies' aggregation to be an object, got: %T", policies)
				return false
			}

			// 2. Verify 'policies' contains 'filter' and DOES NOT contain 'nested'
			if _, hasNested := policiesMap["nested"]; hasNested {
				t.Logf("Expected 'policies' aggregation to not have 'nested' field")
				return false
			}
			if _, hasFilter := policiesMap["filter"]; !hasFilter {
				t.Logf("Expected 'policies' aggregation to have 'filter' field")
				return false
			}

			// 3. Verify 'by_policy' aggregation has correct field replacement in terms
			// Path: policies -> aggregations -> by_policy -> terms -> field
			termField, ok := getNested(policiesMap, "aggregations", "by_policy", "terms", "field")
			if !ok {
				termField, ok = getNested(policiesMap, "aggs", "by_policy", "terms", "field")
			}

			if !ok {
				t.Logf("Expected 'by_policy' terms aggregation field not found")
				return false
			}

			if termFieldStr, ok := termField.(string); !ok || termFieldStr != "policies.enforced_policies" {
				t.Logf("Expected field to be 'policies.enforced_policies', got: %v", termField)
				return false
			}

			return true
		}),
	).Return(&elastic.Aggregations{}, nil) // Return empty result

	// 4. Send request
	rec := httptest.NewRecorder()
	req, err := http.NewRequest("POST", AggsPath, bytes.NewBufferString(reqBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// The handler method is logs.Aggregate()
	flowsHandler.logs.Aggregate().ServeHTTP(rec, req)

	// 5. Verify
	assert.Equal(t, http.StatusOK, rec.Code)
	mockLogBackend.AssertExpectations(t)
}
