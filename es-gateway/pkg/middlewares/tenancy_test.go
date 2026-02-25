package middlewares_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/es-gateway/pkg/middlewares"
)

func TestKibanaTenancy_Enforce(t *testing.T) {
	const (
		tenantID                           = "anyTenant"
		sampleBooleanQueryWithFilterClause = `
{
  "query": { 
    "bool": { 
      "must": [
      ],
      "filter": [ 
        { "term":  { "message": "document" }}
      ]
    }
  }
}`
		sampleBooleanQueryWithMustClause = `
{
  "query": { 
    "bool": { 
      "must": [
        { "match": { "tenant":   "A"        }}
      ],
      "filter": [ 
      ]
    }
  }
}`

		sampleBooleanQueryWithMustNotClause = `
{
  "query": { 
    "bool": { 
      "must_not": [
        { "match": { "tenant":   "A"        }}
      ],
      "filter": [ 
      ]
    }
  }
}`
		sampleQueryStringQuery = `
{
  "query": {
    "query_string": {
      "query": "(A) OR (B)",
      "default_field": "tenant"
    }
  }
}`
		sampleFuzzyQuery = `
{
  "query": {
    "fuzzy": {
      "tenant.keyword": {
        "value": "A"
      }
    }
  }
}`
		sampleRegexpQuery = `
{
  "query": {
    "regexp": {
      "tenant.keyword": {
        "value": "(A|B)",
        "flags": "ALL",
        "case_insensitive": true
      }
    }
  }
}`
		samplePrefixQuery = `
{
  "query": {
    "prefix": {
      "tenant.keyword": {
        "value": "A"
      }
    }
  }
}`
		sampleWildcardQuery = `
{
  "query": {
    "wildcard": {
      "tenant.keyword": {
        "value": "A*"
      }
    }
  }
}`
		sampleRangeQuery = `
{
  "query": {
    "range": {
      "tenant.keyword": {
        "gte": 0
      }
    }
  }
}`
		sampleMatchAllQuery = `
{
  "query": {
    "match_all": {}
  }
}
`
		sampleBoostingWithAConstantScore = `
{
  "query": {
    "constant_score": {
      "filter": {
        "term": { "tenant.keyword": "A" }
      },
      "boost": 1.2
    }
  }
}`
		sampleScriptQuery = `{
  "query": {
    "bool": {
      "filter": {
        "script": {
          "script": "any"
        }
      }
    }
  }
}`
	)

	expectedTenantQuery := map[string]any{
		"term": map[string]any{
			"tenant.keyword": tenantID,
		},
	}

	tests := []struct {
		name       string
		url        string
		body       string
		wantStatus int
	}{
		{
			name: "Should enforce tenancy for a generic boolean query with a filter clause using POST",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-filter-context.html
			body:       sampleBooleanQueryWithFilterClause,
			wantStatus: http.StatusOK,
		},

		{
			name: "Should enforce tenancy for a generic boolean query with a must clause using POST",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-filter-context.html
			body:       sampleBooleanQueryWithMustClause,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for a generic boolean query with a must not clause using POST",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-filter-context.html
			body:       sampleBooleanQueryWithMustNotClause,
			wantStatus: http.StatusOK,
		},

		{
			name:       "Should deny any search request with an empty query field",
			url:        "/calico_anyData*/_async_search",
			body:       `{"query":{}}`,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "Should deny an empty async request",
			url:        "/calico_anyData*/_async_search",
			body:       `{}`,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "Should not process malformed requests",
			url:        "/calico_anyData*/_async_search",
			body:       `{#!#$!1}`,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "Should deny aggregations requests without a query field",
			url:        "/calico_anyData*/_async_search",
			body:       `{"agg":{}}`,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "Should enforce tenancy for a generic query string",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-query-string-query.html
			body:       sampleQueryStringQuery,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for a generic fuzzy string",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-fuzzy-query.html
			body:       sampleFuzzyQuery,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for a generic regex query",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-regexp-query.html
			body:       sampleRegexpQuery,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for a generic prefix query",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-regexp-query.html
			body:       samplePrefixQuery,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for a generic wildcard query",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-wildcard-query.html
			body:       sampleWildcardQuery,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for a generic range query",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-range-query.html#range-query-ex-request
			body:       sampleRangeQuery,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for a match all query",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-match-all-query.html
			body:       sampleMatchAllQuery,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for query using a constant score boost",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/compound-queries.html
			body:       sampleBoostingWithAConstantScore,
			wantStatus: http.StatusOK,
		},
		{
			name: "Should enforce tenancy for query using a script",
			url:  "/calico_anyData*/_async_search",
			// https://www.elastic.co/guide/en/elasticsearch/reference/7.17/query-dsl-script-query.html
			body:       sampleScriptQuery,
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := middlewares.NewKibanaTenancy(tenantID).Enforce()
			rec := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodPost, tt.url, bytes.NewBufferString(tt.body))
			require.NoError(t, err)

			var wantFilterClause map[string]any
			if tt.wantStatus == http.StatusOK {
				var initialQuery map[string]any
				err = json.Unmarshal([]byte(tt.body), &initialQuery)
				require.NoError(t, err)
				wantFilterClause = initialQuery["query"].(map[string]any)
			}

			// Process the requests
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The test handler simply returns an OK body. This is used by the
				// tests to prove that the middleware passed the request on
				// to the next handler.
				w.WriteHeader(http.StatusOK)

				body, err := middlewares.ReadBody(w, r)
				require.NoError(t, err)

				// Check that the new query is valid json
				queryBody := make(map[string]any)
				err = json.Unmarshal(body, &queryBody)
				require.NoError(t, err)

				// Check that we have a boolean query defined
				require.NotNil(t, queryBody["query"])
				query := queryBody["query"].(map[string]any)
				require.NotNil(t, query["bool"])
				booleanQuery := query["bool"].(map[string]any)

				// Check tenancy query is included on must clause
				require.NotNil(t, booleanQuery["must"])
				tenantQuery := booleanQuery["must"].(map[string]any)
				require.Equal(t, expectedTenantQuery, tenantQuery)

				// Check initial query is included on filter query
				if wantFilterClause != nil {
					require.NotNil(t, booleanQuery["filter"])
					require.Equal(t, wantFilterClause, booleanQuery["filter"])
				}
			})

			handler(testHandler).ServeHTTP(rec, req)
			// Check the returned status code
			require.Equal(t, tt.wantStatus, rec.Result().StatusCode)
		})
	}
}
