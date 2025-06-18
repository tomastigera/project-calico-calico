package middlewares_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/es-gateway/pkg/middlewares"
)

func TestIsAllowed(t *testing.T) {
	const (
		bulkBodySampleWithKibanaIndices = `{"index" : { "_index" : ".kibana", "_id" : "1" }}
{ "field1" : "value1" }
{ "delete" : { "_index" : ".kibana", "_id" : "2" } }
{ "create" : { "_index" : ".kibana", "_id" : "3" } }
{ "field1" : "value1" }
{ "update" : {"_id" : "1", "_index" : ".kibana"} }
{ "doc" : {"field2" : "value2"} }`
		bulkBodyIndexWithNonKibanaIndices = `{"index" : { "_index" : "anyIndex", "_id" : "1" }}
{ "field1" : "value1" }`
		bulkBodyDeleteWithNonKibanaIndices = `{ "delete" : { "_index" : "anyIndex", "_id" : "2" } }`
		bulkBodyCreateWithNonKibanaIndices = `{ "create" : { "_index" : "anyIndex", "_id" : "3" } }
{ "field1" : "value1" }`
		bulkBodyUpdateWithNonKibanaIndices = `{ "update" : {"_id" : "1", "_index" : "anyIndex"} }
{ "doc" : {"field2" : "value2"} }`
		bulkBodyWithKibanaAndNonKibanaIndices = `{"index" : { "_index" : ".kibana", "_id" : "1" }}
{ "field1" : "value1" }
{"index" : { "_index" : "anyIndex", "_id" : "1" }}
{ "field1" : "value1" }`
		closePointInTimeBodyWithKibanaIndex = `{"id":"u961AwETLmtpYmFuYV83LjE3LjE4XzAwMRZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3ABY0a1RZdEdHMFRIV0hJYXNIUDZTdFVBAAAAAAAAANE4FnZXUFZrMjdMVENlTFFqSUhxS3VFX1EAARZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3AAA="}`
		serchBodyWithKibanaIndex            = `{"pit":{"id":"u961AwETLmtpYmFuYV83LjE3LjE4XzAwMRZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3ABY0a1RZdEdHMFRIV0hJYXNIUDZTdFVBAAAAAAAAANE4FnZXUFZrMjdMVENlTFFqSUhxS3VFX1EAARZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3AAA="}}`
		mgetBodySampleWithKibanaIndices     = `{"docs":[{"_id":"dashboard:3a849d80-e970-11ea-83c8-edded0d3c4d6","_index":".kibana_8.18.1"}]}`
		mgetBodyIndexWithNonKibanaIndices   = `{"docs":[{"_id":"dashboard:3a849d80-e970-11ea-83c8-edded0d3c4d6","_index":".anyIndex"}]}`
	)

	tests := []struct {
		name      string
		method    string
		url       string
		body      *string
		wantAllow bool
		wantError error
	}{
		// Bulk request tests
		{
			name:      "Should reject any bulk requests that targets a calico index ",
			method:    http.MethodPost,
			url:       "/calico_flows.123/_bulk",
			wantAllow: false,
		},
		{
			name:      "Should allow any bulk requests that targets a kibana index in its body",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(bulkBodySampleWithKibanaIndices),
			wantAllow: true,
		},
		{
			name:      "Should reject any bulk requests that does not target a kibana index for an index action",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(bulkBodyIndexWithNonKibanaIndices),
			wantAllow: false,
		},
		{
			name:      "Should reject any bulk requests that does not target a kibana index for a delete action",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(bulkBodyDeleteWithNonKibanaIndices),
			wantAllow: false,
		},
		{
			name:      "Should reject any bulk requests that does not target a kibana index for a create action",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(bulkBodyCreateWithNonKibanaIndices),
			wantAllow: false,
		},
		{
			name:      "Should reject any bulk requests that does not target a kibana index for a update action",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(bulkBodyUpdateWithNonKibanaIndices),
			wantAllow: false,
		},
		{
			name:      "Should reject any bulk requests that contains both kibana indices and non-kibana indices",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(bulkBodyWithKibanaAndNonKibanaIndices),
			wantAllow: false,
		},
		{
			name:      "Should process bulk requests ending in newline",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(fmt.Sprintf("%s\n", bulkBodySampleWithKibanaIndices)),
			wantAllow: true,
		},
		{
			name:      "Should process bulk requests ending in newline for Windows",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(fmt.Sprintf("%s\r\n", bulkBodySampleWithKibanaIndices)),
			wantAllow: true,
		},
		{
			name:      "Should not process a empty bulk request",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(``),
			wantAllow: false,
			wantError: fmt.Errorf("unexpected end of JSON input"),
		},
		{
			name:      "Should not process bulk request with no actions",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(fmt.Sprintf(`{}%s{}%s`, "\n", "\n")),
			wantAllow: false,
			wantError: middlewares.NoIndexError,
		},
		{
			name:      "Should not process a malformed bulk request",
			method:    http.MethodPost,
			url:       "/_bulk",
			body:      ptrString(`{@#$!@#!32}`),
			wantAllow: false,
			wantError: fmt.Errorf("invalid character '@' looking for beginning of object key string"),
		},
		// Request that start with a Kibana index
		{
			name:      "Should allow all GET requests for an index that starts with Kibana",
			method:    http.MethodGet,
			url:       "/.kibana",
			wantAllow: true,
		},
		{
			name:      "Allow all PUT requests for an index that starts with Kibana",
			method:    http.MethodPut,
			url:       "/.kibana",
			wantAllow: true,
		},
		{
			name:      "Allow all DELETE requests for an index that starts with Kibana",
			method:    http.MethodDelete,
			url:       "/.kibana",
			wantAllow: true,
		},
		{
			name:      "Allow all POST requests for an index that starts with Kibana",
			method:    http.MethodPost,
			url:       "/.kibana",
			wantAllow: true,
		},
		{
			name:      "Allow all HEAD requests for an index that starts with Kibana",
			method:    http.MethodHead,
			url:       "/.kibana",
			wantAllow: true,
		},
		// Nodes requests
		{
			name:      "Should allow _nodes using a filter path set to nodes.*.version,nodes.*.http.publish_address,nodes.*.ip",
			method:    http.MethodGet,
			url:       "/_nodes?filter_path=nodes.*.version%2Cnodes.*.http.publish_address%2Cnodes.*.ip",
			wantAllow: true,
		},
		{
			name:      "Should deny _nodes requests with a missing value for the filter query parameter",
			method:    http.MethodGet,
			url:       "/_nodes?filter_path=",
			wantAllow: false,
		},
		{
			name:      "Should deny any _nodes requests",
			method:    http.MethodGet,
			url:       "/_nodes",
			wantAllow: false,
		},
		// Close Point in time requests
		{
			name:      "Should allow a point in time deletion request for a kibana index",
			method:    http.MethodDelete,
			url:       "/_pit",
			body:      ptrString(closePointInTimeBodyWithKibanaIndex),
			wantAllow: true,
		},
		{
			name:      "Should not process a malformed close point in time request",
			method:    http.MethodDelete,
			url:       "/_pit",
			body:      ptrString(`{@#$!@#!32}`),
			wantAllow: false,
			wantError: fmt.Errorf("invalid character '@' looking for beginning of object key string"),
		},
		{
			name:      "Should not process an empty close point in time request",
			method:    http.MethodDelete,
			url:       "/_pit",
			body:      ptrString(``),
			wantAllow: false,
			wantError: fmt.Errorf("unexpected end of JSON input"),
		},
		{
			name:      "Should not process an empty json for a close point in time request",
			method:    http.MethodDelete,
			url:       "/_pit",
			body:      ptrString(`{}`),
			wantAllow: false,
		},
		{
			name:      "Should not process a close point in time request without an id",
			method:    http.MethodDelete,
			url:       "/_pit",
			body:      ptrString(`{"id":""}`),
			wantAllow: false,
		},
		{
			name:      "Should deny a close point in time request that does not reference a kibana index",
			method:    http.MethodDelete,
			url:       "/_pit",
			body:      ptrString(fmt.Sprintf(`{"id":"%s"}`, base64.StdEncoding.EncodeToString([]byte("anyIndex")))),
			wantAllow: false,
		},
		{
			name:      "Should not process a close point in time request without an id that is base64 encoded",
			method:    http.MethodDelete,
			url:       "/_pit",
			body:      ptrString(`{"id":"anyValue"}`),
			wantAllow: false,
		},
		// Task requests
		{
			name:      "Should allow any requests to read tasks",
			method:    http.MethodGet,
			url:       "/_tasks/",
			wantAllow: true,
		},
		// Kibana Template requests
		{
			name:      "Should allow to check existence for templates for kibana",
			method:    http.MethodHead,
			url:       "/_template/.kibana",
			wantAllow: true,
		},
		{
			name:      "Should allow to read templates for kibana index templates",
			method:    http.MethodGet,
			url:       "/_template/kibana_index_template*",
			wantAllow: true,
		},
		// Search requests for Kibana indices
		{
			name:      "Should allow a search request for a kibana index",
			method:    http.MethodPost,
			url:       "/_search?allow_partial_search_results=false",
			body:      ptrString(serchBodyWithKibanaIndex),
			wantAllow: true,
		},
		{
			name:      "Should not process a malformed search request",
			method:    http.MethodPost,
			url:       "/_search?allow_partial_search_results=false",
			body:      ptrString(`{@#$!@#!32}`),
			wantAllow: false,
			wantError: fmt.Errorf("invalid character '@' looking for beginning of object key string"),
		},
		{
			name:      "Should not process an empty search request",
			method:    http.MethodPost,
			url:       "/_search?allow_partial_search_results=false",
			body:      ptrString(``),
			wantAllow: false,
			wantError: fmt.Errorf("unexpected end of JSON input"),
		},
		{
			name:      "Should not process an empty json for search request",
			method:    http.MethodPost,
			url:       "/_search?allow_partial_search_results=false",
			body:      ptrString(`{}`),
			wantAllow: false,
		},
		{
			name:      "Should not process a search request without an id",
			method:    http.MethodPost,
			url:       "/_search?allow_partial_search_results=false",
			body:      ptrString(`{"pit":{"id":""}}`),
			wantAllow: false,
		},
		{
			name:      "Should deny a search request that does not reference a kibana index",
			method:    http.MethodPost,
			url:       "/_search?allow_partial_search_results=false",
			body:      ptrString(fmt.Sprintf(`{"pit":{"id":"%s"}}`, base64.StdEncoding.EncodeToString([]byte("anyIndex")))),
			wantAllow: false,
		},
		{
			name:      "Should not process a search request without an id that is base64 encoded",
			method:    http.MethodPost,
			url:       "/_search?allow_partial_search_results=false",
			body:      ptrString(`{"pit":{"id":"anyID"}}`),
			wantAllow: false,
			wantError: fmt.Errorf("illegal base64 data at input byte 4"),
		},

		// Security requests
		{
			name:      "Should allow for kibana to read its privileges",
			method:    http.MethodGet,
			url:       "/_security/privilege/kibana-.kibana",
			wantAllow: true,
		},
		{
			name:      "Should allow for kibana to check its privileges",
			method:    http.MethodPost,
			url:       "/_security/user/_has_privileges",
			wantAllow: true,
		},
		// License requests
		{
			name:      "Should allow for kibana to check elastic license",
			method:    http.MethodGet,
			url:       "/_xpack?accept_enterprise=true",
			wantAllow: true,
		},
		{
			name:      "Should deny xpack requests with missing values for accept_enterprise query parameter",
			method:    http.MethodGet,
			url:       "/_xpack?accept_enterprise",
			wantAllow: false,
		},
		{
			name:      "Should deny any xpack requests",
			method:    http.MethodGet,
			url:       "/_xpack",
			wantAllow: false,
		},
		// Async search requests
		{
			name:      "Should allow an async search request for a calico cloud index",
			method:    http.MethodPost,
			url:       "/calico_anyData*/_async_search",
			wantAllow: true,
		},
		{
			name:      "Should not allow an async search request for other indices",
			method:    http.MethodPost,
			url:       "/anyIndex*/_async_search",
			wantAllow: false,
		},
		{
			name:      "Should not allow an async search request without a target",
			method:    http.MethodPost,
			url:       "/_async_search",
			wantAllow: false,
		},
		{
			name:      "Should not allow an async search request for a kibana index and query q param",
			method:    http.MethodPost,
			url:       "/calico_anyData*/_async_search?q=abc",
			wantAllow: false,
		},
		{
			name:      "Should allow an async search request for a kibana index to retrieve partial results",
			method:    http.MethodGet,
			url:       "/_async_search/FnF4REF0THh5U2gtM3Q0eVpMdWltSmcdNGtUWXRHRzBUSFdISWFzSFA2U3RVQToxMTUwMTY=",
			wantAllow: true,
		},
		{
			name:      "Should not allow an async search request for a kibana index using GET",
			method:    http.MethodGet,
			url:       "/calico_anyData*/_async_search",
			wantAllow: false,
		},
		{
			name:      "Should not allow an async search request with a query parameter",
			method:    http.MethodGet,
			url:       "/_async_search/FnF4REF0THh5U2gtM3Q0eVpMdWltSmcdNGtUWXRHRzBUSFdISWFzSFA2U3RVQToxMTUwMTY=?q=any",
			wantAllow: false,
		},
		{
			name:      "Should not allow an async search request with a GET with a body",
			method:    http.MethodGet,
			url:       "/_async_search",
			wantAllow: false,
			body:      ptrString(`{}`),
		},
		{
			name:      "Should allow a delete request for an async search",
			method:    http.MethodDelete,
			url:       "/_async_search/FnF4REF0THh5U2gtM3Q0eVpMdWltSmcdNGtUWXRHRzBUSFdISWFzSFA2U3RVQToxMTUwMTY=",
			wantAllow: true,
		},
		// Field caps requests
		{
			name:      "Should allow a field caps request for a kibana index",
			method:    http.MethodGet,
			url:       "/calico_anyData*/_field_caps",
			wantAllow: true,
		},
		{
			name:      "Should not allow a field caps request for other indices",
			method:    http.MethodGet,
			url:       "/anyIndex*/_field_caps",
			wantAllow: false,
		},
		{
			name:      "Should not allow any GET field caps requests without a target",
			method:    http.MethodGet,
			url:       "/_field_caps",
			wantAllow: false,
		},
		{
			name:      "Should not allow any POST field caps requests without a target",
			method:    http.MethodPost,
			url:       "/_field_caps",
			wantAllow: false,
		},
		// MGET requests
		{
			name:      "Should reject any mget requests that target a calico index",
			method:    http.MethodPost,
			url:       "/calico_flows.123/_mget",
			wantAllow: false,
		},
		{
			name:      "Should allow any mget requests that target a kibana index in its body",
			method:    http.MethodPost,
			url:       "/_mget",
			body:      ptrString(mgetBodySampleWithKibanaIndices),
			wantAllow: true,
		},
		{
			name:      "Should reject any mget requests that does not target a kibana index",
			method:    http.MethodPost,
			url:       "/_mget",
			body:      ptrString(mgetBodyIndexWithNonKibanaIndices),
			wantAllow: false,
		},
		{
			name:      "Should not process an empty mget request",
			method:    http.MethodPost,
			url:       "/_mget",
			body:      ptrString(``),
			wantAllow: false,
			wantError: fmt.Errorf("unexpected end of JSON input"),
		},
		{
			name:      "Should not process mget request with no docs",
			method:    http.MethodPost,
			url:       "/_mget",
			body:      ptrString(`{"docs":[]}`),
			wantAllow: false,
			wantError: middlewares.NoIndexError,
		},
		{
			name:      "Should not process mget request with no index on a doc",
			method:    http.MethodPost,
			url:       "/_mget",
			body:      ptrString(`{"docs":[{"_index": ""}]}`),
			wantAllow: false,
			wantError: middlewares.NoIndexError,
		},
		{
			name:      "Should not process a malformed mget request",
			method:    http.MethodPost,
			url:       "/_mget",
			body:      ptrString(`{@#$!@#!32}`),
			wantAllow: false,
			wantError: fmt.Errorf("invalid character '@' looking for beginning of object key string"),
		},
		// Authentication requests
		{
			name:      "Should allow authentication requests",
			method:    http.MethodGet,
			url:       "/_security/_authenticate",
			wantAllow: true,
		},
		// Exploratory requests
		{
			name:      "Should not allow any msearch request for calico cloud indices",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_msearch",
			wantAllow: false,
		},
		{
			name:      "Should not allow any count request for calico cloud indices",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_count?q=tenant:any",
			wantAllow: false,
		},
		{
			name:      "Should not allow any validate request for calico cloud indices",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_validate/query?q=tenant:any",
			wantAllow: false,
		},
		{
			name:      "Should not allow any document retrieval request for calico cloud indices",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_doc",
			wantAllow: false,
		},
		{
			name:      "Should not allow any knn search request for calico cloud indices",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_knn_search",
			wantAllow: false,
		},
		{
			name:      "Should not allow any search shards request for calico cloud indices",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_search_shards",
			wantAllow: false,
		},
		{
			name:      "Should not allow any search templates request for calico cloud indices using GET",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_search/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow any search templates request using GET",
			method:    http.MethodGet,
			url:       "/_search/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow any search templates request using POST",
			method:    http.MethodPost,
			url:       "/_search/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow any search templates creation request",
			method:    http.MethodPut,
			url:       "/_scripts/my-search-template",
			wantAllow: false,
		},
		{
			name:      "Should not validate any search templates",
			method:    http.MethodPost,
			url:       "/_render/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow running multiple templates requests for calico indices using GET",
			method:    http.MethodGet,
			url:       "/calico_anyIndex*/_msearch/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow running multiple templates requests for calico indices using POST",
			method:    http.MethodPost,
			url:       "/calico_anyIndex*/_msearch/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow running multiple templates requests using GET",
			method:    http.MethodGet,
			url:       "/_msearch/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow running multiple templates requests using POST",
			method:    http.MethodPost,
			url:       "/_msearch/template",
			wantAllow: false,
		},
		{
			name:      "Should not allow requests for all indices",
			method:    http.MethodGet,
			url:       "/_all",
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, body(tt.body))
			require.NoError(t, err)
			gotAllow, gotError := middlewares.IsAllowed(nil, req)
			require.Equal(t, tt.wantAllow, gotAllow)
			if tt.wantError != nil {
				require.Error(t, gotError)
				require.Equal(t, tt.wantError.Error(), gotError.Error())
			} else {
				require.NoError(t, gotError)
			}
		})
	}
}

func body(body *string) io.Reader {
	if body == nil {
		return nil
	}

	return bytes.NewBufferString(*body)
}

func ptrString(s string) *string {
	return &s
}
