// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package middlewares

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var fieldCapsRegexp = regexp.MustCompile(`(/calico_)(.+)(\*)(/_field_caps)`)
var asyncSearchRegexp = regexp.MustCompile(`(/calico_)(.+)(\*)(/_async_search)`)

func IsAllowed(w http.ResponseWriter, r *http.Request) (allow bool, err error) {
	switch {
	// All requests that are allowed below are needed to mark Kibana up and running
	case r.URL.Path == "/_bulk" && r.Method == http.MethodPost:
		// This is a request Kibana makes to update its indices
		// POST /_bulk?refresh=false&_source_includes=originId&require_alias=true
		// {"update":{"_id":"task:endpoint:user-artifact-packager:1.0.0","_index":".kibana_task_manager_8.18.1"}}
		// We need to filter through the body of this request and determine if we access only .kibana indices
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/docs-bulk.html
		return isBulkRequestAllowed(w, r)
	case strings.HasPrefix(r.URL.Path, "/.kibana"):
		// These request access kibana indices for read/write/update data
		// DELETE /.kibana_task_manager_8.18.1/_doc/
		// GET /.kibana_8.18.1/_doc/
		// GET /.kibana%2C.kibana_8.18.1?ignore_unavailable=true
		// GET /.kibana_task_manager%2C.kibana_task_manager_8.18.1?ignore_unavailable=true
		// GET /.kibana-event-log-*/_alias
		// GET /.kibana-event-log-*/_settings
		// GET /.kibana_security_session_1/_doc
		// GET /.kibana_task_manager_8.18.1/_doc/
		// POST /.kibana_8.18.1_001/_pit?keep_alive=10m
		// POST /.kibana_8.18.1_001/_update_by_query
		// POST /.kibana_8.18.1/_search
		// POST /.kibana_8.18.1/_update
		// POST /.kibana_task_manager_8.18.1_001/_pit?keep_alive=10m
		// POST /.kibana_task_manager_8.18.1_001/_update_by_query
		// POST /.kibana_task_manager/_search
		// POST /.kibana_task_manager/_update_by_query
		// PUT /.kibana_8.18.1_001/_mapping?timeout=60s
		// PUT /.kibana_8.18.1/_create
		// PUT /.kibana_8.18.1/_doc
		// PUT /.kibana_task_manager_8.18.1_001/_mapping?
		// PUT /.kibana_task_manager_8.18.1/_create
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/rest-apis.html
		return true, nil
	case r.URL.Path == "/_nodes" && r.Method == http.MethodGet &&
		hasQueryParam(r, "filter_path", "nodes.*.version,nodes.*.http.publish_address,nodes.*.ip"):
		// This is a periodic request Kibana makes to gather information about Elastic nodes
		// The following information is retrieved: nodes.*.version,nodes.*.http.publish_address,nodes.*.ip
		// GET /_nodes?filter_path=nodes.*.version%2Cnodes.*.http.publish_address%2Cnodes.*.ip
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/cluster.html#cluster-nodes
		return true, nil
	case r.URL.Path == "/_pit" && r.Method == http.MethodDelete:
		// This is a request to delete a point in time. We will allow it without checking the index
		// PIT request are previously make for kibana indices, like the ones below
		// POST /.kibana_task_manager_8.18.1_001/_pit?keep_alive=10m
		// DELETE /_pit
		// {"id":"u961AwETLmtpYmFuYV83LjE3LjE4XzAwMRZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3ABY0a1RZdEdHMFRIV0hJYXNIUDZTdFVBAAAAAAAAANE4FnZXUFZrMjdMVENlTFFqSUhxS3VFX1EAARZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3AAA="}
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/point-in-time-api.html
		return isDeletePointInTimeRequestAllowed(w, r)
	case strings.HasPrefix(r.URL.Path, "/_tasks/") && r.Method == http.MethodGet:
		// This is a request from Kibana to access task APIs
		// This request is needed for Kibana to be marked Running
		// GET /_tasks/4kTYtGG0THWHIasHP6StUA%3A658066?wait_for_completion=true&timeout=60s
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/current/tasks.html#tasks-api-path-params
		return true, nil
	case r.URL.Path == "/_template/.kibana" && r.Method == http.MethodHead:
		// This request checks the existence of template ./_template/.kibana
		// HEAD /_template/.kibana
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-template-exists-v1.html
		return true, nil
	case r.URL.Path == "/_template/kibana_index_template*" && r.Method == http.MethodGet:
		// This request retrieves all index templates that start with kibana_index_template
		// GET /_template/kibana_index_template*
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-get-template.html
		return true, nil
	case r.URL.Path == "/_search" && r.Method == http.MethodPost && hasQueryParam(r, "allow_partial_search_results", "false"):
		// This is a search request that does not specify the index in the path. This needs special handling to determine
		// if we support the query or not. For example, search requests with a point in time do not
		// specify the index in the URL. Kibana makes _search requests with a point in time during startup.
		// This request is needed for Kibana to be marked Running
		// POST /_search?allow_partial_search_results=false
		// {
		//  "sort": {
		//    "_shard_doc": {
		//      "order": "asc"
		//    }
		//  },
		//  "pit": {
		//    "id": "u961AwETLmtpYmFuYV83LjE3LjE4XzAwMRZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3ABY0a1RZdEdHMFRIV0hJYXNIUDZTdFVBAAAAAAAAAD_TFnZXUFZrMjdMVENlTFFqSUhxS3VFX1EAARZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3AAA=",
		//    "keep_alive": "10m"
		//  }..}
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/point-in-time-api.html
		return isSearchRequestAllowed(w, r)
	case r.URL.Path == "/_security/privilege/kibana-.kibana" && r.Method == http.MethodGet:
		// This request retrieves privileges for application kibana-.kibana
		// GET /_security/privilege/kibana-.kibana
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-api-get-privileges.html
		return true, nil
	case r.URL.Path == "/_security/user/_has_privileges" && r.Method == http.MethodPost:
		// This requests checks what privileges has application kibana-.kibana
		// POST /_security/user/_has_privileges
		// {"index":[],"application":[{"application":"kibana-.kibana","resources":["*"],"privileges":["version:8.18.1","login:","ui:8.18.1:enterpriseSearch/all"]}]
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-api-has-privileges.html
		return true, nil
	case r.URL.Path == "/_xpack" && r.Method == http.MethodGet && hasQueryParam(r, "accept_enterprise", "true"):
		// This is a request Kibana makes to retrieves license details
		// GET /_xpack?accept_enterprise=true
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/info-api.html
		return true, nil
	case strings.HasPrefix(r.URL.Path, "/_cluster/health/.kibana") && r.Method == http.MethodGet && hasQueryParam(r, "wait_for_status", "yellow"):
		// This is a request Kibana makes to check the health of the cluster
		// GET /_cluster/health/.kibana_task_manager_8.18.1_001?wait_for_status=yellow&timeout=60s
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/cluster-health.html
		return true, nil
	case r.URL.Path == "/_aliases" && r.Method == http.MethodPost:
		// This is a request Kibana makes to assign an alias to an index
		// This is needed by FV tests in order to mark single node Kibana as ready
		// POST /_aliases
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-aliases.html
		return isAliasesRequestAllowed(w, r)

	// All requests that are allowed below are needed to load Discovery and Dashboards
	case asyncSearchRegexp.MatchString(r.URL.Path) && r.Method == http.MethodPost && !r.URL.Query().Has("q"):
		// This is a request Kibana makes when loading Discovery and Dashboards
		// This will start an async search request. We expect to have the query
		// defined inside the body at this step. We will allow async requests
		// only for calico indices and enhance them with tenancy enforcement
		// POST /calico_flows*/_async_search
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/async-search.html
		return true, nil
	case strings.HasPrefix(r.URL.Path, "/_async_search") && r.Method == http.MethodGet && r.Body == nil && !r.URL.Query().Has("q"):
		// This is a request Kibana makes when loading Discovery and Dashboards
		// This will retrieve partial results from the previous issued query
		// We will restrict creation of async searches requests to calico indices and
		// enhance them with a tenancy enforcement. Thus, these requests will be allowed
		// GET /_async_search/FnF4REF0THh5U2gtM3Q0eVpMdWltSmcdNGtUWXRHRzBUSFdISWFzSFA2U3RVQToxMTUwMTY=
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/async-search.html
		return true, nil
	case strings.HasPrefix(r.URL.Path, "/_async_search") && r.Method == http.MethodDelete:
		// This is a request Kibana makes when loading Discovery and Dashboards
		// This will delete a previously started async search requests
		// We will restrict creation of async searches requests to calico indices and
		// enhance them with a tenancy enforcement as the next step after we allow the requests.
		// DELETE /_async_search/FnF4REF0THh5U2gtM3Q0eVpMdWltSmcdNGtUWXRHRzBUSFdISWFzSFA2U3RVQToxMTUwMTY=
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/async-search.html
		return true, nil
	case fieldCapsRegexp.MatchString(r.URL.Path) && r.Method == http.MethodGet:
		// This is a request Kibana makes when loading Discovery and Dashboards
		// We will limit this API only for calico indices
		// GET /calico_flows*/_field_caps
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/search-field-caps.html
		return true, nil
	case r.URL.Path == "/_mget" && r.Method == http.MethodPost:
		// This is a request Kibana makes when loading Discovery and Dashboards
		// POST /_mget
		// {"docs":[{"_id":"dashboard:3a849d80-e970-11ea-83c8-edded0d3c4d6","_index":".kibana_8.18.1"}]}
		// We need to filter through the body of this request and determine if we
		// access only .kibana* indices
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/docs-multi-get.html
		return isMGETRequestAllowed(w, r)
	case r.URL.Path == "/_security/_authenticate" && r.Method == http.MethodGet:
		// This request is used when users log in
		// GET /_security/_authenticate
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/security-api-authenticate.html
		return true, nil

	// All requests are needed by event log plugin
	// https://github.com/elastic/kibana/blob/8.13/x-pack/plugins/event_log/README.md
	case strings.HasPrefix(r.URL.Path, "/_alias/.kibana-event-log") && r.Method == http.MethodHead:
		// This request is needed by the event log plugin
		// HEAD /_alias/.kibana-event-log-8.18.1
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-get-alias.html
		return true, nil
	case r.URL.Path == "/_ilm/policy/kibana-event-log-policy" && r.Method == http.MethodGet:
		// This request is needed by the event log plugin
		// GET /_ilm/policy/kibana-event-log-policy
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/ilm-get-lifecycle.html
		return true, nil
	case strings.HasPrefix(r.URL.Path, "/_index_template/.kibana-event-log") && r.Method == http.MethodHead:
		// This request is needed by the event log plugin
		// HEAD /_index_template/.kibana-event-log-8.18.1-template
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-template-exists-v1.html
		return true, nil
	case strings.HasPrefix(r.URL.Path, "/_template/.kibana-event-log") && r.Method == http.MethodHead:
		// This request is needed by the event log plugin
		// HEAD /_template/.kibana-event-log-8.18.1-template
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-template-exists-v1.html
		return true, nil
	case r.URL.Path == "/_template/.kibana-event-log-*" && r.Method == http.MethodGet:
		// This request is needed by the event log plugin
		// GET /_template/.kibana-event-log-*
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-get-template.html
		return true, nil

	// All requests are needed by the monitoring plugin
	// https://github.com/elastic/kibana/tree/7.17/x-pack/plugins/monitoring
	// This plugin is needed in order to monitor Kibana application
	// https://www.elastic.co/guide/en/kibana/7.17/xpack-monitoring.html
	case r.URL.Path == "/_monitoring/bulk" && r.Method == http.MethodPost:
		// This request is needed by the monitor plugin
		// POST /_monitoring/bulk?system_id=kibana&system_api_version=7&interval=10000ms
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/docs-bulk.html
		return true, nil

	// All requests are needed by the reporting plugin
	// https://github.com/elastic/kibana/tree/8.13/x-pack/plugins/reporting
	// This plugin is needed by Discovery page to share results
	// https://www.elastic.co/guide/en/kibana/7.17/reporting-getting-started.html
	case r.URL.Path == "/.reporting-*/_search" && r.Method == http.MethodPost:
		// This request is needed by the reporting plugin
		// POST /.reporting-*/_search?size=1&seq_no_primary_term=true&_source_excludes=output
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/search-search.html
		return true, nil
	case r.URL.Path == "/_ilm/policy/kibana-reporting" && r.Method == http.MethodGet:
		// This request is needed by the reporting plugin
		// GET /_ilm/policy/kibana-reporting
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/ilm-get-lifecycle.html
		return true, nil

	// ALl requests below are needed by the security plugin
	// https://github.com/elastic/kibana/tree/8.13/x-pack/plugins/security
	// This plugin is needed in order to enforce RBAC to correlate kibana users
	// with their corresponding Elastic roles
	// https://www.elastic.co/guide/en/kibana/7.17/using-kibana-with-security.html
	case r.URL.Path == "/_index_template/.kibana_security_session_index_template_1" && r.Method == http.MethodHead:
		// This request is needed by the security plugin
		// HEAD /_index_template/.kibana_security_session_index_template_1
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-template-exists-v1.html
		return true, nil
	case r.URL.Path == "/_template/.kibana_security_session_index_template_1" && r.Method == http.MethodHead:
		// This request checks the existence of template .kibana_security_session_index_template_1
		// This request is needed by the security plugin
		// HEAD /_template/.kibana_security_session_index_template_1
		// Elastic API: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/indices-template-exists-v1.html
		return true, nil

	default:
		return false, nil
	}
}

func hasQueryParam(r *http.Request, key string, value string) bool {
	queryValue := r.URL.Query().Get(key)
	if queryValue == "" {
		return false
	}
	return queryValue == value
}

// IndexMetadata is used unmarshal a JSON and
// extract the index name
type IndexMetadata struct {
	Index string `json:"_index"`
}

// BulkAction is used unmarshal a single JSON line from _bulk request
// and extract only the index
type BulkAction struct {
	Update *IndexMetadata `json:"update,omitempty"`
	Index  *IndexMetadata `json:"index,omitempty"`
	Delete *IndexMetadata `json:"delete,omitempty"`
	Create *IndexMetadata `json:"create,omitempty"`
}

func (r BulkAction) GetIndexMetadata() *IndexMetadata {
	if r.Create != nil {
		return r.Create
	} else if r.Delete != nil {
		return r.Delete
	} else if r.Index != nil {
		return r.Index
	} else if r.Update != nil {
		return r.Update
	}

	return nil
}

var NoIndexError = fmt.Errorf("no index referenced on the request")

// isBulkRequestAllowed will determine if a bulk request is allowed or not
// Bulk requests have the following format:
// POST _bulk
// { "index" : { "_index" : "test", "_id" : "1" } }
// { "field1" : "value1" }
// { "delete" : { "_index" : "test", "_id" : "2" } }
// { "create" : { "_index" : "test", "_id" : "3" } }
// { "field1" : "value3" }
// { "update" : {"_id" : "1", "_index" : "test"} }
// { "doc" : {"field2" : "value2"} }
// We need to process each action and determine if we reference any other index
// than a .kibana index
func isBulkRequestAllowed(w http.ResponseWriter, r *http.Request) (bool, error) {
	body, err := ReadBody(w, r)
	if err != nil {
		return false, err
	}

	// We need to process each line and determine if we have index, delete, create or update
	lines := strings.Split(string(bytes.Trim(body, "\r\n")), "\n")
	for index := 0; index < len(lines); index++ {
		bulkRequest := BulkAction{}
		err = json.Unmarshal([]byte(lines[index]), &bulkRequest)
		if err != nil {
			return false, err
		}

		if bulkRequest.Index != nil || bulkRequest.Update != nil || bulkRequest.Create != nil {
			// This is an index/update/create elastic action
			// These actions expect the full document on the next line
			// We will need to skip processing next element
			index++
		}

		indexMetadata := bulkRequest.GetIndexMetadata()
		if indexMetadata == nil {
			return false, NoIndexError
		}

		if !isAKibanaIndex(indexMetadata.Index) {
			return false, nil
		}
	}

	return true, nil
}

// SearchRequestWithPIT is used unmarshal a JSON _search request
// and extract only the PointInTime
type SearchRequestWithPIT struct {
	PIT PointInTime `json:"pit"`
}

// PointInTime is used unmarshal a JSON _search request
// and extract only the PointInTime ID
type PointInTime struct {
	ID string `json:"id"`
}

// isSearchRequestAllowed will determine if a _search request is allowed or not
// POST /_search?allow_partial_search_results=false
//
//	{
//	 "sort": {
//	   "_shard_doc": {
//	     "order": "asc"
//	   }
//	 },
//	 "pit": {
//	   "id": "u961AwETLmtpYmFuYV83LjE3LjE4XzAwMRZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3ABY0a1RZdEdHMFRIV0hJYXNIUDZTdFVBAAAAAAAAAD_TFnZXUFZrMjdMVENlTFFqSUhxS3VFX1EAARZ4WmR3Y1FZY1JBYTQwbWVDam5zeGh3AAA=",
//	   "keep_alive": "10m"
//	 }..}
//
// We need to process the point in time ID and determine if it references any other index
// than a .kibana index
func isSearchRequestAllowed(w http.ResponseWriter, r *http.Request) (bool, error) {
	// We expect this type of request to be issued only against Kibana indices
	body, err := ReadBody(w, r)
	if err != nil {
		return false, err
	}
	searchRequest := SearchRequestWithPIT{}
	err = json.Unmarshal(body, &searchRequest)
	if err != nil {
		return false, err
	}

	if searchRequest.PIT.ID == "" {
		// We will reject any search without an index and a point in time
		return false, nil
	}

	// Search request with a point in time do not specify
	// the index on the request. We can base64 decode and extract the name
	decodedID, err := base64.StdEncoding.DecodeString(searchRequest.PIT.ID)
	if err != nil {
		return false, err
	}

	if !strings.Contains(string(decodedID), ".kibana") {
		// We will reject any search request with a point in time that does not
		// reference a kibana index
		return false, nil
	}

	return true, nil
}

func isDeletePointInTimeRequestAllowed(w http.ResponseWriter, r *http.Request) (bool, error) {
	// We expect this type of request to be issued only against Kibana indices
	body, err := ReadBody(w, r)
	if err != nil {
		return false, err
	}
	pointInTimeRequest := PointInTime{}
	err = json.Unmarshal(body, &pointInTimeRequest)
	if err != nil {
		return false, err
	}

	if pointInTimeRequest.ID == "" {
		return false, nil
	}

	// Point in time requests do not specify the index on the request.
	// We can base64 decode and extract the name
	decodedID, err := base64.StdEncoding.DecodeString(pointInTimeRequest.ID)
	if err != nil {
		return false, err
	}

	if !strings.Contains(string(decodedID), ".kibana") {
		// We will reject any search request with a point in time that does not
		// reference a kibana index
		return false, nil
	}

	return true, nil
}

// MultipleGetRequest is used unmarshal a JSON _mget request
// and extract only the index from the documents
type MultipleGetRequest struct {
	Docs []IndexMetadata `json:"docs"`
}

// isMGETRequestAllowed will determine if a _mget request is allowed or not
// POST /_mget
//
//	{
//	 "docs": [
//	   {
//	     "_index": "my-index-000001",
//	     "_id": "1"
//	   },
//	   {
//	     "_index": "my-index-000001",
//	     "_id": "2"
//	   }
//	 ]
//	}
//
// We need to process each document and determine if we reference any other index
// than a .kibana index
func isMGETRequestAllowed(w http.ResponseWriter, r *http.Request) (bool, error) {
	body, err := ReadBody(w, r)
	if err != nil {
		return false, err
	}
	mGetRequest := MultipleGetRequest{}
	err = json.Unmarshal(body, &mGetRequest)
	if err != nil {
		return false, err
	}

	if len(mGetRequest.Docs) == 0 {
		return false, NoIndexError
	}

	for _, doc := range mGetRequest.Docs {
		if doc.Index == "" {
			return false, NoIndexError
		}
		if !isAKibanaIndex(doc.Index) {
			return false, nil
		}
	}
	return true, nil
}

func isAKibanaIndex(id string) bool {
	return strings.HasPrefix(id, ".kibana")
}

// AliasIndex will only extract the index information
type AliasIndex struct {
	Index string `json:"index"`
}

// Aliases is used unmarshal a JSON _aliases request
// and extract only the index from actions
type Aliases struct {
	Actions []struct {
		Add         *AliasIndex `json:"add,omitempty"`
		Remove      *AliasIndex `json:"remove,omitempty"`
		RemoveIndex *AliasIndex `json:"removeIndex,omitempty"`
	} `json:"actions"`
}

// isAliasesRequestAllowed will determine if an alias request is allowed or not
// POST /_aliases
//
//	{
//	 "actions": [
//	   {
//	     "add": {
//	       "index": ".kibana_task_manager_8.18.1_001",
//	       "alias": ".kibana_task_manager"
//	     }
//	   },
//	   {
//	     "add": {
//	       "index": ".kibana_task_manager_8.18.1_001",
//	       "alias": ".kibana_task_manager_8.18.1"
//	     }
//	   }
//	 ]
//	}
//
// We need to process each action and determine if the indices referenced are kibana indices
func isAliasesRequestAllowed(w http.ResponseWriter, r *http.Request) (bool, error) {
	// We expect this type of request to be issued only against Kibana indices
	body, err := ReadBody(w, r)
	if err != nil {
		return false, err
	}
	aliasesRequest := Aliases{}
	err = json.Unmarshal(body, &aliasesRequest)
	if err != nil {
		return false, err
	}

	for _, action := range aliasesRequest.Actions {
		if action.Add != nil {
			// Add needs to reference a kibana index
			if !isAKibanaIndex(action.Add.Index) {
				return false, nil
			}
		}
		if action.RemoveIndex != nil {
			// RemoveIndex needs to reference a kibana index
			if !isAKibanaIndex(action.Add.Index) {
				return false, nil
			}
		}
		if action.Remove != nil {
			// Remove needs to reference a kibana index
			if !isAKibanaIndex(action.Add.Index) {
				return false, nil
			}
		}
	}

	return true, nil
}
