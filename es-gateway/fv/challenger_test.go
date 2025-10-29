// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package fv_test

import (
	"net/http"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestFV_Challenger(t *testing.T) {
	t.Run("Ensure Challenger sends connections to Elastic", func(t *testing.T) {
		defer setupAndTeardown(t, DefaultChallengerArgs(), nil)()

		response, elasticBody, err := doRequest("GET", "http://localhost:5555/", nil, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		// Response sample from Elastic
		//{
		//  "name" : "asincu-Precision-5540",
		//  "cluster_name" : "docker-cluster",
		//  "cluster_uuid" : "5lIuJ_FXSBakaIOJJBl4Zw",
		//  "version" : {
		//    "number" : "x.y.z",
		//    "build_flavor" : "default",
		//    "build_type" : "docker",
		//    "build_hash" : "8682172c2130b9a411b1bd5ff37c9792367de6b0",
		//    "build_date" : "2024-02-02T12:04:59.691750271Z",
		//    "build_snapshot" : false,
		//    "lucene_version" : "x.y.z",
		//    "minimum_wire_compatibility_version" : "6.8.0",
		//    "minimum_index_compatibility_version" : "6.0.0-beta1"
		//  },
		//  "tagline" : "You Know, for Search"
		//}
		require.Contains(t, string(elasticBody), "You Know, for Search")
	})

	var isKibanaReady = func() bool {
		log.Debugf("Making requests to see if Kibana is up and ready")
		response, _, err := doRequest("GET", "http://localhost:5601/", nil, nil)
		if err != nil {
			log.Warnf("Received error %s", err)
			return false
		}
		if response.StatusCode != http.StatusOK {
			log.Warnf("Received status %s", response.Status)
			return false
		}
		return true
	}

	var kibanaHeaders = map[string]string{
		"Content-Type": "application/json",
		"kbn-xsrf":     "true",
	}

	t.Run("Ensure Kibana connects to Elastic via Kibana Proxy", func(t *testing.T) {
		kibanaArgs := &RunKibanaArgs{
			Image: "docker.elastic.co/kibana/kibana:8.18.8",
			// We are setting the proxy endpoint as elastic backend
			ElasticHosts: "http://localhost:5555",
		}
		defer setupAndTeardown(t, DefaultChallengerArgs(), kibanaArgs)()

		require.Eventually(t, isKibanaReady, 30*time.Second, 100*time.Millisecond)

		log.Debugf("Making requests to see Kibana features")
		response, _, err := doRequest("GET", "http://localhost:5601/api/features", nil, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("Ensure Kibana Spaces can be created", func(t *testing.T) {
		kibanaArgs := &RunKibanaArgs{
			Image: "docker.elastic.co/kibana/kibana:8.18.8",
			// We are setting the proxy endpoint as elastic backend
			ElasticHosts: "http://localhost:5555",
		}
		defer setupAndTeardown(t, DefaultChallengerArgs(), kibanaArgs)()

		require.Eventually(t, isKibanaReady, 30*time.Second, 100*time.Millisecond)

		log.Debugf("Making requests to verify that a Kibana space is created")
		space := `{"id": "any","name": "Any Kibana space"}`
		response, body, err := doRequest("POST", "http://localhost:5601/api/spaces/space", kibanaHeaders, []byte(space))
		log.Debugf("Response body: %s", string(body))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("Ensure Dashboards and Index Patterns can be created", func(t *testing.T) {
		kibanaArgs := &RunKibanaArgs{
			Image: "docker.elastic.co/kibana/kibana:8.18.8",
			// We are setting the proxy endpoint as elastic backend
			ElasticHosts: "http://localhost:5555",
		}
		defer setupAndTeardown(t, DefaultChallengerArgs(), kibanaArgs)()

		require.Eventually(t, isKibanaReady, 30*time.Second, 100*time.Millisecond)

		savedObjects := `[
  {
    "type": "index-pattern",
    "id": "my-pattern",
    "attributes": {
      "title": "my-pattern-*"
    }
  },
  {
    "type": "dashboard",
    "id": "be3733a0-9efe-11e7-acb3-3dab96693fab",
    "attributes": {
      "title": "Look at my dashboard"
    }
  }
]`

		log.Debugf("Making requests to verify that Kibana objects are created successfully")
		response, body, err := doRequest("POST", "http://localhost:5601/api/saved_objects/_bulk_create", kibanaHeaders, []byte(savedObjects))
		log.Debugf("Response body: %s", string(body))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
	})

	t.Run("Ensure tenancy is enforce on async search requests", func(t *testing.T) {
		defer setupAndTeardown(t, DefaultChallengerArgs(), nil)()

		// Write a document for tenant A in Elastic
		tenantAData := `{"tenant":"A"}`
		esHeaders := map[string]string{"Content-Type": "application/json"}
		responseDocTenantA, body, err := doRequest("POST", "http://localhost:9200/calico_any.001/_doc/1?refresh=true", esHeaders, []byte(tenantAData))
		log.Debugf("Response body: %s", string(body))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, responseDocTenantA.StatusCode)

		// Write a document for tenant B in Elastic
		tenantBData := `{"tenant":"B"}`
		responseDocTenantB, body, err := doRequest("POST", "http://localhost:9200/calico_any.001/_doc/2?refresh=true", esHeaders, []byte(tenantBData))
		log.Debugf("Response body: %s", string(body))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, responseDocTenantB.StatusCode)

		// make an async search request via the Challenger
		searchBody := `{"query": {"match_all":{}}}`
		response, data, err := doRequest("POST", "http://localhost:5555/calico_any*/_async_search", kibanaHeaders, []byte(searchBody))
		log.Debugf("Response body: %s", string(data))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Contains(t, string(data), tenantAData)
		require.NotContains(t, string(data), tenantBData)
	})
}
