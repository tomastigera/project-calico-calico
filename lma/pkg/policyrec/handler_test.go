// Copyright (c) 2019, 2022 Tigera, Inc. All rights reserved.
package policyrec_test

import (
	"bytes"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lma/pkg/policyrec"
)

var (
	properRequestBody           = `{"start_time": "now-3h", "end_time": "now-0h", "endpoint_name": "test-app-pod", "namespace": "test-namespace"}`
	missingEndpointName         = `{"start_time": "now-3h", "end_time": "now-0h", "namespace": "test-namespace"}`
	missingStartTime            = `{"end_time": "now-0h", "endpoint_name": "test-app-pod", "namespace": "test-namespace"}`
	missingEndTime              = `{"start_time": "now-3h", "endpoint_name": "test-app-pod", "namespace": "test-namespace"}`
	missingNamespace            = `{"start_time": "now-3h", "end_time": "now-0h", "endpoint_name": "test-app-pod"}`
	missingNamespaceAndEndpoint = `{"start_time": "now-3h", "end_time": "now-0h"}`
	improperJSONRequestBody     = `"start_time": "now-3h", "end_time": "now-0h", "endpoint_name": "test-app-pod", "namespace": "test-namespace"`

	fullParams = policyrec.PolicyRecommendationParams{
		StartTime:     "now-3h",
		EndTime:       "now-0h",
		EndpointName:  "test-app-pod",
		Namespace:     "test-namespace",
		DocumentIndex: "tigera_secure_ee_flows*",
	}

	globalParams = policyrec.PolicyRecommendationParams{
		StartTime:     "now-3h",
		EndTime:       "now-0h",
		EndpointName:  "test-app-pod",
		DocumentIndex: "tigera_secure_ee_flows*",
	}

	namespaceParams = policyrec.PolicyRecommendationParams{
		StartTime:     "now-3h",
		EndTime:       "now-0h",
		EndpointName:  "",
		Namespace:     "test-namespace",
		DocumentIndex: "tigera_secure_ee_flows*",
	}
)

var _ = Describe("Policy Recommendation Unit Tests for handler functions", func() {
	DescribeTable("Extracts the query parameters from the request and validates them",
		func(origReqBody string, expectedParams policyrec.PolicyRecommendationParams, expectErr bool) {
			// Build the request
			b := []byte(origReqBody)
			req, err := http.NewRequest("POST", "", bytes.NewBuffer(b))
			Expect(err).NotTo(HaveOccurred())

			// Run the param extraction function
			params, err := policyrec.ExtractPolicyRecommendationParamsFromRequest(req)

			if expectErr {
				Expect(params).To(BeNil())
				Expect(err).NotTo(BeNil())
			} else {
				Expect(*params).To(Equal(expectedParams))
				Expect(err).NotTo(HaveOccurred())
			}
		},
		Entry("Proper request body with all values filled", properRequestBody, fullParams, false),
		Entry("Request body missing endpoint name", missingEndpointName, namespaceParams, false),
		Entry("Request body missing start time", missingStartTime, nil, true),
		Entry("Request body missing namespace and endpoint", missingNamespaceAndEndpoint, nil, true),
		Entry("Request body missing end time", missingEndTime, nil, true),
		Entry("Request body missing namespace (global)", missingNamespace, globalParams, false),
		Entry("Request body is improperly formatted JSON", improperJSONRequestBody, nil, true),
	)
})
