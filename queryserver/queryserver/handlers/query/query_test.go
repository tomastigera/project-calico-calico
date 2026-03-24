// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.
package query

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/queryserver/pkg/querycache/client"
)

var (
	//go:embed testdata/expected_metrics.txt
	expectedMetrics string
)

var _ = Describe("Queryserver query tests", func() {

	Context("Prometheus metrics export", func() {

		It("should export metrics", func() {
			qi := client.MockQueryInterface{}
			qi.On("RunQuery", mock.Anything, mock.Anything).Return(&client.QueryClusterResp{
				NumGlobalNetworkPolicies:          1,
				NumUnmatchedGlobalNetworkPolicies: 2,
				NumNetworkPolicies:                3,
				NumUnmatchedNetworkPolicies:       4,
				NumHostEndpoints:                  5,
				NumUnlabelledHostEndpoints:        6,
				NumUnprotectedHostEndpoints:       7,
				NumWorkloadEndpoints:              8,
				NumUnlabelledWorkloadEndpoints:    9,
				NumUnprotectedWorkloadEndpoints:   10,
				NumFailedWorkloadEndpoints:        11,
				NumNodes:                          12,
				NumNodesWithNoEndpoints:           13,
				NumNodesWithNoHostEndpoints:       14,
				NumNodesWithNoWorkloadEndpoints:   15,
				NamespaceCounts: map[string]client.QueryClusterNamespaceCounts{
					"ns1": {
						NumNetworkPolicies:              16,
						NumUnmatchedNetworkPolicies:     17,
						NumWorkloadEndpoints:            18,
						NumUnlabelledWorkloadEndpoints:  19,
						NumUnprotectedWorkloadEndpoints: 20,
						NumFailedWorkloadEndpoints:      21,
					},
					"ns2": {
						NumNetworkPolicies:              22,
						NumUnmatchedNetworkPolicies:     23,
						NumWorkloadEndpoints:            24,
						NumUnlabelledWorkloadEndpoints:  25,
						NumUnprotectedWorkloadEndpoints: 26,
						NumFailedWorkloadEndpoints:      27,
					},
				},
			}, nil)

			r := httptest.NewRequest("GET", "http://example.com/foo", nil)
			w := httptest.NewRecorder()

			q := NewQuery(&qi, nil, nil)
			q.Metrics(w, r)

			resp := w.Result()
			Expect(resp).NotTo(BeNil())
			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(body)).To(Equal(expectedMetrics))
		})

		It("should write nothing when query interface failed to query", func() {
			qi := client.MockQueryInterface{}
			qi.On("RunQuery", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("RunQuery failed"))

			r := httptest.NewRequest("GET", "http://example.com/foo", nil)
			w := httptest.NewRecorder()

			q := NewQuery(&qi, nil, nil)
			q.Metrics(w, r)

			resp := w.Result()
			Expect(resp).NotTo(BeNil())
			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(body)).To(Equal(""))
		})

		It("should write nothing when response isn't of type QueryClusterResp", func() {
			qi := client.MockQueryInterface{}
			qi.On("RunQuery", mock.Anything, mock.Anything).Return(nil, nil)

			r := httptest.NewRequest("GET", "http://example.com/foo", nil)
			w := httptest.NewRecorder()

			q := NewQuery(&qi, nil, nil)
			q.Metrics(w, r)

			resp := w.Result()
			Expect(resp).NotTo(BeNil())
			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(body)).To(Equal(""))
		})
	})

	Context("Summary request header parsing", func() {

		It("should get validate Authorization token from request header", func() {
			q := query{qi: &client.MockQueryInterface{}, cfg: nil}
			r := httptest.NewRequest("GET", "http://example.com/foo", nil)

			token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			t := q.getToken(r)
			Expect(t).To(Equal(token))
		})

		It("should return an empty string when Authorization token is invalid", func() {
			q := query{qi: &client.MockQueryInterface{}, cfg: nil}
			r := httptest.NewRequest("GET", "http://example.com/foo", nil)

			token := "invalid-token"
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

			t := q.getToken(r)
			Expect(t).To(Equal(""))
		})

		It("should return a timestamp when to is valid in the request query parameter list", func() {
			q := query{qi: &client.MockQueryInterface{}, cfg: nil}
			r := httptest.NewRequest("GET", "http://example.com/foo", nil)

			params := r.URL.Query()
			params.Add("to", "now-5m")
			r.URL.RawQuery = params.Encode()

			ts, err := q.getTimestamp(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(ts).NotTo(BeNil())
			Expect(ts.IsZero()).To(BeFalse())
		})

		It("should return nil when to is now in the request query parameter list", func() {
			q := query{qi: &client.MockQueryInterface{}, cfg: nil}
			r := httptest.NewRequest("GET", "http://example.com/foo", nil)

			params := r.URL.Query()
			params.Add("to", "now-0m")
			r.URL.RawQuery = params.Encode()

			ts, err := q.getTimestamp(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(ts).To(BeNil())
		})

		It("should return nil when to is invalid in the request query parameter list", func() {
			q := query{qi: &client.MockQueryInterface{}, cfg: nil}
			r := httptest.NewRequest("GET", "http://example.com/foo", nil)

			// not a time
			params := make(url.Values)
			params.Add("to", "abc")
			r.URL.RawQuery = params.Encode()

			ts, err := q.getTimestamp(r)
			Expect(err).To(HaveOccurred())
			Expect(ts).To(BeNil())

			// missing to
			params = make(url.Values)
			r.URL.RawQuery = params.Encode()

			ts, err = q.getTimestamp(r)
			Expect(err).To(HaveOccurred())
			Expect(ts).To(BeNil())
		})

	})

	Context("tests parseEndpointsBody", func() {
		It("should set EndpointsList to empty string if empty string is set in the request", func() {
			reqBody := client.QueryEndpointsReqBody{
				EndpointsList: []string{},
			}

			reqBodyBytes, err := json.Marshal(reqBody)
			Expect(err).ShouldNot(HaveOccurred())

			req, err := parseEndpointsBody(reqBodyBytes)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(req.EndpointsList).NotTo(BeNil())
			Expect(req.EndpointsList).To(HaveLen(0))

		})
		It("should set EndpointsList to nil string if nil is set in the request", func() {
			reqBody := client.QueryEndpointsReqBody{
				EndpointsList: nil,
			}

			reqBodyBytes, err := json.Marshal(reqBody)
			Expect(err).ShouldNot(HaveOccurred())

			req, err := parseEndpointsBody(reqBodyBytes)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(req.EndpointsList).To(BeNil())
		})
		It("should set EndpointsList to nil string when it is not set at all", func() {
			reqBody := client.QueryEndpointsReqBody{}

			reqBodyBytes, err := json.Marshal(reqBody)
			Expect(err).ShouldNot(HaveOccurred())

			req, err := parseEndpointsBody(reqBodyBytes)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(req.EndpointsList).To(BeNil())
		})
	})

	Context("Test getPolicyFieldSelector for field selection", func() {

		It("should return the policy field selector with uid and name selected", func() {
			req := httptest.NewRequest("GET", "http://locahost:8080/policies?fields=UID,NAME", nil)

			pfs := getPolicyFieldSelector(req)
			Expect(pfs["uid"]).To(BeTrue())
			Expect(pfs["name"]).To(BeTrue())
			Expect(pfs["namespace"]).To(BeFalse())

		})

		It("should return the nil as policy field selector when \"fields\" is not passed in the url", func() {
			req := httptest.NewRequest("GET", "http://locahost:8080/policies", nil)

			pfs := getPolicyFieldSelector(req)

			Expect(pfs).To(BeNil())
		})

		It("should return the policy field selector with nothing selected if \"fields\" is passed but not set", func() {
			req := httptest.NewRequest("GET", "http://locahost:8080/policies?fields", nil)

			pfs := getPolicyFieldSelector(req)

			Expect(len(pfs)).To(Equal(0))
		})

	})

	Context("parseTimeRange", func() {
		It("should return nil from and to when neither is provided", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(from).To(BeNil())
			Expect(to).To(BeNil())
		})

		It("should parse valid RFC3339 from and to parameters", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(from).NotTo(BeNil())
			Expect(to).NotTo(BeNil())
			Expect(from.Year()).To(Equal(2026))
			Expect(to.Day()).To(Equal(2))
		})

		It("should return error for invalid from parameter", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?from=not-a-date", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid 'from' parameter"))
			Expect(from).To(BeNil())
			Expect(to).To(BeNil())
		})

		It("should return error for invalid to parameter", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?to=not-a-date", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid 'to' parameter"))
			Expect(from).To(BeNil())
			Expect(to).To(BeNil())
		})

		It("should parse from alone without to", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?from=2026-03-01T12:00:00Z", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(from).NotTo(BeNil())
			Expect(to).To(BeNil())
		})

		It("should parse to alone without from", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?to=2026-03-01T12:00:00Z", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(from).To(BeNil())
			Expect(to).NotTo(BeNil())
		})

		It("should return error when to is before from", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("'to' is before 'from'"))
			Expect(from).To(BeNil())
			Expect(to).To(BeNil())
		})

		It("should accept when from equals to", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?from=2026-01-01T00:00:00Z&to=2026-01-01T00:00:00Z", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(from).NotTo(BeNil())
			Expect(to).NotTo(BeNil())
			Expect(from.Equal(*to)).To(BeTrue())
		})

		It("should parse relative time formats like now-15m", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?from=now-15m&to=now-0m", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(from).NotTo(BeNil())
			Expect(to).NotTo(BeNil())
			Expect(to.After(*from)).To(BeTrue())
		})

		It("should parse 'now' as a valid time", func() {
			r := httptest.NewRequest("GET", "http://example.com/policies?from=now-1h&to=now", nil)
			from, to, err := parseTimeRange(r)
			Expect(err).NotTo(HaveOccurred())
			Expect(from).NotTo(BeNil())
			Expect(to).NotTo(BeNil())
			Expect(to.After(*from)).To(BeTrue())
		})
	})

})
