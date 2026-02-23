// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jwt"
	"github.com/felixge/httpsnoop"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request Metrics", func() {

	Context("http request handling", func() {

		mux := http.NewServeMux()
		mux.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
		})
		mux.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(302)
		})
		mux.HandleFunc("/baz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
		})
		mux.HandleFunc("/qux", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		})

		mux.Handle("/metrics", NewHandler())

		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var authToken jwt.JWT

			fakeAuthSub := r.Header.Get("FakeAuthSub")
			if fakeAuthSub != "" {
				authToken = newFakeJWT(fakeAuthSub)
			}

			var httpSnoopMetrics httpsnoop.Metrics

			onRequestEnd := OnRequestStart(r, authToken)
			defer onRequestEnd(&httpSnoopMetrics)

			httpSnoopMetrics = httpsnoop.CaptureMetricsFn(w, func(w http.ResponseWriter) {
				mux.ServeHTTP(w, r)
			})
		})

		httpServer := httptest.NewServer(handler)
		httpClient := httpServer.Client()

		doReq := func(path string, sub string) int {
			req, err := http.NewRequest(http.MethodGet, httpServer.URL+path, nil)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())

			if sub != "" {
				req.Header.Set("FakeAuthSub", sub)
			}

			resp, err := httpClient.Do(req)
			ExpectWithOffset(1, err).ToNot(HaveOccurred())

			return resp.StatusCode
		}

		scrapeMetrics := func() []string {
			resp, err := http.Get(httpServer.URL + "/metrics")
			ExpectWithOffset(2, err).ToNot(HaveOccurred())
			respBody, err := io.ReadAll(resp.Body)
			ExpectWithOffset(2, err).ToNot(HaveOccurred())
			ExpectWithOffset(2, resp.StatusCode).To(Equal(http.StatusOK))
			lines := strings.Split(string(respBody), "\n")
			var result []string
			for _, line := range lines {
				if strings.HasPrefix(line, "http_request") {
					result = append(result, line)
				}
			}
			return result
		}

		expectMetrics := func(expected ...string) {
			results := scrapeMetrics()
			for _, e := range expected {
				ExpectWithOffset(1, results).To(ContainElement(e))
			}
		}

		When("anonymous request", func() {
			It("should record metrics for user '-'", func() {
				Expect(doReq("/foo", "")).To(Equal(201))
				Expect(doReq("/foo?watch=true", "")).To(Equal(201))
				expectMetrics(
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"2XX\",svcAcc=\"-\"} 1",
					"http_request_statuses_total{long=\"true\",method=\"GET\",statusCategory=\"2XX\",svcAcc=\"-\"} 1",
					"http_requests_total{long=\"false\",method=\"GET\",svcAcc=\"-\"} 2", // first request + /metrics request
					"http_requests_total{long=\"true\",method=\"GET\",svcAcc=\"-\"} 1",
					"http_requests_inflight{long=\"false\",method=\"GET\",svcAcc=\"-\"} 1", // metrics request
					"http_requests_inflight{long=\"true\",method=\"GET\",svcAcc=\"-\"} 0",
				)
				Expect(doReq("/bar", "")).To(Equal(302))
				Expect(doReq("/qux", "")).To(Equal(500))
				Expect(doReq("/qux", "")).To(Equal(500))
				expectMetrics(
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"3XX\",svcAcc=\"-\"} 1",
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"5XX\",svcAcc=\"-\"} 2",
				)
				Expect(doReq("/qux", "")).To(Equal(500))
				expectMetrics(
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"3XX\",svcAcc=\"-\"} 1",
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"5XX\",svcAcc=\"-\"} 3",
				)
			})
		})
		When("no cluster id header is supplied", func() {
			It("should default to 'cluster'", func() {
				Expect(doReq("/baz", "")).To(Equal(403))
				expectMetrics(
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"4XX\",svcAcc=\"-\"} 1",
				)
			})
		})
		When("a request from an email address", func() {
			It("should have svcAcc of 'non-sa' ", func() {
				Expect(doReq("/bar", "test@acme.com")).To(Equal(302))
				expectMetrics(
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"3XX\",svcAcc=\"non-sa\"} 1",
				)
			})
		})
		When("a request from a service account", func() {
			It("should have shortened svcAcc", func() {
				Expect(doReq("/baz", "system:serviceaccount:foo:bar")).To(Equal(403))
				expectMetrics(
					"http_request_statuses_total{long=\"false\",method=\"GET\",statusCategory=\"4XX\",svcAcc=\"s:sa:foo:bar\"} 1",
				)
			})
		})
	})

})

type fakeJWT struct {
	claims map[string]any
}

func newFakeJWT(sub string) *fakeJWT {
	return &fakeJWT{claims: map[string]any{
		"sub": sub,
	}}
}

func (f *fakeJWT) Claims() jwt.Claims {
	return f.claims
}

func (f *fakeJWT) Validate(_ any, _ crypto.SigningMethod, _ ...*jwt.Validator) error {
	panic("implement me")
}

func (f *fakeJWT) Serialize(_ any) ([]byte, error) {
	panic("implement me")
}
