// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/packetcapture/pkg/middleware"
)

var _ = Describe("Parser", func() {
	type expectedResponse struct {
		ns        string
		name      string
		clusterID string
		body      string
		action    string
		status    int
	}
	DescribeTable("Validate download requests",
		func(url, method, xClusterID string, expected expectedResponse) {
			var req, err = http.NewRequest(method, url, nil)
			req.Header.Set(lmak8s.XClusterIDHeader, xClusterID)
			Expect(err).NotTo(HaveOccurred())

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Expect namespace, name and cluster ID to be set on the context
				Expect(middleware.NamespaceFromContext(r.Context())).To(Equal(expected.ns))
				Expect(middleware.CaptureNameFromContext(r.Context())).To(Equal(expected.name))
				Expect(middleware.ClusterIDFromContext(r.Context())).To(Equal(expected.clusterID))
				Expect(middleware.ActionIDFromContext(r.Context())).To(Equal(expected.action))
			})

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := middleware.Parse(testHandler)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(expected.status))
			Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal(expected.body))
		},
		Entry("Malformed request", "/$534/$  ", "GET", "",
			expectedResponse{ns: "", name: "", clusterID: lmak8s.DefaultCluster,
				body: "request URL is malformed", status: http.StatusBadRequest}),
		Entry("Missing prefix", "/", "GET", "",
			expectedResponse{ns: "", name: "", clusterID: lmak8s.DefaultCluster,
				body: "request URL is malformed", status: http.StatusBadRequest}),
		Entry("Missing namespace and name", "/download", "GET", "",
			expectedResponse{ns: "", name: "", clusterID: lmak8s.DefaultCluster,
				body: "request URL is malformed", status: http.StatusBadRequest}),
		Entry("Missing namespace", "/download/ns", "GET", "",
			expectedResponse{ns: "ns", name: "", clusterID: lmak8s.DefaultCluster,
				body: "request URL is malformed", status: http.StatusBadRequest}),
		Entry("Missing query", "/download/ns/name", "GET", "",
			expectedResponse{ns: "ns", name: "name", clusterID: lmak8s.DefaultCluster,
				body: "request URL is malformed", status: http.StatusBadRequest}),
		Entry("Invalid query", "/download/ns/name/file=abc", "GET", "",
			expectedResponse{ns: "ns", name: "name", clusterID: lmak8s.DefaultCluster,
				body: "request URL is malformed", status: http.StatusBadRequest}),
		Entry("Ok for default cluster", "/download/ns/name/files.zip", "GET", "",
			expectedResponse{ns: "ns", name: "name", clusterID: lmak8s.DefaultCluster,
				body: "", action: middleware.GET, status: http.StatusOK}),
		Entry("Ok for other cluster", "/download/ns/name/files.zip", "GET", "otherCluster",
			expectedResponse{ns: "ns", name: "name", clusterID: "otherCluster",
				body: "", action: middleware.GET, status: http.StatusOK}),
		Entry("Invalid query", "/files/ns/name/file=abc", "DELETE", "",
			expectedResponse{ns: "ns", name: "name", clusterID: lmak8s.DefaultCluster,
				body: "request URL is malformed", status: http.StatusBadRequest}),
		Entry("Ok for default cluster", "/files/ns/name", "DELETE", "",
			expectedResponse{ns: "ns", name: "name", clusterID: lmak8s.DefaultCluster,
				body: "", action: middleware.DELETE, status: http.StatusOK}),
		Entry("Ok for other cluster", "/files/ns/name", "DELETE", "otherCluster",
			expectedResponse{ns: "ns", name: "name", clusterID: "otherCluster",
				body: "", action: middleware.DELETE, status: http.StatusOK}),
	)
})
