// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package middleware

import (
	"bytes"
	_ "embed"
	"errors"
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/lma/pkg/httputils"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

var (
	//go:embed testdata/invalid_request_body_badly_formed_string_value.json
	invalidRequestBodyBadlyFormedStringValue string
)

var _ = Describe("Middleware utility tests", func() {
	Context("Parse cluster name from request header", func() {
		It("should parse cluster name when x-cluster-id is set in header", func() {
			req, err := http.NewRequest("GET", "http://some-url", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Add("x-cluster-id", "test-cluster-name")
			clusterName := MaybeParseClusterNameFromRequest(req)
			Expect(clusterName).To(Equal("test-cluster-name"))
		})

		It("should return default cluster name when x-cluster-id is not set in header", func() {
			req, err := http.NewRequest("GET", "http://some-url", nil)
			Expect(err).NotTo(HaveOccurred())
			clusterName := MaybeParseClusterNameFromRequest(req)
			Expect(clusterName).To(Equal("cluster"))
		})

		It("should return default cluster name when request is nil", func() {
			clusterName := MaybeParseClusterNameFromRequest(nil)
			Expect(clusterName).To(Equal("cluster"))
		})
	})

	Context("parseBody response validation", func() {
		It("Should return a HttpStatusError when parsing a http status error body", func() {
			r, err := http.NewRequest(
				http.MethodGet, "", bytes.NewReader([]byte(invalidRequestBodyBadlyFormedStringValue)))
			Expect(err).NotTo(HaveOccurred())

			var w http.ResponseWriter
			_, err = ParseBody[v1.CommonSearchRequest](w, r)
			Expect(err).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(errors.As(err, &mr)).To(BeTrue())
		})
	})
})
