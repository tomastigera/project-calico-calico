// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package httputils_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/olivere/elastic/v7"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/projectcalico/calico/lma/pkg/httputils"
)

const (
	validRequestBody = `
{
  "cluster": "c_val",
  "page_size": 152,
  "search_after": "sa_val"
}`
	badlyFormedAtPosisitonRequestBody = `
{
  "cluster": c_val,
  "page_size": 152,
  "search_after": "sa_val"
}`
	badlyFormedRequestBody = `
{
  "cluster": "c_val",
  "page_size": 152,
  "search_after": "sa_val"
`
	invalidValueRequestBody = `
{
  "cluster": "c_val",
  "page_size": "152",
  "search_after": "sa_val"
}`
	tooManyJsonsInRequestBody = `
{
  "cluster": "c_val",
  "page_size": 152, 
  "search_after": "sa_val"
}
{
  "cluster": "c2_val",
  "page_size": 156,
  "search_after": "sa2_val"
}`

	unknownFieldRequestBody = `
{
  "invalid_cluster_key": "c_val",
  "page_size": 152,
  "search_after": "sa_val"
}`
)

// testparams is used for testing decoding.
type testparams struct {
	ClusterName string `json:"cluster" validate:"omitempty"`
	Selector    string `json:"selector" validate:"omitempty"`
	PageSize    int    `json:"page_size" validate:"gte=0,lte=1000"`
	SearchAfter any    `json:"search_after" validate:"omitempty"`
}

var _ = Describe("Test /httputils/encoder", func() {
	Context("Test that the request body decode function behaves as expected", func() {
		It("Should return an error if the json is badly formed in the request body", func() {
			r, err := http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte(badlyFormedAtPosisitonRequestBody)))
			Expect(err).NotTo(HaveOccurred())

			var params testparams
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, r, &params)
			Expect(decodeError).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(true).To(BeEquivalentTo(errors.As(decodeError, &mr)))
			Expect(400).To(BeEquivalentTo(mr.Status))
			Expect("Request body contains badly-formed JSON (at position 17)").To(BeEquivalentTo(mr.Msg))
			Expect("invalid character 'c' looking for beginning of value").To(BeEquivalentTo(mr.Err.Error()))
		})

		It("Should return an error if the json is badly formed in the request body", func() {
			r, err := http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte(badlyFormedRequestBody)))
			Expect(err).NotTo(HaveOccurred())

			var params testparams
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, r, &params)
			Expect(decodeError).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(true).To(BeEquivalentTo(errors.As(decodeError, &mr)))
			Expect(400).To(BeEquivalentTo(mr.Status))
			Expect("Request body contains badly-formed JSON").To(BeEquivalentTo(mr.Msg))
			Expect(io.ErrUnexpectedEOF).To(BeEquivalentTo(mr.Err))
		})

		It("Should return an error if the json is badly formed in the request body", func() {
			data :=
				struct {
					ClusterName     string `json:"cluster"`
					InvalidPageSize string `json:"page_size"`
					SarchAfter      any    `json:"search_after"`
				}{}
			umerr := json.Unmarshal([]byte(invalidValueRequestBody), &data)
			Expect(umerr).ShouldNot(HaveOccurred())
			s, _ := json.Marshal(data)
			r, err := http.NewRequest(http.MethodGet, "", bytes.NewReader(s))
			Expect(err).NotTo(HaveOccurred())

			var params testparams
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, r, &params)
			Expect(decodeError).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(true).To(BeEquivalentTo(errors.As(decodeError, &mr)))
			Expect(400).To(BeEquivalentTo(mr.Status))
			Expect("Request body contains an invalid value for the \"page_size\" field (at position 36)").To(BeEquivalentTo(mr.Msg))
			Expect("json: cannot unmarshal string into Go struct field testparams.page_size of type int").To(BeEquivalentTo(mr.Err.Error()))
		})

		It("Should return an error if there is an unknown field in the request body", func() {
			data :=
				struct {
					ClusterName string `json:"invalid_cluster_key"`
					PageSize    int    `json:"page_size"`
					SarchAfter  any    `json:"search_after"`
				}{}
			umerr := json.Unmarshal([]byte(unknownFieldRequestBody), &data)
			Expect(umerr).ShouldNot(HaveOccurred())
			s, _ := json.Marshal(data)
			r, err := http.NewRequest(http.MethodGet, "", bytes.NewReader(s))
			Expect(err).NotTo(HaveOccurred())

			var params testparams
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, r, &params)
			Expect(decodeError).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(true).To(BeEquivalentTo(errors.As(decodeError, &mr)))
			Expect(400).To(BeEquivalentTo(mr.Status))
			Expect("Request body contains unknown field \"invalid_cluster_key\"").To(BeEquivalentTo(mr.Msg))
			Expect(httputils.ErrJsonUnknownField).To(BeEquivalentTo(mr.Err))
		})

		It("Should return an error if the request body is empty (nil)", func() {
			r, err := http.NewRequest(http.MethodGet, "", bytes.NewReader(nil))
			Expect(err).NotTo(HaveOccurred())
			var params testparams
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, r, &params)
			Expect(decodeError).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(true).To(BeEquivalentTo(errors.As(decodeError, &mr)))
			Expect(400).To(BeEquivalentTo(mr.Status))
			Expect("Request body must not be empty").To(BeEquivalentTo(mr.Msg))
			Expect(io.EOF).To(BeEquivalentTo(mr.Err))
		})

		It("Should return an error if the request body exceeds 1Mb in size", func() {
			data := struct {
				Field1 string   `json:"field1"`
				Field2 int      `json:"field2"`
				Field3 []string `json:"field3"`
			}{}

			// Create JSON object of size gt 1Mb.
			field3Size := 100000
			data.Field1 = "val_field1"
			data.Field2 = 5
			data.Field3 = make([]string, field3Size)
			for i := range field3Size {
				data.Field3[i] = fmt.Sprintf("val_field3_%d", i)
			}

			s, _ := json.Marshal(data)
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader(s))
			Expect(err).NotTo(HaveOccurred())

			var params struct {
				Field1 string   `json:"field1"`
				Field2 int      `json:"field2"`
				Field3 []string `json:"field3"`
			}
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, req, &params)
			Expect(decodeError).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(true).To(BeEquivalentTo(errors.As(decodeError, &mr)))
			Expect(413).To(BeEquivalentTo(mr.Status))
			Expect("Request body must not be larger than 1MB").To(BeEquivalentTo(mr.Msg))
			Expect(httputils.ErrHttpRequestBodyTooLarge).To(BeEquivalentTo(mr.Err))
		})

		It("Should return an error if the request body contains more than one JSON object", func() {
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte(tooManyJsonsInRequestBody)))
			Expect(err).NotTo(HaveOccurred())

			var params testparams
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, req, &params)
			Expect(decodeError).To(HaveOccurred())

			var mr *httputils.HttpStatusError
			Expect(true).To(BeEquivalentTo(errors.As(decodeError, &mr)))
			Expect(400).To(BeEquivalentTo(mr.Status))
			Expect("Request body must only contain a single JSON object").To(BeEquivalentTo(mr.Msg))
			Expect(httputils.ErrTooManyJsonObjectsInRequestBody).To(BeEquivalentTo(mr.Err))
		})

		It("Should return a valid set of parameters", func() {
			data := testparams{}
			umerr := json.Unmarshal([]byte(validRequestBody), &data)
			Expect(umerr).ShouldNot(HaveOccurred())
			s, _ := json.Marshal(data)
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader(s))
			Expect(err).NotTo(HaveOccurred())

			var params testparams
			var w http.ResponseWriter
			decodeError := httputils.Decode(w, req, &params)
			Expect(decodeError).ToNot(HaveOccurred())
			Expect(params.ClusterName).To(BeEquivalentTo("c_val"))
			Expect(params.PageSize).To(BeEquivalentTo(152))
			Expect(params.SearchAfter).To(BeEquivalentTo("sa_val"))
		})
	})

	Context("Test that the request body encode function behaves as expected", func() {
		It("Should encode the parameters without panicing", func() {
			data := testparams{}
			umerr := json.Unmarshal([]byte(validRequestBody), &data)
			Expect(umerr).ShouldNot(HaveOccurred())
			s, _ := json.Marshal(data)
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader(s))
			Expect(err).NotTo(HaveOccurred())

			var params testparams
			w := httptest.NewRecorder()

			decodeError := httputils.Decode(w, req, &params)
			Expect(decodeError).ToNot(HaveOccurred())
			Expect(params.ClusterName).To(BeEquivalentTo("c_val"))
			Expect(params.PageSize).To(BeEquivalentTo(152))
			Expect(params.SearchAfter).To(BeEquivalentTo("sa_val"))

			httputils.Encode(w, params)
		})
	})

	Context("Test that EncodeError encodes correctly", func() {
		It("Should encode a Kubernetes Status", func() {
			w := httptest.NewRecorder()
			err := kerrors.NewBadRequest("some reason or other")
			httputils.EncodeError(w, err)
			Expect(w.Code).To(Equal(http.StatusBadRequest))
			Expect(strings.TrimSpace(w.Body.String())).To(Equal("some reason or other"))
		})

		It("Should encode an elastic error", func() {
			w := httptest.NewRecorder()
			err := &elastic.Error{
				Status: http.StatusBadGateway,
			}
			httputils.EncodeError(w, err)
			Expect(w.Code).To(Equal(http.StatusBadGateway))
			Expect(strings.TrimSpace(w.Body.String())).To(Equal("elastic: Error 502 (Bad Gateway)"))
		})

		It("Should encode an HttpStatusError error", func() {
			w := httptest.NewRecorder()
			err := &httputils.HttpStatusError{
				Status: http.StatusConflict,
				Msg:    "something",
			}
			httputils.EncodeError(w, err)
			Expect(w.Code).To(Equal(http.StatusConflict))
			Expect(strings.TrimSpace(w.Body.String())).To(Equal("something"))
		})

		It("Should encode a generic error", func() {
			w := httptest.NewRecorder()
			err := errors.New("it's an error")
			httputils.EncodeError(w, err)
			Expect(w.Code).To(Equal(http.StatusInternalServerError))
			Expect(strings.TrimSpace(w.Body.String())).To(Equal("it's an error"))
		})
	})
})
