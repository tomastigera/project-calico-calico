// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package event

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/test/thirdpartymock"
)

var (
	// requests from manager to ui-apis
	//go:embed testdata/event_delete_request_from_manager.json
	eventDeleteRequest []byte
	//go:embed testdata/event_dismiss_request_from_manager.json
	eventDismissRequest []byte
	//go:embed testdata/event_restore_request_from_manager.json
	eventRestoreRequest []byte
	//go:embed testdata/event_mixed_request_from_manager.json
	eventMixedRequest []byte
	//go:embed testdata/event_bulk_missing_field.json
	eventBulkMissingField []byte

	// responses from linseed to ui-apis
	//go:embed testdata/event_bulk_delete_response.json
	eventBulkDeleteResponse []byte
	//go:embed testdata/event_bulk_dismiss_response.json
	eventBulkDismissResponse []byte
	//go:embed testdata/event_bulk_restore_response.json
	eventBulkRestoreResponse []byte

	eventsMixedDismissResponse string = `{
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "errors": [{"resource": "id4", "type": "", "reason": "it failed"}],
  "created": null,
  "updated": [
	  {"id": "id2", "status": 200},
	  {"id": "id4", "status": 404},
	  {"id": "id6", "status": 200}
  ]
}`

	eventsMixedRestoreResponse string = `{
	"total": 3,
	"succeeded": 2,
	"failed": 1,
	"errors": [{"resource": "id8", "type": "", "reason": "it failed"}],
	"created": null,
	"updated": [
		{"id": "id7", "status": 200},
		{"id": "id8", "status": 404},
		{"id": "id9", "status": 200}
	]
  }`

	eventsMixedDelResponse string = `{
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "errors": [{"resource": "id3", "type": "", "reason": "it failed"}],
  "created": null,
  "deleted": [
	  {"id": "id1", "status": 200},
	  {"id": "id3", "status": 404},
	  {"id": "id5", "status": 200}
  ]
}`
)

var _ = Describe("Event middleware tests", func() {
	var mockDoer *thirdpartymock.MockDoer
	var lsclient client.MockClient

	BeforeEach(func() {
		mockDoer = new(thirdpartymock.MockDoer)

		lsclient = client.NewMockClient("")
	})

	AfterEach(func() {
		mockDoer.AssertExpectations(GinkgoT())
	})

	Context("Elasticsearch /events request and response validation", func() {
		It("should return a valid event bulk delete response", func() {
			// Set up a response from Linseed.
			res := rest.MockResult{Body: eventBulkDeleteResponse}
			lsclient.SetResults(res)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(eventDeleteRequest))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := EventHandler(lsclient)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.BulkEventResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Errors).To(BeTrue())
			Expect(len(resp.Items)).To(Equal(3))

			Expect(resp.Items[0].ID).To(Equal("id1"))
			Expect(resp.Items[0].Result).To(Equal("deleted"))
			Expect(resp.Items[0].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[0].Error).To(BeNil())

			Expect(resp.Items[1].ID).To(Equal("id2"))
			Expect(resp.Items[1].Status).To(Equal(http.StatusNotFound))
			Expect(resp.Items[1].Error).NotTo(BeNil())
			Expect(resp.Items[1].Error.Type).To(Equal("unknown"))

			Expect(resp.Items[2].ID).To(Equal("id3"))
			Expect(resp.Items[2].Result).To(Equal("deleted"))
			Expect(resp.Items[2].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[2].Error).To(BeNil())
		})

		It("should return a valid event bulk dismiss response", func() {
			// Set up a response from Linseed.
			res := rest.MockResult{Body: eventBulkDismissResponse}
			lsclient.SetResults(res)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(eventDismissRequest))
			Expect(err).NotTo(HaveOccurred())

			Expect(lsclient.Requests()).To(BeEmpty())

			rr := httptest.NewRecorder()
			handler := EventHandler(lsclient)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.BulkEventResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Errors).To(BeTrue())
			Expect(len(resp.Items)).To(Equal(3))

			Expect(resp.Items[0].ID).To(Equal("id1"))
			Expect(resp.Items[0].Result).To(Equal("updated"))
			Expect(resp.Items[0].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[0].Error).To(BeNil())

			Expect(resp.Items[1].ID).To(Equal("id2"))
			Expect(resp.Items[1].Status).To(Equal(http.StatusNotFound))
			Expect(resp.Items[1].Error).NotTo(BeNil())
			Expect(resp.Items[1].Error.Type).To(Equal("unknown"))

			Expect(resp.Items[2].ID).To(Equal("id3"))
			Expect(resp.Items[2].Result).To(Equal("updated"))
			Expect(resp.Items[2].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[2].Error).To(BeNil())

			// Let's check that Linseed receives expected data
			lsRequests := lsclient.Requests()
			Expect(len(lsRequests)).To(Equal(1))
			lsRequest := lsRequests[0]
			body := lsRequest.GetBody().([]byte)
			data := string(body)
			Expect(data).To(ContainSubstring(`"id":`))
			Expect(data).To(ContainSubstring(`"dismissed":true`))
		})

		It("should return a valid event bulk restore response", func() {
			// Set up a response from Linseed.
			res := rest.MockResult{Body: eventBulkRestoreResponse}
			lsclient.SetResults(res)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(eventRestoreRequest))
			Expect(err).NotTo(HaveOccurred())

			Expect(lsclient.Requests()).To(BeEmpty())

			rr := httptest.NewRecorder()
			handler := EventHandler(lsclient)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.BulkEventResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Errors).To(BeTrue())
			Expect(len(resp.Items)).To(Equal(3))

			Expect(resp.Items[0].ID).To(Equal("id1"))
			Expect(resp.Items[0].Result).To(Equal("updated"))
			Expect(resp.Items[0].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[0].Error).To(BeNil())

			Expect(resp.Items[1].ID).To(Equal("id2"))
			Expect(resp.Items[1].Status).To(Equal(http.StatusNotFound))
			Expect(resp.Items[1].Error).NotTo(BeNil())
			Expect(resp.Items[1].Error.Type).To(Equal("unknown"))

			Expect(resp.Items[2].ID).To(Equal("id3"))
			Expect(resp.Items[2].Result).To(Equal("updated"))
			Expect(resp.Items[2].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[2].Error).To(BeNil())

			// Let's check that Linseed receives expected data
			lsRequests := lsclient.Requests()
			Expect(len(lsRequests)).To(Equal(1))
			lsRequest := lsRequests[0]
			body := lsRequest.GetBody().([]byte)
			data := string(body)
			Expect(data).To(ContainSubstring(`"id":`))
			// If dismissed is false, it will be omitted from the JSON :)
			Expect(data).NotTo(ContainSubstring(`"dismissed":`))
		})

		It("should return a valid event bulk mixed response", func() {
			// Set up responses from Linseed.
			resDel := rest.MockResult{Body: []byte(eventsMixedDelResponse)}
			resDis := rest.MockResult{Body: []byte(eventsMixedDismissResponse)}
			resRes := rest.MockResult{Body: []byte(eventsMixedRestoreResponse)}
			lsclient.SetResults(resDel, resDis, resRes)

			// validate responses
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(eventMixedRequest))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := EventHandler(lsclient)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusOK))

			var resp v1.BulkEventResponse
			err = json.Unmarshal(rr.Body.Bytes(), &resp)
			Expect(err).NotTo(HaveOccurred())

			Expect(resp.Errors).To(BeTrue())

			// Deleted items
			Expect(resp.Items[0].ID).To(Equal("id1"))
			Expect(resp.Items[0].Result).To(Equal("deleted"))
			Expect(resp.Items[0].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[0].Error).To(BeNil())

			Expect(resp.Items[1].ID).To(Equal("id3"))
			Expect(resp.Items[1].Status).To(Equal(http.StatusNotFound))
			Expect(resp.Items[1].Error).NotTo(BeNil())
			Expect(resp.Items[1].Error.Type).To(Equal("unknown"))

			Expect(resp.Items[2].ID).To(Equal("id5"))
			Expect(resp.Items[2].Result).To(Equal("deleted"))
			Expect(resp.Items[2].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[2].Error).To(BeNil())

			// Dismissed items
			Expect(resp.Items[3].ID).To(Equal("id2"))
			Expect(resp.Items[3].Result).To(Equal("updated"))
			Expect(resp.Items[3].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[3].Error).To(BeNil())

			Expect(resp.Items[4].ID).To(Equal("id4"))
			Expect(resp.Items[4].Status).To(Equal(http.StatusNotFound))
			Expect(resp.Items[4].Error).NotTo(BeNil())
			Expect(resp.Items[4].Error.Type).To(Equal("unknown"))

			Expect(resp.Items[5].ID).To(Equal("id6"))
			Expect(resp.Items[5].Result).To(Equal("updated"))
			Expect(resp.Items[5].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[5].Error).To(BeNil())

			// Restored items
			Expect(resp.Items[6].ID).To(Equal("id7"))
			Expect(resp.Items[6].Result).To(Equal("updated"))
			Expect(resp.Items[6].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[6].Error).To(BeNil())

			Expect(resp.Items[7].ID).To(Equal("id8"))
			Expect(resp.Items[7].Status).To(Equal(http.StatusNotFound))
			Expect(resp.Items[7].Error).NotTo(BeNil())
			Expect(resp.Items[7].Error.Type).To(Equal("unknown"))

			Expect(resp.Items[8].ID).To(Equal("id9"))
			Expect(resp.Items[8].Result).To(Equal("updated"))
			Expect(resp.Items[8].Status).To(Equal(http.StatusOK))
			Expect(resp.Items[8].Error).To(BeNil())
		})

		It("should return error when request is not POST", func() {
			req, err := http.NewRequest(http.MethodGet, "", bytes.NewReader([]byte("any")))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := EventHandler(lsclient)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusMethodNotAllowed))
		})

		It("should return error when request body is not valid", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte("invalid-json-body")))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := EventHandler(lsclient)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return error when bulk event request items are missing fields", func() {
			req, err := http.NewRequest(http.MethodPost, "", bytes.NewReader([]byte(eventBulkMissingField)))
			Expect(err).NotTo(HaveOccurred())

			rr := httptest.NewRecorder()
			handler := EventHandler(lsclient)
			handler.ServeHTTP(rr, req)

			Expect(rr.Code).To(Equal(http.StatusBadRequest))
		})
	})
})
