package middlewares

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func OKFunc(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

var _ = Describe("cve mitigation", func() {

	var (
		handler  http.Handler
		recorder *httptest.ResponseRecorder
	)

	BeforeEach(func() {
		recorder = httptest.NewRecorder()
		handler = RejectUnacceptableContentTypeHandler(http.HandlerFunc(OKFunc))
	})

	DescribeTable("test CVE-2020-28491", func(method, url, contentType string, expectedStatusCode int) {
		var req, err = http.NewRequest(method, url, nil)
		Expect(err).NotTo(HaveOccurred())
		if contentType != "" {
			req.Header = http.Header{}
			req.Header.Add("CoNteNt-TyPe", contentType) // Oddly cased as to prove that our code is case-insensitive.

		}
		handler.ServeHTTP(recorder, req)
		Expect(recorder.Code).To(Equal(expectedStatusCode))
	},
		Entry("should reject cbor requests", "POST", "", contentTypeApplicationCBOR, http.StatusUnsupportedMediaType),
		Entry("should reject cbor requests", "PUT", "", contentTypeApplicationCBOR, http.StatusUnsupportedMediaType),
		Entry("should reject cbor requests", "GET", "", contentTypeApplicationCBOR, http.StatusUnsupportedMediaType),
		Entry("should reject cbor requests", "PANCAKE", "", contentTypeApplicationCBOR, http.StatusUnsupportedMediaType),
		Entry("should reject cbor requests to other endpoints", "PUT", "/my-index", contentTypeApplicationCBOR, http.StatusUnsupportedMediaType),

		Entry("should reject smile requests", "POST", "", contentTypeApplicationSMILE, http.StatusUnsupportedMediaType),
		Entry("should reject smile requests", "PUT", "", contentTypeApplicationSMILE, http.StatusUnsupportedMediaType),
		Entry("should reject smile requests", "GET", "", contentTypeApplicationSMILE, http.StatusUnsupportedMediaType),
		Entry("should reject smile requests", "PANCAKE", "", contentTypeApplicationSMILE, http.StatusUnsupportedMediaType),
		Entry("should reject smile requests to other endpoints", "PUT", "/my-index", contentTypeApplicationSMILE, http.StatusUnsupportedMediaType),

		Entry("should reject cbor requests regardless of casing", "POST", "", "APPLICATION/CBOR", http.StatusUnsupportedMediaType),
		Entry("should reject cbor requests regardless of casing", "POST", "", "APPLICation/CBOR", http.StatusUnsupportedMediaType),
		Entry("should reject smile requests regardless of casing", "POST", "", "APPLICATION/SMILE", http.StatusUnsupportedMediaType),
		Entry("should reject smile requests regardless of casing", "POST", "", "APPLICATION/smile", http.StatusUnsupportedMediaType),

		Entry("should accept json requests", "POST", "", "application/json", http.StatusOK),
		Entry("should accept json requests", "GET", "", "application/json", http.StatusOK),
		Entry("should accept json requests regardless of casing", "GET", "", "APPLICATION/JSON", http.StatusOK),
		Entry("should not panic on nil pointer when no header is added", "POST", "", "", http.StatusOK),
	)
})
