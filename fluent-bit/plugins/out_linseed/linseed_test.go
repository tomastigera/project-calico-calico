// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package main

import (
	"bytes"
	_ "embed"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Linseed out plugin tests", func() {
	var (
		f            *os.File
		ndjsonBuffer bytes.Buffer
	)

	BeforeEach(func() {
		var err error
		f, err = os.CreateTemp("", "kubeconfig")
		Expect(err).NotTo(HaveOccurred())

		ndjsonBuffer.Write([]byte(`{"record":1}\n{"record":2}\n`))
	})

	AfterEach(func() {
		os.Remove(f.Name())
	})

	Context("http request tests", func() {
		It("should send expected requests", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.URL.Path).To(Equal("/ingestion/api/v1/flows/logs/bulk"))
				Expect(r.Header).To(HaveKeyWithValue("Authorization", []string{"Bearer some-token"}))
				Expect(r.Header).To(HaveKeyWithValue("Content-Type", []string{"application/x-ndjson"}))

				bytes, err := io.ReadAll(r.Body)
				Expect(err).NotTo(HaveOccurred())
				Expect(string(bytes)).To(Equal(`{"record":1}\n{"record":2}\n`))

				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client = server.Client()
			err := doRequest(server.URL, "flows", "some-token", &ndjsonBuffer)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return error when log type is unexpected", func() {
			err := doRequest("https://1.2.3.4:5678", "unknown-log-type", "some-token", &ndjsonBuffer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`unknown log type "unknown-log-type"`))
		})

		It("should return error when http response is not ok", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer server.Close()

			client = server.Client()
			err := doRequest(server.URL, "flows", "some-token", &ndjsonBuffer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error response from server"))
		})
	})
})
