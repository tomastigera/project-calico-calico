// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

package http

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"unsafe"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/fluent-bit/plugins/out_linseed/pkg/config"
)

var (
	//go:embed testdata/ca.crt
	caCert string
	//go:embed testdata/kubeconfig_cert-auth.template
	kubeconfigCertAuthTemplate string
)

var _ = Describe("Linseed out plugin http tests", func() {
	var (
		client            *Client
		f                 *os.File
		mockTokenProvider *MockTokenProvider
		ndjsonBuffer      bytes.Buffer
	)

	BeforeEach(func() {
		// mock token provider
		mockTokenProvider = NewMockTokenProvider(GinkgoT())

		// fake payload
		ndjsonBuffer.Write([]byte(`{"record":1}\n{"record":2}\n`))

		// http client
		var err error
		client, f, err = newHTTPClient(validKubeconfig)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		err := os.Remove(f.Name())
		Expect(err).NotTo(HaveOccurred())
	})

	Context("http request tests", func() {
		It("should send expected requests", func() {
			mockTokenProvider.On("Token").Return("some-token", nil)

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

			client.Client = server.Client()
			client.tokenProvider = mockTokenProvider
			err := client.Do(server.URL, "flows", &ndjsonBuffer)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return error when log type is unexpected", func() {
			err := client.Do("https://1.2.3.4:5678", "unknown-log-type", &ndjsonBuffer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(`unknown log type "unknown-log-type"`))
		})

		It("should return error when http response is not ok", func() {
			mockTokenProvider.On("Token").Return("some-token", nil)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer server.Close()

			client.Client = server.Client()
			client.tokenProvider = mockTokenProvider
			err := client.Do(server.URL, "flows", &ndjsonBuffer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error response from server"))
		})

		It("should return error when token provider fails", func() {
			mockTokenProvider.On("Token").Return("", fmt.Errorf("token provider error"))

			client.tokenProvider = mockTokenProvider
			err := client.Do("https://1.2.3.4:5678", "flows", &ndjsonBuffer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("token provider error"))
		})

		It("should refresh token when http response is 401", func() {
			mockTokenProvider.On("Refresh").Return("new-token", nil)
			mockTokenProvider.On("Token").Return("some-token", nil)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()

			client.Client = server.Client()
			client.tokenProvider = mockTokenProvider
			err := client.Do(server.URL, "flows", &ndjsonBuffer)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("error response from server"))
			Expect(mockTokenProvider.AssertCalled(GinkgoT(), "Refresh")).To(BeTrue())
		})
	})

	Context("http client cert pool tests", func() {
		It("should add kubeconfig certificate-authority-data to the cert pool", func() {
			transport, ok := client.Transport.(*http.Transport)
			Expect(ok).To(BeTrue())
			Expect(transport).NotTo(BeNil())
			Expect(transport.TLSClientConfig).NotTo(BeNil())

			certPool := transport.TLSClientConfig.RootCAs
			Expect(certPool).NotTo(BeNil())

			found := false
			//nolint:staticcheck // Ignore SA1019 deprecated
			for _, subject := range certPool.Subjects() {
				if bytes.Contains(subject, []byte("jiawei-root-signer")) {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should add kubeconfig certificate-authority to the cert pool", func() {
			// write ca.cert to a temporary file
			caCertFile, err := os.CreateTemp("", "ca.crt")
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = os.Remove(caCertFile.Name()) }()

			_, err = caCertFile.WriteString(caCert)
			Expect(err).NotTo(HaveOccurred())
			err = caCertFile.Close()
			Expect(err).NotTo(HaveOccurred())

			// recreate the http client with the new kubeconfig
			client, f, err = newHTTPClient(fmt.Sprintf(kubeconfigCertAuthTemplate, caCertFile.Name()))
			Expect(err).NotTo(HaveOccurred())

			transport, ok := client.Transport.(*http.Transport)
			Expect(ok).To(BeTrue())
			Expect(transport).NotTo(BeNil())
			Expect(transport.TLSClientConfig).NotTo(BeNil())

			certPool := transport.TLSClientConfig.RootCAs
			Expect(certPool).NotTo(BeNil())

			found := false
			//nolint:staticcheck // Ignore SA1019 deprecated
			for _, subject := range certPool.Subjects() {
				if bytes.Contains(subject, []byte("jiawei-root-signer")) {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})
	})
})

func newHTTPClient(kubeconfig string) (*Client, *os.File, error) {
	f, err := os.CreateTemp("", "kubeconfig")
	Expect(err).NotTo(HaveOccurred())
	_, err = f.WriteString(kubeconfig)
	Expect(err).NotTo(HaveOccurred())
	err = f.Close()
	Expect(err).NotTo(HaveOccurred())

	err = os.Setenv("KUBECONFIG", f.Name())
	Expect(err).NotTo(HaveOccurred())
	err = os.Setenv("ENDPOINT", "https://1.2.3.4:5678")
	Expect(err).NotTo(HaveOccurred())

	cfg, err := config.NewConfig(nil, func(plugin unsafe.Pointer, key string) string {
		if key == "tls.verify" {
			return "true"
		}
		return ""
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	client, err := NewClient(cfg)
	return client, f, err
}
