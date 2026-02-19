// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package kibana

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	calicojson "github.com/projectcalico/calico/ui-apis/test/json"
)

var _ = Describe("client", func() {
	Context("Login", func() {
		var (
			currentURL = "https://localhost:9443/"
			username   = "username"
			password   = "password"
		)

		It("returns the Kibana response on a successful request", func() {
			var wg sync.WaitGroup
			wg.Add(1)

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer GinkgoRecover()
				defer wg.Done()
				defer func() { _ = r.Body.Close() }()

				body, err := io.ReadAll(r.Body)
				Expect(err).ShouldNot(HaveOccurred())

				Expect(calicojson.MustUnmarshalToStandObject(body)).Should(Equal(map[string]interface{}{
					"currentURL":   currentURL,
					"providerName": "basic",
					"providerType": "basic",
					"params": map[string]interface{}{
						"username": username,
						"password": password,
					},
				}))

				Expect(r.Header.Get("kbn-xsrf")).Should(Equal("true"))

				http.SetCookie(w, &http.Cookie{Name: "testcookie", Value: "testvalue"})

				w.WriteHeader(http.StatusOK)
			}))

			cli := NewClient(&http.Client{
				Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			}, ts.URL)

			response, err := cli.Login(currentURL, username, password)

			wg.Wait()

			Expect(err).ShouldNot(HaveOccurred())
			Expect(response).ShouldNot(BeNil())
			Expect(response.StatusCode).Should(Equal(200))
			Expect(len(response.Cookies())).Should(Equal(1))
		})

		It("returns an error if the request failed with an error", func() {
			cli := NewClient(&http.Client{
				Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			}, "http://does-not-exist")

			_, err := cli.Login(currentURL, username, password)
			Expect(err).Should(HaveOccurred())
		})
	})
})
