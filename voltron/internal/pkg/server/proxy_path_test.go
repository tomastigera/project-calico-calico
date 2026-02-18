// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package server_test

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/authentication/user"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/apiserver/pkg/authentication"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/regex"
	"github.com/projectcalico/calico/voltron/internal/pkg/server"
	"github.com/projectcalico/calico/voltron/internal/pkg/test"
)

var _ = Describe("Server supports unauthenticated targets", func() {
	var (
		fakeClient ctrlclient.WithWatch

		voltronExtHttpsCert    *x509.Certificate
		voltronExtHttpsPrivKey *rsa.PrivateKey
		voltronIntHttpsCert    *x509.Certificate
		voltronIntHttpsPrivKey *rsa.PrivateKey
		httpClient             *http.Client
	)

	BeforeEach(func() {
		var err error

		scheme := kscheme.Scheme
		err = v3.AddToScheme(scheme)
		Expect(err).NotTo(HaveOccurred())

		fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()

		voltronExtHttpCertTemplate := test.CreateServerCertificateTemplate("localhost")
		voltronExtHttpsPrivKey, voltronExtHttpsCert, err = test.CreateCertPair(voltronExtHttpCertTemplate, nil, nil)
		Expect(err).ShouldNot(HaveOccurred())

		voltronIntHttpCertTemplate := test.CreateServerCertificateTemplate("tigera-manager.tigera-manager.svc")
		voltronIntHttpsPrivKey, voltronIntHttpsCert, err = test.CreateCertPair(voltronIntHttpCertTemplate, nil, nil)
		Expect(err).ShouldNot(HaveOccurred())
	})

	Context("Server is running", func() {
		var (
			httpsAddr     string
			srvWg         *sync.WaitGroup
			srv           *server.Server
			defaultServer *httptest.Server
		)

		BeforeEach(func() {
			var err error

			mockAuthenticator := new(auth.MockJWTAuth)
			mockAuthenticator.On("Authenticate",
				mock.MatchedBy(func(req *http.Request) bool {
					return req.Header["Bearer"][0] == "imauthenticated"
				})).Return(
				&user.DefaultInfo{
					Name:   "jane@example.io",
					Groups: []string{"developers"},
				}, 200, nil)
			mockAuthenticator.On("Authenticate", mock.Anything).Return(
				nil, 401, fmt.Errorf("user is not authorized"))
			mockAuthenticator.On("Authorize", mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

			defaultServer = httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Echo the token, such that we can determine if the auth header was successfully swapped.
					w.Header().Set(authentication.AuthorizationHeader, r.Header.Get(authentication.AuthorizationHeader))
					w.WriteHeader(200)
					_, _ = w.Write([]byte("Success"))
				}))

			defaultURL, err := url.Parse(defaultServer.URL)
			Expect(err).NotTo(HaveOccurred())

			defaultProxy, e := proxy.New([]proxy.Target{
				{Path: "/", Dest: defaultURL},
				{Path: "/unauthenticated/", Dest: defaultURL},
				{Path: "/authenticated/", Dest: defaultURL},
				{Path: "/authenticated/nested-unauthenticated", Dest: defaultURL},
			})
			Expect(e).NotTo(HaveOccurred())

			tunnelTargetWhitelist, err := regex.CompileRegexStrings([]string{`^/$`, `^/some/path$`})
			Expect(err).ShouldNot(HaveOccurred())

			k8sTargets, err := regex.CompileRegexStrings([]string{`^/api/?`, `^/apis/?`})
			Expect(err).ShouldNot(HaveOccurred())

			srv, httpsAddr, _, _, srvWg = createAndStartServer(fakeClient,
				config,
				mockAuthenticator,
				"",
				server.WithExternalCreds(test.CertToPemBytes(voltronExtHttpsCert), test.KeyToPemBytes(voltronExtHttpsPrivKey)),
				server.WithInternalCreds(test.CertToPemBytes(voltronIntHttpsCert), test.KeyToPemBytes(voltronIntHttpsPrivKey)),
				server.WithDefaultProxy(defaultProxy),
				server.WithKubernetesAPITargets(k8sTargets),
				server.WithTunnelTargetWhitelist(tunnelTargetWhitelist),
				server.WithUnauthenticatedTargets([]string{
					"/unauthenticated/",
					"/authenticated/nested-unauthenticated",
				}),
			)

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "localhost",
				},
			}
			httpClient = &http.Client{Transport: tr}
		})

		AfterEach(func() {
			Expect(srv.Close()).NotTo(HaveOccurred())
			defaultServer.Close()
			srvWg.Wait()
		})

		It("should be able to access the authenticated endpoint with correct token", func() {
			req, err := http.NewRequest("GET", "https://"+httpsAddr+"/authenticated/", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Add("Bearer", "imauthenticated")

			resp, err := httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(Equal("Success"))
		})

		It("should not be able to access the authenticated endpoint without the correct token", func() {
			req, err := http.NewRequest("GET", "https://"+httpsAddr+"/authenticated/", nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Add("Bearer", "imNOTauthenticated")

			resp, err := httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(401))
		})

		It("should be able to access the unauthenticated endpoint without a token", func() {
			req, err := http.NewRequest("GET", "https://"+httpsAddr+"/unauthenticated/", nil)
			Expect(err).NotTo(HaveOccurred())

			resp, err := httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(Equal("Success"))
		})

		It("should be able to access the nested unauthenticated endpoint without a token", func() {
			req, err := http.NewRequest("GET", "https://"+httpsAddr+"/authenticated/nested-unauthenticated", nil)
			Expect(err).NotTo(HaveOccurred())

			resp, err := httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(Equal("Success"))
		})
	})
})
