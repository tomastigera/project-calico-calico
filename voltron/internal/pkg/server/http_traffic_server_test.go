// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package server_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/lma/pkg/auth"
	vcfg "github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/server"
)

func init() {
	log.SetOutput(GinkgoWriter)
	log.SetLevel(log.DebugLevel)
}

var _ = Describe("Creating an HTTPS server that only proxies traffic", func() {
	var (
		fakeClient ctrlclient.WithWatch

		mockAuthenticator  *auth.MockJWTAuth
		srv                *server.Server
		externalServerName string
		internalServerName string
		externalCACert     []byte
		externalCert       []byte
		externalKey        []byte
		internalCACert     []byte
		internalCert       []byte
		internalKey        []byte
		listener           net.Listener
		address            net.Addr
	)

	JustBeforeEach(func() {
		var err error

		mockAuthenticator = new(auth.MockJWTAuth)

		By("Creating a default destination server that return 200 OK")
		defaultServer := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				_, _ = w.Write([]byte("Success"))
			}))

		defaultURL, err := url.Parse(defaultServer.URL)
		Expect(err).NotTo(HaveOccurred())

		By("Creating a default proxy to proxy traffic to the default destination")
		defaultProxy, err := proxy.New([]proxy.Target{
			{
				Path: "/",
				Dest: defaultURL,
			},
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating TCP listener to help communication")
		listener, err = net.Listen("tcp", "localhost:0")
		Expect(err).NotTo(HaveOccurred())
		address = listener.Addr()
		Expect(address).ShouldNot(BeNil())
		Expect(err).NotTo(HaveOccurred())

		By("Creating and starting server that only serves HTTPS traffic")
		opts := []server.Option{
			server.WithDefaultAddr(address.String()),
			server.WithDefaultProxy(defaultProxy),
			server.WithExternalCreds(externalCert, externalKey),
			server.WithInternalCreds(internalCert, internalKey),
			server.WithKeepAliveSettings(true, 100),
			server.WithUnauthenticatedTargets([]string{"/"}),
		}

		voltronConfig := vcfg.Config{}

		srv, err = server.New(
			fakeClient,
			config,
			voltronConfig,
			mockAuthenticator, mockFactory,
			opts...,
		)
		Expect(err).NotTo(HaveOccurred())

		go func() {
			_ = srv.ServeHTTPS(listener, "", "")
		}()
	})

	assertHTTPSServerBehaviour := func() {
		It("Does not initiate a tunnel server when the tunnel destination doesn't have tls certificates", func() {
			err := srv.ServeTunnelsTLS(listener)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("no tunnel server was initiated"))
		})

		It("Receives 200 OK when reaching the proxy server using HTTPS using the external server name", func() {
			var err error

			rootCAs := x509.NewCertPool()
			rootCAs.AppendCertsFromPEM(externalCACert)

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    rootCAs,
					ServerName: externalServerName,
				},
			}
			client := &http.Client{Transport: tr}
			req, err := http.NewRequest("GET", "https://"+address.String()+"/", nil)
			Expect(err).NotTo(HaveOccurred())

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(Equal("Success"))
		})

		It("Receives 200 OK when reaching the proxy server using HTTPS using the internal server name", func() {
			var err error

			rootCAs := x509.NewCertPool()
			rootCAs.AppendCertsFromPEM(internalCACert)

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    rootCAs,
					ServerName: internalServerName,
				},
			}
			client := &http.Client{Transport: tr}
			req, err := http.NewRequest("GET", "https://"+address.String()+"/", nil)
			Expect(err).NotTo(HaveOccurred())

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(Equal("Success"))
		})

		It("Receives 200 OK when reaching the proxy server using HTTP 2", func() {
			var err error

			rootCAs := x509.NewCertPool()
			rootCAs.AppendCertsFromPEM(externalCACert)

			tr := &http2.Transport{
				TLSClientConfig: &tls.Config{
					NextProtos: []string{"h2"},
					RootCAs:    rootCAs,
					ServerName: externalServerName,
				},
			}

			client := &http.Client{Transport: tr}
			req, err := http.NewRequest("GET", "https://"+address.String()+"/", nil)
			Expect(err).NotTo(HaveOccurred())

			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(200))

			body, err := io.ReadAll(resp.Body)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(body)).To(Equal("Success"))
		})

		It("Receives 400 when reaching the proxy server using HTTP", func() {
			var err error
			req, err := http.NewRequest("GET", "http://"+address.String()+"/", nil)
			Expect(err).NotTo(HaveOccurred())

			resp, err := http.DefaultClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(400))
		})
	}

	Context("Using self signed root CA certs with DNS set to voltron", func() {
		BeforeEach(func() {
			externalServerName = "voltron"
			internalServerName = "voltron"

			key, cert, err := generateKeyCert("tigera-voltron", "voltron")
			Expect(err).NotTo(HaveOccurred())
			Expect(key).NotTo(BeNil())
			Expect(cert).NotTo(BeNil())

			externalCACert = cert
			externalCert = cert
			externalKey = key
			internalCACert = cert
			internalCert = cert
			internalKey = key
		})

		assertHTTPSServerBehaviour()
	})

	Context("Using certs that have PKCS8 Key format", func() {
		var err error

		BeforeEach(func() {
			externalServerName = "tigera-manager.calico-monitoring.svc"
			internalServerName = "tigera-manager.calico-monitoring.svc"

			externalCACert, err = os.ReadFile("testdata/cert-pkcs8-format.pem")
			Expect(err).NotTo(HaveOccurred())
			externalCert, err = os.ReadFile("testdata/cert-pkcs8-format.pem")
			Expect(err).NotTo(HaveOccurred())
			externalKey, err = os.ReadFile("testdata/key-pkcs8-format.pem")
			Expect(err).NotTo(HaveOccurred())
			internalCACert, err = os.ReadFile("testdata/cert-pkcs8-format.pem")
			Expect(err).NotTo(HaveOccurred())
			internalCert, err = os.ReadFile("testdata/cert-pkcs8-format.pem")
			Expect(err).NotTo(HaveOccurred())
			internalKey, err = os.ReadFile("testdata/key-pkcs8-format.pem")
			Expect(err).NotTo(HaveOccurred())
		})

		assertHTTPSServerBehaviour()
	})

	Context("Using two set of certs for internal and external HTTPS traffic", func() {
		var err error

		BeforeEach(func() {
			externalServerName = "localhost"
			internalServerName = "tigera-manager.tigera-manager.svc"

			externalCACert, err = os.ReadFile("testdata/localhost-intermediate-CA.pem")
			Expect(err).NotTo(HaveOccurred())
			externalCert, err = os.ReadFile("testdata/localhost.pem")
			Expect(err).NotTo(HaveOccurred())
			externalKey, err = os.ReadFile("testdata/localhost.key")
			Expect(err).NotTo(HaveOccurred())
			internalCACert, err = os.ReadFile("testdata/tigera-manager-svc-intermediate-CA.pem")
			Expect(err).NotTo(HaveOccurred())
			internalCert, err = os.ReadFile("testdata/tigera-manager-svc.pem")
			Expect(err).NotTo(HaveOccurred())
			internalKey, err = os.ReadFile("testdata/tigera-manager-svc.key")
			Expect(err).NotTo(HaveOccurred())
		})

		assertHTTPSServerBehaviour()
	})
})

func generateKeyCert(commonName, dnsName string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pn := pkix.Name{
		CommonName:   commonName,
		Country:      []string{"US"},
		Locality:     []string{"San Francisco"},
		Organization: []string{"Tigera, Inc."},
		Province:     []string{"California"},
	}

	tpl := &x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsName},
		EmailAddresses:        []string{"contact@tigera.io"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		Issuer:                pn,
		NotAfter:              time.Now().AddDate(1, 0, 0),
		NotBefore:             time.Now(),
		SerialNumber:          big.NewInt(123),
		Subject:               pn,
	}

	cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	return keyPem, certPem, nil
}
