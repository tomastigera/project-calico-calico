package tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	calicoTLS "github.com/projectcalico/calico/crypto/pkg/tls"
)

// The following UTs ensure that the failure cases for proxying are covered by tests. They also ensure that HTTPS
// connection to proxy is under test. The mainline case / happy path is handled by the FV tests.
var _ = Describe("tlsDialViaHTTPProxy", func() {
	var httpProxy, httpsProxy *goproxy.ProxyHttpServer
	var httpProxyServer, httpsProxyServer *http.Server
	var httpProxyURL, httpsProxyURL *url.URL
	var tunnelClientTLSConfig, proxyClientTLSConfig *tls.Config
	var wg sync.WaitGroup
	BeforeEach(func() {
		httpProxy = goproxy.NewProxyHttpServer()
		httpsProxy = goproxy.NewProxyHttpServer()
		tlsConfig, errTLS := calicoTLS.NewTLSConfig()
		Expect(errTLS).NotTo(HaveOccurred())
		tunnelClientTLSConfig = tlsConfig
		proxyClientTLSConfig = tlsConfig

		// Silence warnings from connections being closed. The proxy server lib only accepts the unstructured std logger.
		silentLogger := log.New(io.Discard, "", log.LstdFlags)
		httpProxy.Logger = silentLogger
		httpsProxy.Logger = silentLogger

		// Instantiate the HTTP server.
		httpProxyServer = &http.Server{
			Addr:    ":3128",
			Handler: httpProxy,
		}
		httpProxyURL = &url.URL{
			Scheme: "http",
			Host:   "localhost:3128",
		}
		wg.Go(func() {
			_ = httpProxyServer.ListenAndServe()
		})

		// Wait for the server to be ready.
		Eventually(func() error {
			_, err := net.Dial("tcp", "localhost:3128")
			return err
		}).WithTimeout(5 * time.Second).ShouldNot(HaveOccurred())

		// Instantiate the HTTPS server.
		// Create a CA.
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		caTemplate := &x509.Certificate{
			Subject: pkix.Name{
				Organization: []string{"Tigera, Inc."},
			},
			SerialNumber:          big.NewInt(123),
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		caCert, err := x509.ParseCertificate(caCertBytes)
		Expect(err).NotTo(HaveOccurred())
		certPool := x509.NewCertPool()
		certPool.AddCert(caCert)
		proxyClientTLSConfig.RootCAs = certPool

		// Issue a cert from that CA that has the expected names.
		proxyKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		proxyTemplate := &x509.Certificate{
			Subject: pkix.Name{
				CommonName:   "localhost",
				Organization: []string{"proxy-co"},
			},
			DNSNames:              []string{"localhost"},
			IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
			SerialNumber:          big.NewInt(456),
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			BasicConstraintsValid: true,
		}
		proxyCertBytes, err := x509.CreateCertificate(rand.Reader, proxyTemplate, caCert, &proxyKey.PublicKey, caKey)
		Expect(err).NotTo(HaveOccurred())
		proxyCert, err := x509.ParseCertificate(proxyCertBytes)
		Expect(err).NotTo(HaveOccurred())

		// Set the CA as a RootCA on the proxyTLSConfig
		httpsProxyServer = &http.Server{
			Addr:    ":3129",
			Handler: httpsProxy,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{
					{
						Certificate: [][]byte{proxyCert.Raw, caCert.Raw},
						PrivateKey:  proxyKey,
					},
				},
			},
		}
		httpsProxyURL = &url.URL{
			Scheme: "https",
			Host:   "localhost:3129",
		}
		wg.Go(func() {
			_ = httpsProxyServer.ListenAndServeTLS("", "")
		})

		// Wait for the server to be ready.
		Eventually(func() error {
			// Silence logging, as we'll see handshake failures from opening a TCP connection without a handshake.
			httpsProxyServer.ErrorLog = silentLogger
			_, err := net.Dial("tcp", "localhost:3129")
			httpProxyServer.ErrorLog = nil
			return err
		}).WithTimeout(5 * time.Second).ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		_ = httpProxyServer.Close()
		_ = httpsProxyServer.Close()
		wg.Wait()
	})

	for _, tls := range []bool{false, true} {
		It(fmt.Sprintf("errors when the CONNECT request is rejected (tls: %v)", tls), func() {
			var proxyServer *goproxy.ProxyHttpServer
			var proxyURL *url.URL
			if tls {
				proxyServer = httpsProxy
				proxyURL = httpsProxyURL
			} else {
				proxyServer = httpProxy
				proxyURL = httpProxyURL
			}

			// Set up the proxy server to reject CONNECT requests with a 401.
			proxyServer.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				ctx.Resp = &http.Response{
					Status:     http.StatusText(http.StatusUnauthorized),
					StatusCode: http.StatusUnauthorized,
				}
				return goproxy.RejectConnect, host
			}))

			_, err := tlsDialViaHTTPProxy(
				newDialer(time.Second),
				"someplace:443",
				proxyURL,
				tunnelClientTLSConfig,
				proxyClientTLSConfig,
			)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Unauthorized"))
		})

		It(fmt.Sprintf("errors when proxy auth is required but not provided (tls: %v)", tls), func() {
			var proxyServer *goproxy.ProxyHttpServer
			var proxyURL *url.URL
			if tls {
				proxyServer = httpsProxy
				proxyURL = httpsProxyURL
			} else {
				proxyServer = httpProxy
				proxyURL = httpProxyURL
			}

			// Set up the proxy server to reject all requests on the basis of failed auth.
			auth.ProxyBasic(proxyServer, "test", func(user, passwd string) bool {
				return false
			})

			_, err := tlsDialViaHTTPProxy(
				newDialer(time.Second),
				"someplace:443",
				proxyURL,
				tunnelClientTLSConfig,
				proxyClientTLSConfig,
			)

			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Proxy Authentication Required"))
		})
	}

	// The function under test can detect a specific misbehaviour of the proxy: sending data immediately after accepting the CONNECT.
	// However, there are a couple of scenarios in which it __cannot__ reliably detect this misbehaviour:
	// 1. When it reads data from the underlying client connection before the proxy has sent the unexpected data.
	// 2. When it's connection to the proxy is HTTPS, since TLS records are read from the underlying client connection one at a time.
	// In both of these cases, this function only reads the 200 response to the CONNECT from the connection, and therefore does not observe
	// any misbehaviour. In these cases, we still receive a generic error during mTLS handshake failure, but mTLS is not in scope of this test.
	It("errors explicitly when the server continues to send data after it accepts the CONNECT request", func() {
		// Set up a proxy server that writes extra data to the connection after accepting the CONNECT request.
		httpProxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return &goproxy.ConnectAction{
				Action: goproxy.ConnectHijack,
				Hijack: func(req *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
					n, err := client.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
					Expect(n).ToNot(BeZero())
					Expect(err).NotTo(HaveOccurred(), "Failed to write 200 to hijacked connection")
					n, err = client.Write([]byte("hello, I shouldn't be speaking right now"))
					Expect(n).ToNot(BeZero())
					Expect(err).NotTo(HaveOccurred(), "Failed to write data to hijacked connection")
				},
			}, host
		}))

		var err error
		// Validate that our dial function notices the extra bytes following the 200.
		// We wrap this test in an Eventually in case our first tries hit the race condition described in (1) above.
		// Hitting the race condition is not a problem in practice, it just means we have a less precise error message.
		Eventually(func() string {
			_, err = tlsDialViaHTTPProxy(
				newDialer(time.Second),
				"someplace:443",
				httpProxyURL,
				tunnelClientTLSConfig,
				proxyClientTLSConfig,
			)
			return err.Error()
		}).WithTimeout(10 * time.Second).Should(ContainSubstring("buffered data"))
	})
})

var _ = Describe("GetHTTPProxyURL", func() {
	var originalHTTPProxy, originalHTTPSProxy, originalNoProxy string
	httpProxyHost := "http-proxy:8080"
	httpsProxyHost := "https-proxy:8443"

	BeforeEach(func() {
		originalHTTPProxy = os.Getenv("HTTP_PROXY")
		originalHTTPSProxy = os.Getenv("HTTPS_PROXY")
		originalNoProxy = os.Getenv("NO_PROXY")
		_ = os.Setenv("HTTP_PROXY", "http://"+httpProxyHost)
		_ = os.Setenv("HTTPS_PROXY", "https://"+httpsProxyHost)
	})

	AfterEach(func() {
		_ = os.Setenv("HTTP_PROXY", originalHTTPProxy)
		_ = os.Setenv("HTTPS_PROXY", originalHTTPSProxy)
		_ = os.Setenv("NO_PROXY", originalNoProxy)
	})

	// The following tests validate that we successfully wrap the underlying httpproxy lib calls to resolve the proxy URL.
	// We do not exhaustively test the scenarios of proxy resolution here, as that is tested by the lib itself - we just
	// test the wrapping. Our wrapping needs to treat the voltron host:port as an HTTPS target.
	It("returns the HTTPS proxy for a given target", func() {
		url, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).To(BeNil())
		Expect(url.Scheme).To(Equal("https"))
		Expect(url.Host).To(Equal(httpsProxyHost))
	})

	It("returns no proxy for a given target if no HTTPS proxy present", func() {
		_ = os.Setenv("HTTPS_PROXY", "")
		url, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).To(BeNil())
		Expect(url).To(BeNil())
	})

	It("respects NO_PROXY for a given DNS target", func() {
		_ = os.Setenv("NO_PROXY", "voltron,8.8.8.8")
		url, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).To(BeNil())
		Expect(url).To(BeNil())
	})

	It("respects NO_PROXY for a given IP target", func() {
		_ = os.Setenv("NO_PROXY", "voltron,8.8.8.8")
		url, err := GetHTTPProxyURL("8.8.8.8:9449")
		Expect(err).To(BeNil())
		Expect(url).To(BeNil())
	})

	// The following tests validate that our wrapping handles port coercion correctly relative to the scheme.
	It("handles HTTP without port proxy URL", func() {
		_ = os.Setenv("HTTPS_PROXY", "http://https-proxy")
		url, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).To(BeNil())
		Expect(url.Host).To(Equal("https-proxy:80"))
		Expect(url.Port()).To(Equal("80"))
	})
	It("handles HTTP with port proxy URL", func() {
		_ = os.Setenv("HTTPS_PROXY", "http://https-proxy:9000")
		url, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).To(BeNil())
		Expect(url.Host).To(Equal("https-proxy:9000"))
		Expect(url.Port()).To(Equal("9000"))
	})
	It("handles HTTPS without port proxy URL", func() {
		_ = os.Setenv("HTTPS_PROXY", "https://https-proxy")
		url, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).To(BeNil())
		Expect(url.Host).To(Equal("https-proxy:443"))
		Expect(url.Port()).To(Equal("443"))
	})
	It("handles HTTPS with port proxy URL", func() {
		_ = os.Setenv("HTTPS_PROXY", "https://https-proxy:9000")
		url, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).To(BeNil())
		Expect(url.Host).To(Equal("https-proxy:9000"))
		Expect(url.Port()).To(Equal("9000"))
	})

	It("returns error when an invalid scheme is set on the proxy URL", func() {
		_ = os.Setenv("HTTPS_PROXY", "socks://socks-proxy:9000")
		_, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).ToNot(BeNil())
	})

	It("returns error when the proxy URL is malformed", func() {
		_ = os.Setenv("HTTPS_PROXY", "^&#$")
		_, err := GetHTTPProxyURL("voltron:9449")
		Expect(err).ToNot(BeNil())
	})
})
