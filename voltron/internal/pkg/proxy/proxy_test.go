package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/internal/pkg/test"
	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
)

func init() {
	log.SetOutput(GinkgoWriter)
	log.SetLevel(log.DebugLevel)
}

var _ = Describe("Proxy", func() {
	Describe("When empty", func() {
		It("should return error to any request", func() {
			p, err := proxy.New(nil)
			Expect(err).NotTo(HaveOccurred())

			r, err := http.NewRequest("GET", "http://host/path", nil)
			Expect(err).NotTo(HaveOccurred())

			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(404))
		})

		It("should fail to configure with a bad target", func() {
			_, err := proxy.New([]proxy.Target{{}})
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("When configured", func() {
		t := &transport{
			func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body("")}, nil
			},
		}

		p, _ := proxy.New([]proxy.Target{
			{
				Path: "/path/",
				Dest: &url.URL{
					Scheme: "http",
					Host:   "some",
				},
				Transport: t,
			},
		})

		It("should be redirected to the root", func() {
			r, err := http.NewRequest("GET", "http://host/path", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(301))
			Expect(res.Header.Get("Location")).To(Equal("/path/"))
		})

		It("should reach the root", func() {
			r, err := http.NewRequest("GET", "http://host/path/", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))
		})

		It("should reach a sub tree", func() {
			r, err := http.NewRequest("GET", "http://host/path/sub/tree", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))
		})

		It("should fail to reach missing target", func() {
			r, err := http.NewRequest("GET", "http://host/missing", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(404))
		})

		It("should have the HSTS header set", func() {
			r, err := http.NewRequest("GET", "http://host/path/", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))
			// Verify the response header contains the HSTS header
			hstsHeader := res.Header.Get("Strict-Transport-Security")
			Expect(hstsHeader).To(ContainSubstring("max-age=31536000; includeSubDomains"))
		})
	})

	Describe("When having a catch all path", func() {
		t := &transport{
			func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body("")}, nil
			},
		}

		p, _ := proxy.New([]proxy.Target{
			{
				Path: "/path/",
				Dest: &url.URL{
					Scheme: "http",
					Host:   "some",
				},
				Transport: t,
			},
			{
				Path: "/",
				Dest: &url.URL{
					Scheme: "http",
					Host:   "some",
				},
				Transport: t,
			},
		})

		It("should return 200 to /path target ", func() {
			r, err := http.NewRequest("GET", "http://host/path/", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))
		})

		It("should return 200 to any requests", func() {
			r, err := http.NewRequest("GET", "http://host/anyTarget/", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))
		})
	})

	Describe("When target has a regexp", func() {
		t := &transport{
			func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: body("")}, nil
			},
		}

		p, _ := proxy.New([]proxy.Target{
			{
				Path: "/path/",
				Dest: &url.URL{
					Scheme: "http",
					Host:   "some",
				},
				PathRegexp: regexp.MustCompile("must.*match"),
				Transport:  t,
			},
		})

		It("should reach a sub tree with a refined match", func() {
			r, err := http.NewRequest("GET", "http://host/path/sub/tree/must/contain/match", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))
		})

		It("should fail to reach if not a precise match", func() {
			r, err := http.NewRequest("GET", "http://host/path/no/match", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(404))
		})

		Describe("When it also has a replace", func() {
			t := &transport{
				func(r *http.Request) (*http.Response, error) {
					if r.URL.Path == "/the/right/result" {
						return &http.Response{StatusCode: 200, Body: body("")}, nil
					}
					log.Errorf("bad path: %q", r.URL.Path)
					return &http.Response{StatusCode: 404, Body: body("")}, nil
				},
			}

			p, _ := proxy.New([]proxy.Target{
				{
					Path: "/path/the/remove/right/remove/result",
					Dest: &url.URL{
						Scheme: "http",
						Host:   "some",
					},
					PathRegexp:  regexp.MustCompile("(path|remove)/"),
					PathReplace: []byte(""),
					Transport:   t,
				},
				{
					Path: "/result/the/right",
					Dest: &url.URL{
						Scheme: "http",
						Host:   "some",
					},
					PathRegexp:  regexp.MustCompile("(result)/(.*)/(right)"),
					PathReplace: []byte("$2/$3/$1"),
					Transport:   t,
				},
			})

			It("should reach target with removed path bits", func() {
				r, err := http.NewRequest("GET", "http://host/path/the/remove/right/remove/result", nil)
				Expect(err).NotTo(HaveOccurred())
				w := httptest.NewRecorder()
				p.ServeHTTP(w, r)

				res := w.Result()
				Expect(res.StatusCode).To(Equal(200))
			})

			It("should reach target with rewritten path bits", func() {
				r, err := http.NewRequest("GET", "http://host/result/the/right", nil)
				Expect(err).NotTo(HaveOccurred())
				w := httptest.NewRecorder()
				p.ServeHTTP(w, r)

				res := w.Result()
				Expect(res.StatusCode).To(Equal(200))
			})
		})
	})

	Describe("When some targets have a token", func() {
		token := "some-token"
		noToken := "no token"

		withToken := &transport{
			func(r *http.Request) (*http.Response, error) {
				h := r.Header.Get("Authorization")
				if h == "" {
					return &http.Response{StatusCode: 400, Body: body("no token")}, nil
				}
				if h != "Bearer "+token {
					return &http.Response{StatusCode: 400, Body: body("bad token")}, nil
				}
				return &http.Response{StatusCode: 200, Body: body(token)}, nil
			},
		}

		withoutToken := &transport{
			func(r *http.Request) (*http.Response, error) {
				h := r.Header.Get("Authorization")
				if h != "" {
					return &http.Response{StatusCode: 400, Body: body("unexpected token " + h)}, nil
				}
				return &http.Response{StatusCode: 200, Body: body(noToken)}, nil
			},
		}

		p, _ := proxy.New([]proxy.Target{
			{
				Path: "/token",
				Dest: &url.URL{
					Scheme: "http",
					Host:   "some",
				},
				Token:     oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
				Transport: withToken,
			},
			{
				Path: "/",
				Dest: &url.URL{
					Scheme: "http",
					Host:   "other",
				},
				Transport: withoutToken,
			},
		})

		It("should get token if configured with one", func() {
			r, err := http.NewRequest("GET", "http://host/token", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))

			msg, err := io.ReadAll(res.Body)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(msg)).To(Equal(token))
		})

		It("should not get token if unconfigured", func() {
			r, err := http.NewRequest("GET", "http://host/path", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))

			msg, err := io.ReadAll(res.Body)
			Expect(err).NotTo(HaveOccurred())

			Expect(string(msg)).To(Equal(noToken))
		})
	})

	Describe("When CA bundle configured", func() {
		It("Should fail for http target", func() {
			file, _, err := createCa()
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = os.Remove(file.Name()) }()

			_, err = proxy.New([]proxy.Target{
				{
					Path: "/path",
					Dest: &url.URL{
						Scheme: "http",
						Host:   "some",
					},
					CAPem: file.Name(),
				},
			})
			Expect(err).To(HaveOccurred())
		})

		It("Should work if the certs match", func() {
			file, ca, err := createCa()
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = os.Remove(file.Name()) }()

			server := httptest.NewUnstartedServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// just returns 200
				}),
			)

			parseCert, _ := x509.ParseCertificate(ca)
			certPem := test.PemEncodeCert(parseCert)
			cert, err := tls.X509KeyPair(certPem, []byte(test.PrivateRSA))
			Expect(err).NotTo(HaveOccurred())

			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

			server.StartTLS()
			defer server.Close()

			srvURL, err := url.Parse(server.URL)
			Expect(err).NotTo(HaveOccurred())

			certFile, err := os.CreateTemp("", "path-cert")
			Expect(err).ShouldNot(HaveOccurred())
			_, err = certFile.Write(certPem)
			Expect(err).ShouldNot(HaveOccurred())

			p, err := proxy.New([]proxy.Target{
				{
					Path:  "/path",
					Dest:  srvURL,
					CAPem: certFile.Name(),
				},
			})
			Expect(err).NotTo(HaveOccurred())

			r, err := http.NewRequest("GET", server.URL+"/path", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).To(Equal(200))
		})

		It("Should fail if the certs do not match", func() {
			file, _, err := createCa()
			Expect(err).NotTo(HaveOccurred())
			defer func() { _ = os.Remove(file.Name()) }()

			server := httptest.NewUnstartedServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// just returns 200
				}),
			)

			badCert, key, _ := test.CreateSelfSignedX509CertRandom()
			certPem := utils.CertPEMEncode(badCert)
			keyPem, _ := utils.KeyPEMEncode(key)
			cert, err := tls.X509KeyPair(certPem, keyPem)
			Expect(err).NotTo(HaveOccurred())

			server.TLS = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

			server.StartTLS()
			defer server.Close()

			srvURL, err := url.Parse(server.URL)
			Expect(err).NotTo(HaveOccurred())

			p, err := proxy.New([]proxy.Target{
				{
					Path:  "/path",
					Dest:  srvURL,
					CAPem: file.Name(),
				},
			})
			Expect(err).NotTo(HaveOccurred())

			r, err := http.NewRequest("GET", server.URL+"/path", nil)
			Expect(err).NotTo(HaveOccurred())
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)

			res := w.Result()
			Expect(res.StatusCode).NotTo(Equal(200))
		})
	})
})

func createCa() (*os.File, []byte, error) {
	ca, _ := test.CreateSelfSignedX509CertBinary("xyz", true)
	file, err := os.CreateTemp("", "test-certificate")
	if err != nil {
		return nil, nil, err
	}
	_, err = file.Write(ca)

	if err != nil {
		return nil, nil, err
	}
	return file, ca, nil
}

type transport struct {
	rt func(*http.Request) (*http.Response, error)
}

func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.rt(r)
}

func body(msg string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(msg))
}
