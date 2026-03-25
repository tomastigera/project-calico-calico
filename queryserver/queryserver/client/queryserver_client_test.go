package client

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	querycacheclient "github.com/projectcalico/calico/queryserver/pkg/querycache/client"
)

var _ = Describe("QuerysServerClient tests", func() {
	Context("test SearchEndpoints", func() {
		var server *httptest.Server
		BeforeEach(func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept") != "application/json" {
					http.Error(w, "bad accept header", http.StatusBadRequest)
					return
				}
				if r.Method != "POST" {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"count": 0, "items": []}`))
				Expect(err).ShouldNot(HaveOccurred())
			}))
		})

		AfterEach(func() {
			server.Close()
		})
		It("managed cluster", func() {
			config := &QueryServerConfig{
				QueryServerTunnelURL: server.URL,
				QueryServerURL:       "",
				QueryServerCA:        "/etc/pki/tls/certs/ca.crt",
				QueryServerToken:     "test_data/token",
			}

			client := queryServerClient{
				client: &http.Client{},
			}

			body := &querycacheclient.QueryEndpointsReqBody{}
			resp, err := client.SearchEndpoints(config, body, "managed-cluster")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(resp.Count).To(Equal(0))

		})

		It("management / standalone cluster", func() {
			config := &QueryServerConfig{
				QueryServerTunnelURL: "",
				QueryServerURL:       server.URL,
				QueryServerCA:        "/etc/pki/tls/certs/ca.crt",
				QueryServerToken:     "test_data/token",
			}

			client := queryServerClient{
				client: &http.Client{},
			}

			body := &querycacheclient.QueryEndpointsReqBody{}
			resp, err := client.SearchEndpoints(config, body, "cluster")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(resp.Count).To(Equal(0))
		})

		It("query server token is empty", func() {
			config := &QueryServerConfig{
				QueryServerTunnelURL: "",
				QueryServerURL:       server.URL,
				QueryServerCA:        "/etc/pki/tls/certs/ca.crt",
				QueryServerToken:     "",
			}

			client := queryServerClient{
				client: &http.Client{},
			}

			body := &querycacheclient.QueryEndpointsReqBody{}
			resp, err := client.SearchEndpoints(config, body, "cluster")
			Expect(err).To(Equal(errInvalidToken))
			Expect(resp).To(BeNil())
		})

		It("non-200 response from queryserver returns error", func() {
			errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Error: unknown policy kind: test-policy", http.StatusBadRequest)
			}))
			defer errorServer.Close()

			config := &QueryServerConfig{
				QueryServerTunnelURL: "",
				QueryServerURL:       errorServer.URL,
				QueryServerCA:        "/etc/pki/tls/certs/ca.crt",
				QueryServerToken:     "test_data/token",
			}

			client := queryServerClient{
				client: &http.Client{},
			}

			body := &querycacheclient.QueryEndpointsReqBody{}
			resp, err := client.SearchEndpoints(config, body, "cluster")
			Expect(err).Should(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("400"))
			Expect(err.Error()).To(ContainSubstring("unknown policy kind"))
			Expect(resp).To(BeNil())
		})
	})
})
