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
				if r.URL.Path != "" {
					w.WriteHeader(http.StatusForbidden)
				}
				if r.Header.Get("Accept") != "application/json" {
					w.WriteHeader(http.StatusBadRequest)
				}
				if r.Method != "POST" {
					w.WriteHeader(http.StatusMethodNotAllowed)
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
			Expect(err).Should(HaveOccurred())
			Expect(resp).To(BeNil())
		})
	})
})
