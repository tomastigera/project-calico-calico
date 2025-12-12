// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package client_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/projectcalico/calico/voltron/internal/pkg/client"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

func init() {
	log.SetOutput(GinkgoWriter)
	log.SetLevel(log.DebugLevel)
}

func getClientFromConn(conn net.Conn, tunnelCreator func(stream io.ReadWriteCloser, opts ...tunnel.Option) (tunnel.Tunnel, error)) *http.Client {
	var t tunnel.Tunnel
	var err error
	if tunnelCreator != nil {
		t, err = tunnelCreator(conn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
		Expect(err).ShouldNot(HaveOccurred())
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if t != nil {
					return t.Open()
				}

				return conn, nil
			},
		},
	}
}

func getServerFromConn(conn net.Conn, handlerFunc http.HandlerFunc) *http.Server {
	session, err := yamux.Server(conn, nil)
	if err != nil {
		panic(err)
	}

	srv := new(http.Server)
	srv.Handler = handlerFunc
	go func() {
		Expect(srv.Serve(session)).Should(Equal(http.ErrServerClosed))
	}()
	return srv
}

func readAll(r io.ReadCloser) string {
	requestBody, err := io.ReadAll(r)
	Expect(err).ShouldNot(HaveOccurred())
	return string(requestBody)
}

func writeResponse(w http.ResponseWriter, response string) {
	_, err := fmt.Fprint(w, response)
	Expect(err).ShouldNot(HaveOccurred())
}

// TODO write more intricate tests once tunnel.Tunnel has been turned into an interface
var _ = Describe("Client", func() {
	Context("ServeTunnelHTTP", func() {
		It("proxies accepted connections", func() {
			expectedBody := "some request body"
			expectedResponse := "proxied and received"
			expectedHeaders := map[string]string{
				"Authorization": "Bearer some-token",
			}

			By("creating a mock server to accept requests")
			var wg sync.WaitGroup
			wg.Add(1)
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer wg.Done()

				for key, value := range expectedHeaders {
					Expect(r.Header.Get(key)).To(Equal(value))
				}

				Expect(readAll(r.Body)).To(Equal(expectedBody))
				writeResponse(w, expectedResponse)
			}))

			By("creating a pipe to mock the connection")
			cliConn, srvConn := net.Pipe()

			url, err := url.Parse(ts.URL)
			Expect(err).ShouldNot(HaveOccurred())

			By("creating a http client with the client side of the pipe")
			cli, err := client.New("http://example.com", "voltron",
				client.WithTunnelDialer(tunnel.NewDialer(func() (tunnel.Tunnel, error) {
					return tunnel.NewClientTunnel(cliConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				}, 1, 0, 5*time.Second)),
				client.WithProxyTargets([]proxy.Target{{Path: "/test", Dest: url, Token: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "some-token"})}}),
			)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(cli).ShouldNot(BeNil())

			go func() {
				Expect(cli.ServeTunnelHTTP()).Should(Equal(http.ErrServerClosed))
			}()

			c := getClientFromConn(srvConn, tunnel.NewServerTunnel)
			Expect(err).ShouldNot(HaveOccurred())

			By("sending a POST request with the http client")
			response, err := c.Post("http://localhost/test", "plain/text", bytes.NewBufferString(expectedBody))

			Expect(err).ShouldNot(HaveOccurred())
			Expect(readAll(response.Body)).To(Equal(expectedResponse))

			wg.Wait()

			Expect(cli.Close()).NotTo(HaveOccurred())
		})
	})
	Context("AcceptAndProxy", func() {
		It("accepts connections from the given listener and sends them down the tunnel", func() {
			By("creating a pipe to mock the connection")
			cliConn, srvConn := net.Pipe()

			By("creating a http client with the client side of the pipe")
			cli, err := client.New("http://example.com", "voltron",
				client.WithTunnelDialer(tunnel.NewDialer(func() (tunnel.Tunnel, error) {
					return tunnel.NewClientTunnel(cliConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				}, 1, 0, 5*time.Second)),
			)
			Expect(err).ShouldNot(HaveOccurred())

			By("creating localhost listener and using it in the client")
			listener, err := net.Listen("tcp", "localhost:0")
			Expect(err).ShouldNot(HaveOccurred())

			go func() {
				Expect(cli.AcceptAndProxy(listener)).Should(Equal(http.ErrServerClosed))
			}()

			By("creating a server to listen on the other end of the pipe")
			getServerFromConn(srvConn, func(w http.ResponseWriter, r *http.Request) {
				Expect(readAll(r.Body)).To(Equal("some request"))
				writeResponse(w, "some response")
			})

			By("sending a request to the port the client is listening on")
			response, err := http.Post("http://"+listener.Addr().String(), "plain/text", bytes.NewBufferString("some request"))
			Expect(err).ShouldNot(HaveOccurred())
			Expect(readAll(response.Body)).To(Equal("some response"))
		})
	})
})
