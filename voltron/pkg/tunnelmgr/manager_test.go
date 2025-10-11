package tunnelmgr_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/voltron/pkg/state"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
	"github.com/projectcalico/calico/voltron/pkg/tunnelmgr"
)

type ConnOpener interface {
	Open() (net.Conn, error)
}

type responseList struct {
	nextIndex int
	responses []string
}

func (rList *responseList) Next() string {
	if rList.responses == nil || rList.nextIndex >= len(rList.responses) {
		return ""
	}

	r := rList.responses[rList.nextIndex]
	rList.nextIndex++
	return r
}

var _ = Describe("Manager", func() {
	Context("client side tunnel", func() {
		Context("opens connections", func() {
			It("opens a connection to a tunnel and writes to it", func() {
				cliConn, srvConn := net.Pipe()
				srv := getServerFromConnection(srvConn, "Response")
				defer func() { _ = srv.Close() }()

				tun, err := tunnel.NewClientTunnel(cliConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				Expect(m.SetTunnel(tun)).ShouldNot(HaveOccurred())

				conn, err := m.Open()
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conn).ShouldNot(BeNil())

				cli := getClientFromOpener(m)

				response, err := cli.Get("http://localhost")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(readResponseBody(response)).To(Equal("Response"))
			})

			It("adheres to the timeout and fails to setup when it is too low", func() {
				cliConn, srvConn := net.Pipe()
				srv := getServerFromConnection(srvConn, "Response")
				defer func() { _ = srv.Close() }()

				tun, err := tunnel.NewClientTunnel(cliConn,
					tunnel.WithKeepAliveSettings(true, 100*time.Second),
					// Set a very low timeout.
					tunnel.WithDialTimeout(1*time.Nanosecond))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				// When the timeout  is only 1 ns, the context times out.
				Expect(m.SetTunnel(tun)).To(HaveOccurred())
				errStruct := state.ErrChannelWriteTimeout{}
				Expect(m.SetTunnel(tun).Error()).To(Equal(errStruct.Error()))
			})

			It("opens multiple connections over the single tunnel", func() {
				cliConn, srvConn := net.Pipe()
				srv := getServerFromConnection(srvConn, "Response 1", "Response 2")
				defer func() { _ = srv.Close() }()

				tun, err := tunnel.NewClientTunnel(cliConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				Expect(m.SetTunnel(tun)).ShouldNot(HaveOccurred())

				conn, err := m.Open()
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conn).ShouldNot(BeNil())

				cli := getClientFromOpener(m)

				response, err := cli.Get("http://localhost")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(readResponseBody(response)).To(Equal("Response 1"))

				response, err = cli.Get("http://localhost")
				Expect(err).ShouldNot(HaveOccurred())
				Expect(readResponseBody(response)).To(Equal("Response 2"))
			})

			It("test tunnel closed before opening", func() {
				cliConn, _ := net.Pipe()

				tun, err := tunnel.NewClientTunnel(cliConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				Expect(m.SetTunnel(tun)).ShouldNot(HaveOccurred())

				Expect(tun.Close()).ShouldNot(HaveOccurred())
				conn, err := m.Open()
				Expect(err).Should(Equal(tunnel.ErrTunnelClosed))
				Expect(conn).Should(BeNil())
			})
		})

		Context("Listen", func() {
			It("accepts a connection from the tunnel and responds to it", func() {
				cliConn, srvConn := net.Pipe()
				tun, err := tunnel.NewClientTunnel(srvConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				Expect(m.SetTunnel(tun)).ShouldNot(HaveOccurred())

				listener, err := m.Listener()
				Expect(err).ShouldNot(HaveOccurred())

				var wg sync.WaitGroup
				wg.Add(1)
				acceptAndRespondOnce(listener, &wg, "200", "Response")

				cliTun, err := tunnel.NewClientTunnel(cliConn)
				Expect(err).ShouldNot(HaveOccurred())

				cli := getClientFromOpener(cliTun)
				response, err := cli.Get("http://example.com")
				Expect(err).ShouldNot(HaveOccurred())

				Expect(readResponseBody(response)).To(Equal("Response"))
				wg.Wait()
			})
			It("receives an error when the connection is closed while waiting to accept a connection", func() {
				cliConn, srvConn := net.Pipe()
				tun, err := tunnel.NewClientTunnel(srvConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				Expect(m.SetTunnel(tun)).ShouldNot(HaveOccurred())

				listener, err := m.Listener()
				Expect(err).ShouldNot(HaveOccurred())

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					conn, err := listener.Accept()
					Expect(err).Should(HaveOccurred())
					Expect(conn).Should(BeNil())
				}()

				Expect(cliConn.Close()).ShouldNot(HaveOccurred())
				wg.Wait()
			})
			It("receives an error when the manager is closed while waiting to accept a connection", func() {
				_, srvConn := net.Pipe()
				tun, err := tunnel.NewClientTunnel(srvConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				Expect(m.SetTunnel(tun)).ShouldNot(HaveOccurred())

				listener, err := m.Listener()
				Expect(err).ShouldNot(HaveOccurred())

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					conn, err := listener.Accept()
					Expect(err).Should(HaveOccurred())
					Expect(conn).Should(BeNil())
				}()

				_ = m.Close()
				Expect(err).ShouldNot(HaveOccurred())
				wg.Wait()
			})
			// This test is here not because we necessarily expect to have multiple listeners, but the current implementation
			// allows for it so it should be tested.
			It("Listens multiple times", func() {
				cliConn, srvConn := net.Pipe()
				tun, err := tunnel.NewClientTunnel(srvConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(HaveOccurred())

				m := tunnelmgr.NewManager()
				defer func() { _ = m.Close() }()
				Expect(m.SetTunnel(tun)).ShouldNot(HaveOccurred())

				listener1, err := m.Listener()
				Expect(err).ShouldNot(HaveOccurred())
				listener2, err := m.Listener()
				Expect(err).ShouldNot(HaveOccurred())

				var wg sync.WaitGroup
				wg.Add(2)
				acceptAndRespondOnce(listener1, &wg, "200", "Response1")
				acceptAndRespondOnce(listener2, &wg, "200", "Response2")

				cliTun, err := tunnel.NewClientTunnel(cliConn)
				Expect(err).ShouldNot(HaveOccurred())
				cli := getClientFromOpener(cliTun)

				response1, err := cli.Get("http://example.com")
				Expect(err).ShouldNot(HaveOccurred())

				response2, err := cli.Get("http://example.com")
				Expect(err).ShouldNot(HaveOccurred())

				Expect(len(filter([]string{"Response1", "Response2"}, readResponseBody(response1), readResponseBody(response2)))).To(Equal(0))

				wg.Wait()
			})

			Context("Dialing for the tunnel", func() {
				It("Successfully dials for a tunnel and allows the user to get a listener", func() {
					cliConn, srvConn := net.Pipe()
					defer func() { _ = cliConn.Close() }()
					defer func() { _ = srvConn.Close() }()

					tun, err := tunnel.NewClientTunnel(cliConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
					Expect(err).ShouldNot(HaveOccurred())

					mockDialer := new(tunnel.MockDialer)
					mockDialer.On("Dial").Return(tun, nil)
					mockDialer.On("Timeout").Return(5 * time.Second)

					m := tunnelmgr.NewManagerWithDialer(mockDialer)
					defer func() { _ = m.Close() }()

					Eventually(func() error {
						_, err := m.Listener()
						return err
					}, "5s", "100ms").ShouldNot(HaveOccurred())
				})
				Context("when dialing hangs", func() {
					It("All functions access the manager state should return ErrStillDialing and then work without error"+
						"after the dialer has finished",
						func() {
							cliConn, srvConn := net.Pipe()
							defer func() { _ = cliConn.Close() }()

							srv := getServerFromConnection(srvConn, "Response")
							defer func() { _ = srv.Close() }()

							tun, err := tunnel.NewClientTunnel(cliConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
							Expect(err).ShouldNot(HaveOccurred())

							// We use this to block the dialer so we can test a hanging dialer
							waitChan := make(chan time.Time)
							defer close(waitChan)

							mockDialer := new(tunnel.MockDialer)
							mockDialer.On("Dial").Return(tun, nil).WaitUntil(waitChan)
							mockDialer.On("Timeout").Return(5 * time.Second)

							m := tunnelmgr.NewManagerWithDialer(mockDialer)
							defer func() { _ = m.Close() }()

							// While dialing all the functions should return ErrStillDialing errors.
							_, err = m.Listener()
							Expect(err).Should(Equal(tunnelmgr.ErrStillDialing))

							_, err = m.Open()
							Expect(err).Should(Equal(tunnelmgr.ErrStillDialing))

							_, err = m.OpenTLS(&tls.Config{})
							Expect(err).Should(Equal(tunnelmgr.ErrStillDialing))

							waitChan <- time.Now()

							// Once dialing is done we should be able to get listeners and open connections.
							Eventually(func() error {
								_, err := m.Listener()
								return err
							}, "5s", "100ms").ShouldNot(HaveOccurred())

							// If the previous check succeeded we know the dialing is complete so we don't need an eventually
							// check
							conn, err := m.Open()
							Expect(err).ShouldNot(HaveOccurred())
							Expect(conn).ShouldNot(BeNil())
						},
					)
				})
			})
		})
		Context("Manager closed", func() {
			It("returns errors", func() {
				m := tunnelmgr.NewManager()
				Expect(m.Close()).ShouldNot(HaveOccurred())
				_, err := m.Listener()
				Expect(err).Should(Equal(tunnelmgr.ErrManagerClosed))
				_, err = m.Open()
				Expect(err).Should(Equal(tunnelmgr.ErrManagerClosed))
				_, err = m.OpenTLS(&tls.Config{})
				Expect(err).Should(Equal(tunnelmgr.ErrManagerClosed))

				errChan := m.ListenForErrors()
				Expect(<-errChan).Should(Equal(tunnelmgr.ErrManagerClosed))
				cliConn, srvConn := net.Pipe()
				defer func() { _ = cliConn.Close() }()
				defer func() { _ = srvConn.Close() }()

				tun, err := tunnel.NewClientTunnel(srvConn, tunnel.WithKeepAliveSettings(true, 100*time.Second))
				Expect(err).ShouldNot(Equal(tunnelmgr.ErrManagerClosed))
				Expect(m.SetTunnel(tun)).Should(Equal(tunnelmgr.ErrManagerClosed))
			})
		})
	})
})

func getServerFromConnection(conn net.Conn, responses ...string) *http.Server {
	session, err := yamux.Server(conn, nil)
	if err != nil {
		panic(err)
	}

	srv := new(http.Server)
	rList := responseList{responses: responses}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(rList.Next()))
		Expect(err).ShouldNot(HaveOccurred())
	})
	go func() { _ = srv.Serve(session) }()
	return srv
}

func acceptAndRespondOnce(listener net.Listener, wg *sync.WaitGroup, status, body string) {
	go func() {
		defer GinkgoRecover()

		defer wg.Done()
		conn, err := listener.Accept()
		Expect(err).ShouldNot(HaveOccurred())
		Expect(conn).ShouldNot(BeNil())

		Expect(createResponse(status, body).Write(conn)).ShouldNot(HaveOccurred())
	}()
}

func createResponse(status, body string) *http.Response {
	closer := io.NopCloser(bytes.NewReader([]byte(body)))
	return &http.Response{
		Status:        status,
		ContentLength: int64(len(body)),
		Body:          closer,
	}
}

func readResponseBody(r *http.Response) string {
	body, err := io.ReadAll(r.Body)
	Expect(err).ShouldNot(HaveOccurred())
	return string(body)
}

func filter(p []string, filters ...string) []string {
	arr := make([]string, len(p))
	copy(arr, p)
	for _, filter := range filters {
		for i := 0; i < len(arr); i++ {
			if filter == arr[i] {
				if i < len(arr)-1 {
					arr = append([]string{}, append(arr[:i], arr[i+1:]...)...)
				} else {
					arr = arr[:i]
				}
			}
		}
	}

	return arr
}

func getClientFromOpener(o ConnOpener) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return o.Open()
			},
		},
	}
}
