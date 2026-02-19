package tls_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/voltron/internal/pkg/utils"
	vtls "github.com/projectcalico/calico/voltron/pkg/tls"
)

type mockListener struct {
	conns chan net.Conn
}

var errConnectionClosed = errors.New("connection closed")

func (m *mockListener) Accept() (net.Conn, error) {
	conn, ok := <-m.conns
	if !ok {
		return nil, errConnectionClosed
	}
	return conn, nil
}

func (m *mockListener) Close() error {
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

var _ = Describe("ListenAndProxy", func() {
	Context("WithProxyOnSNI set to true", func() {
		It("proxies the request to the url defined in the map passed to WithSNIServiceMap", func() {
			serverName := "test.host.svc"

			listener, err := net.Listen("tcp", ":0")
			Expect(err).ShouldNot(HaveOccurred())

			p, err := vtls.NewProxy(
				vtls.WithProxyOnSNI(true),
				vtls.WithSNIServiceMap(map[string]string{
					serverName: listener.Addr().String(),
				}),
			)
			Expect(err).ShouldNot(HaveOccurred())

			src, dst := net.Pipe()

			rootCAs, cert, err := getCerts()
			Expect(err).ShouldNot(HaveOccurred())

			cli := tls.Client(src, &tls.Config{
				ServerName: serverName,
				RootCAs:    rootCAs,
			})

			requestString := "test request\r\n"

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				_, err := cli.Write([]byte(requestString))
				Expect(err).ShouldNot(HaveOccurred())
			}()

			conns := make(chan net.Conn, 1)
			conns <- dst

			wg.Add(1)
			go func() {
				defer wg.Done()
				Expect(p.ListenAndProxy(&mockListener{conns})).Should(Equal(errConnectionClosed))
			}()

			testDownstreamServer(listener, cert, requestString)
			close(conns)
			wg.Wait()
		})

		It("proxies the request to the default URL if a default URL is specified and no match is found for the SNI", func() {
			serverName := "test.host.svc"

			listener, err := net.Listen("tcp", ":0")
			Expect(err).ShouldNot(HaveOccurred())

			p, err := vtls.NewProxy(
				vtls.WithProxyOnSNI(true),
				vtls.WithDefaultServiceURL(listener.Addr().String()),
				vtls.WithSNIServiceMap(map[string]string{
					"othername": "doesnotexist.com",
				}),
			)

			Expect(err).ShouldNot(HaveOccurred())

			src, dst := net.Pipe()

			rootCAs, cert, err := getCerts()
			Expect(err).ShouldNot(HaveOccurred())

			cli := tls.Client(src, &tls.Config{
				ServerName: serverName,
				RootCAs:    rootCAs,
			})

			requestString := "test request\r\n"

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				_, err := cli.Write([]byte(requestString))
				Expect(err).ShouldNot(HaveOccurred())
			}()

			conns := make(chan net.Conn, 1)
			conns <- dst

			wg.Add(1)
			go func() {
				defer wg.Done()
				Expect(p.ListenAndProxy(&mockListener{conns})).Should(Equal(errConnectionClosed))
			}()

			testDownstreamServer(listener, cert, requestString)
			close(conns)
			wg.Wait()
		})

		It("proxies the request to the default URL if no SNI was found", func() {
			listener, err := net.Listen("tcp", ":0")
			Expect(err).ShouldNot(HaveOccurred())

			p, err := vtls.NewProxy(
				vtls.WithProxyOnSNI(true),
				vtls.WithDefaultServiceURL(listener.Addr().String()),
				vtls.WithSNIServiceMap(map[string]string{
					"othername": "doesnotexist.com",
				}),
			)

			Expect(err).ShouldNot(HaveOccurred())

			src, dst := net.Pipe()

			rootCAs, cert, err := getCerts()
			Expect(err).ShouldNot(HaveOccurred())

			cli := tls.Client(src, &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            rootCAs,
			})

			testRequest := "test request\r\n"

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := cli.Write([]byte(testRequest)); err != nil {
					log.Error(err)
				}
			}()

			conns := make(chan net.Conn, 1)
			conns <- dst

			wg.Add(1)
			go func() {
				defer GinkgoRecover()

				defer wg.Done()
				Expect(p.ListenAndProxy(&mockListener{conns})).Should(Equal(errConnectionClosed))
			}()

			testDownstreamServer(listener, cert, testRequest)
			close(conns)
			wg.Wait()
		})
		It("proxies the request to the default URL if WithProxyOnSNI disabled", func() {
			listener, err := net.Listen("tcp", ":0")
			Expect(err).ShouldNot(HaveOccurred())

			p, err := vtls.NewProxy(
				vtls.WithDefaultServiceURL(listener.Addr().String()),
			)

			Expect(err).ShouldNot(HaveOccurred())

			src, dst := net.Pipe()

			rootCAs, cert, err := getCerts()
			Expect(err).ShouldNot(HaveOccurred())

			cli := tls.Client(src, &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            rootCAs,
			})

			testRequest := "test request\r\n"

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := cli.Write([]byte(testRequest)); err != nil {
					log.Error(err)
				}
			}()

			conns := make(chan net.Conn, 1)
			conns <- dst

			wg.Add(1)
			go func() {
				defer wg.Done()
				Expect(p.ListenAndProxy(&mockListener{conns})).Should(Equal(errConnectionClosed))
			}()

			testDownstreamServer(listener, cert, testRequest)
			close(conns)
			wg.Wait()
		})
	})

	Context("Shutdown", func() {
		It("closes the outstanding connection when the listener is closed", func() {
			p, err := vtls.NewProxy(
				vtls.WithDefaultServiceURL("somedomain"),
			)
			Expect(err).ShouldNot(HaveOccurred())
			conns := make(chan net.Conn, 1)
			src, dst := net.Pipe()
			conns <- dst

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				Expect(p.ListenAndProxy(&mockListener{conns})).Should(Equal(errConnectionClosed))
			}()

			wg.Add(1)
			done := failAfter(1 * time.Second)
			go func() {
				defer close(done)
				defer wg.Done()
				buff := make([]byte, 4096)
				for {
					if _, err := src.Read(buff); err != nil {
						// an error indicates closure
						break
					}
				}
			}()

			close(conns)
			wg.Wait()
		})
	})

	/*Context("MaxConnectionConcurrency", func() {
		It("tests we respect the max concurrency limit, processing connections up to the limit but not beyond it", func() {
			listener, err := net.Listen("tcp", ":0")
			Expect(err).ShouldNot(HaveOccurred())

			p, err := vtls.NewProxy(
				vtls.WithDefaultServiceURL(listener.Addr().String()),
				vtls.WithMaxConcurrentConnections(2),
			)

			Expect(err).ShouldNot(HaveOccurred())

			src1, dst1 := net.Pipe()
			src2, dst2 := net.Pipe()
			src3, dst3 := net.Pipe()

			Expect(err).ShouldNot(HaveOccurred())

			var wg sync.WaitGroup

			conns := make(chan net.Conn, 3)
			conns <- dst1
			conns <- dst2
			conns <- dst3

			go func() {
				defer GinkgoRecover()

				Expect(p.ListenAndProxy(&mockListener{conns})).Should(Equal(errConnectionClosed))
			}()

			wg.Add(1)
			go func() {
				defer GinkgoRecover()

				defer wg.Done()
				conn1, err := listener.Accept()
				Expect(err).ShouldNot(HaveOccurred())

				conn2, err := listener.Accept()
				Expect(err).ShouldNot(HaveOccurred())

				closed := false
				go func() {
					defer GinkgoRecover()

					_, err := listener.Accept()
					// This tests that the connection is blocked by the proxy until a previous connection is closed
					Expect(err).ShouldNot(HaveOccurred())
					Expect(closed).Should(BeTrue())
				}()

				time.Sleep(1 * time.Second)

				closed = true
				Expect(conn2.Close()).ShouldNot(HaveOccurred())

				_ = conn1
				_ = conn2
			}()

			rootCAs, _, err := getCerts()
			Expect(err).ShouldNot(HaveOccurred())

			cli := tls.Client(src1, &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            rootCAs,
			})

			cli2 := tls.Client(src2, &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            rootCAs,
			})

			cli3 := tls.Client(src3, &tls.Config{
				InsecureSkipVerify: true,
				RootCAs:            rootCAs,
			})

			go func() { _ = cli.Handshake() }()
			go func() { _ = cli2.Handshake() }()
			go func() { _ = cli3.Handshake() }()

			wg.Wait()
			close(conns)
		}, 100)
	})*/
})

func failAfter(duration time.Duration) chan struct{} {
	ticker := time.NewTicker(duration)
	done := make(chan struct{})

	go func() {
		defer GinkgoRecover()
		defer ticker.Stop()

		select {
		case <-done:
		case <-ticker.C:
			Fail("timed out")
		}
	}()

	return done
}

func testDownstreamServer(listener net.Listener, cert tls.Certificate, expectedRequest string) {
	conn, err := listener.Accept()
	Expect(err).ShouldNot(HaveOccurred())
	srv := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      x509.NewCertPool(),
	})
	err = srv.Handshake()
	Expect(err).ShouldNot(HaveOccurred())

	requestBytes := make([]byte, 4096)
	i, err := srv.Read(requestBytes)
	Expect(err).ShouldNot(HaveOccurred())

	requestString := string(requestBytes[:i])
	Expect(requestString).Should(Equal(expectedRequest))
	Expect(conn.Close()).ShouldNot(HaveOccurred())
}

func getCerts() (*x509.CertPool, tls.Certificate, error) {
	keyx, err := utils.LoadX509Key("testdata/key")
	if err != nil {
		panic(err)
	}

	certx, err := utils.LoadX509Cert("testdata/cert")
	if err != nil {
		panic(err)
	}

	keybytes, err := utils.KeyPEMEncode(keyx)
	if err != nil {
		panic(err)
	}
	cert, err := tls.X509KeyPair(utils.CertPEMEncode(certx), keybytes)
	if err != nil {
		panic(err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(certx)

	return rootCAs, cert, err
}
