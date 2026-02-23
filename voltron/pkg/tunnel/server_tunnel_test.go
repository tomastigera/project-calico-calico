package tunnel_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/voltron/internal/pkg/test"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

func TestServerSideTunnel(t *testing.T) {
	RegisterTestingT(t)

	var (
		err     error
		srvCert *x509.Certificate
		clnCert *x509.Certificate

		lis net.Listener
		srv tunnel.Server
	)

	srvCert, err = test.CreateSelfSignedX509Cert("voltron", true)
	Expect(err).NotTo(HaveOccurred())

	clnCert, err = test.CreateSignedX509Cert("guardian", srvCert)
	Expect(err).NotTo(HaveOccurred())

	t.Run("server starts up", func(t *testing.T) {
		lis, err = net.Listen("tcp", "localhost:0")
		Expect(err).ShouldNot(HaveOccurred())

		cert, err := tls.X509KeyPair(test.CertToPemBytes(srvCert), []byte(test.PrivateRSA))
		Expect(err).ShouldNot(HaveOccurred())

		srv, err = tunnel.NewServer(
			tunnel.WithServerCert(cert),
			tunnel.WithClientCert(srvCert),
			tunnel.WithTLSHandshakeTimeout(200*time.Millisecond),
		)
		Expect(err).NotTo(HaveOccurred())

		go func() {
			_ = srv.ServeTLS(lis)
		}()

		t.Run("should be possible to open a mTLS connection with a correct cert", func(t *testing.T) {
			var (
				err error
				wg  sync.WaitGroup
			)

			var srvT tunnel.Tunnel
			wg.Go(func() {
				var err error
				srvT, err = srv.AcceptTunnel()
				Expect(err).ShouldNot(HaveOccurred())
			})

			certPem := test.PemEncodeCert(clnCert)
			cert, err := tls.X509KeyPair(certPem, []byte(test.PrivateRSA))
			Expect(err).NotTo(HaveOccurred())

			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(srvCert)

			cliT, err := tunnel.DialTLS(lis.Addr().String(), &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: rootCAs}, 5*time.Second, nil)
			Expect(err).ShouldNot(HaveOccurred())
			wg.Wait()

			t.Run("open connections from both sides", func(t *testing.T) {
				t.Log("should be able to send data s -> c")
				clnS, err := cliT.Open()
				Expect(err).ToNot(HaveOccurred())
				defer func() { _ = clnS.Close() }()

				srvS, err := srvT.Accept()
				Expect(err).ToNot(HaveOccurred())
				defer func() { _ = srvS.Close() }()

				recvMsg, err := test.DataFlow(clnS, srvS, []byte("HELLO"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(recvMsg)).To(Equal("HELLO"))

				t.Log("should be able to send data s <- c")
				recvMsg, err = test.DataFlow(srvS, clnS, []byte("WORLD"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(recvMsg)).To(Equal("WORLD"))

				srvS2, err := srvT.Open()
				Expect(err).ToNot(HaveOccurred())
				defer func() { _ = srvS2.Close() }()

				clnS2, err := cliT.Accept()
				Expect(err).ToNot(HaveOccurred())
				defer func() { _ = clnS2.Close() }()

				recvMsg, err = test.DataFlow(clnS2, srvS2, []byte("HELLO"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(recvMsg)).To(Equal("HELLO"))

				t.Log("should be able to send data s <- c")
				recvMsg, err = test.DataFlow(srvS2, clnS2, []byte("WORLD"))
				Expect(err).ToNot(HaveOccurred())
				Expect(string(recvMsg)).To(Equal("WORLD"))

				t.Log("should be able to send data s -> c from both sides concurrently")
				var wg sync.WaitGroup

				rwRun := func(r io.Reader, w io.Writer, msg string) {
					wg.Go(func() {
						_, _ = test.DataFlow(r, w, []byte(msg))
					})
				}

				rwRun(srvS, clnS, "clnS says hi to srvS")
				rwRun(clnS, srvS, "srvS says hi back to clnS")
				rwRun(srvS2, clnS2, "clnS2 says hi to srvS2")
				rwRun(clnS2, srvS2, "srvS2 says hi back to clnS2")

				wg.Wait()
			})

			t.Run("non tls connections should fail", func(t *testing.T) {
				clnC, err := net.Dial("tcp", lis.Addr().String())
				Expect(err).ShouldNot(HaveOccurred())

				_, err = srv.Accept()
				Expect(err).Should(HaveOccurred())

				Eventually(func() error {
					_, err := clnC.Write([]byte("blah"))
					return err
				}).ShouldNot(Succeed())
			})

			t.Run("tunnels should be unusable when server stopped", func(t *testing.T) {
				srv.Stop()

				_, err := cliT.Accept()
				Expect(err).Should(HaveOccurred())

				_, err = cliT.Open()
				Expect(err).Should(HaveOccurred())
			})
		})

	})
}
