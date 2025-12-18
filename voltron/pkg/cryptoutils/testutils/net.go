package cryptoutils

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync"

	"github.com/onsi/gomega"

	"github.com/projectcalico/calico/voltron/pkg/cryptoutils"
)

func TLSPipe() (*tls.Conn, *tls.Conn) {
	cliConn, srvConn := net.Pipe()

	rsaKey, err := cryptoutils.GenerateRSAKey()
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	ca, err := cryptoutils.CreateCertificateAuthority(cryptoutils.WithRSAPrivateKey(rsaKey))
	gomega.Expect(err).ShouldNot(gomega.HaveOccurred())

	serverTLSCert, err := cryptoutils.CreateServerTLSCertificate(
		cryptoutils.WithRSAPrivateKey(rsaKey),
		cryptoutils.WithParent(ca),
		cryptoutils.WithDNSNames("voltron"),
	)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	clientTLSCert, err := cryptoutils.CreateClientTLSCertificate(
		cryptoutils.WithParent(ca),
		cryptoutils.WithRSAPrivateKey(rsaKey),
		cryptoutils.WithDNSNames("guardian"),
	)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(ca)

	var wg sync.WaitGroup
	var tlsServerConn *tls.Conn
	wg.Add(2)
	go func() {
		defer wg.Done()
		tlsServerConn = tls.Server(srvConn, &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    rootCAs,
			Certificates: []tls.Certificate{serverTLSCert},
		})
		gomega.Expect(tlsServerConn.Handshake()).ShouldNot(gomega.HaveOccurred())
	}()

	var tlsClientConn *tls.Conn
	go func() {
		defer wg.Done()
		tlsClientConn = tls.Client(cliConn, &tls.Config{
			RootCAs:      rootCAs,
			ServerName:   "voltron",
			Certificates: []tls.Certificate{clientTLSCert},
		})
		gomega.Expect(tlsClientConn.Handshake()).ShouldNot(gomega.HaveOccurred())
	}()

	wg.Wait()

	return tlsClientConn, tlsServerConn
}
