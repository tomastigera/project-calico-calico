package tls

import (
	"crypto/tls"
	"net"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("extractSNI", func() {
	It("tests a server name can be extracted from the client hello", func() {
		src, dst := net.Pipe()
		serverName := "test.servername.svc"
		cli := tls.Client(src, &tls.Config{
			ServerName: serverName,
		})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cli.Handshake(); err != nil {
				log.Error(err)
			}
		}()
		extractedServerName, bytesRead, err := extractSNI(dst)

		Expect(err).ShouldNot(HaveOccurred())
		Expect(extractedServerName).Should(Equal(serverName))
		Expect(len(bytesRead)).Should(BeNumerically(">", 0))
	})

	It("test we receive the expected error when trying to extract the SNI from an non https connection", func() {
		src, dst := net.Pipe()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := src.Write([]byte("ting\r\n"))
			Expect(err).ShouldNot(HaveOccurred())
		}()
		extractedServerName, bytesRead, err := extractSNI(dst)

		Expect(err).Should(BeAssignableToTypeOf(tls.RecordHeaderError{}))
		Expect(extractedServerName).Should(Equal(""))
		Expect(len(bytesRead)).Should(BeNumerically(">", 0))
	})

})
