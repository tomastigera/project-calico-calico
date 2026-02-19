package conn_test

import (
	"net"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/voltron/pkg/conn"
)

var _ = Describe("Forwarding connections", func() {
	Context("Forward", func() {
		It("sends connection data forwarded back and forward between the connections", func() {
			var dst1, dst2 net.Conn
			var err error

			By("creating two localhost listeners")
			lst1, err := net.Listen("tcp", "localhost:0")
			Expect(err).ShouldNot(HaveOccurred())
			lst2, err := net.Listen("tcp", "localhost:0")
			Expect(err).ShouldNot(HaveOccurred())

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				dst1, err = lst1.Accept()
				Expect(err).ShouldNot(HaveOccurred())
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				dst2, err = lst2.Accept()
				Expect(err).ShouldNot(HaveOccurred())
			}()

			By("connecting to those localhost listens")
			src1, err := net.Dial("tcp", lst1.Addr().String())
			src2, err := net.Dial("tcp", lst2.Addr().String())

			wg.Wait()

			wg.Add(1)
			go func() {
				defer wg.Done()
				conn.Forward(dst1, src2)
			}()

			request := "request"
			response := "response"
			By("listening for data on the dst2")
			go func() {
				buff := make([]byte, len(request))
				_, err := dst2.Read(buff)

				Expect(err).ShouldNot(HaveOccurred())
				Expect(string(buff)).Should(Equal(request))

				_, err = dst2.Write([]byte(response))
				Expect(err).ShouldNot(HaveOccurred())
			}()

			By("writing data on src1")
			_, err = src1.Write([]byte(request))
			Expect(err).ShouldNot(HaveOccurred())

			buff := make([]byte, len(response))
			_, err = src1.Read(buff)

			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(buff)).Should(Equal(response))
			Expect(src1.Close())
			wg.Wait()
		})
	})
})
