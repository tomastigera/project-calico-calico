package tunnel_test

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	testutils "github.com/projectcalico/calico/voltron/pkg/cryptoutils/testutils"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

func TestClientTunnel(t *testing.T) {
	RegisterTestingT(t)

	t.Run("receives a connection when the server side opens the connection", func(t *testing.T) {
		cliConn, srvConn := testutils.TLSPipe()
		tun, err := tunnel.NewClientTunnel(cliConn)
		Expect(err).ToNot(HaveOccurred())

		connResults := make(chan tunnel.ConnOrError)
		done := tun.AcceptWithChannel(connResults)
		defer close(done)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer GinkgoRecover()

			defer wg.Done()
			result := <-connResults
			Expect(result.Error).ToNot(HaveOccurred())
			Expect(result.Conn).ToNot(BeNil())
		}()

		srvTunnel, err := tunnel.NewServerTunnel(srvConn)
		Expect(err).ShouldNot(HaveOccurred())
		_, err = srvTunnel.Open()
		Expect(err).ShouldNot(HaveOccurred())

		wg.Wait()
	})

	t.Run("channel is closed when the tunnel is closed", func(t *testing.T) {
		cliConn, srvConn := net.Pipe()
		tun, err := tunnel.NewClientTunnel(cliConn)
		Expect(err).ToNot(HaveOccurred())

		connResults := make(chan tunnel.ConnOrError)
		done := tun.AcceptWithChannel(connResults)
		defer close(done)

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer GinkgoRecover()

			defer wg.Done()
			_, ok := <-connResults
			Expect(ok).ShouldNot(BeTrue())
		}()

		Expect(srvConn.Close()).ToNot(HaveOccurred())
		wg.Wait()
	})

	t.Run("DialInRoutineWithTimeout", func(t *testing.T) {
		t.Run("sends the tunnel over the result channel if dialing was successful", func(t *testing.T) {
			mockDialer := new(tunnel.MockDialer)
			mockDialer.On("Dial").Return(new(tunnel.MockTunnel), nil)

			results := make(chan tunnel.TunnelOrError)

			closeChan := tunnel.DialInRoutineWithTimeout(mockDialer, results, 2*time.Second)
			defer close(closeChan)

			timer := time.NewTimer(1 * time.Second)
			defer timer.Stop()

			select {
			case result, ok := <-results:
				Expect(ok).Should(BeTrue())
				Expect(result.Error).ShouldNot(HaveOccurred())
			case <-timer.C:
				Fail("timed out waiting for result")
			}

			mockDialer.AssertExpectations(GinkgoT())
		})

		t.Run("sends the error over the result channel if dialing returned an error", func(t *testing.T) {
			mockDialer := new(tunnel.MockDialer)
			mockDialer.On("Dial").Return(nil, fmt.Errorf("failed to dial"))

			results := make(chan tunnel.TunnelOrError)

			closeChan := tunnel.DialInRoutineWithTimeout(mockDialer, results, 2*time.Second)
			defer close(closeChan)

			timer := time.NewTimer(1 * time.Second)
			defer timer.Stop()

			select {
			case result, ok := <-results:
				Expect(ok).Should(BeTrue())
				Expect(result.Error).Should(HaveOccurred())
			case <-timer.C:
				Fail("timed out waiting for result")
			}

			mockDialer.AssertExpectations(GinkgoT())
		})

		t.Run("returns nothing and closes the results channel if the close channel was closed", func(t *testing.T) {
			mockDialer := new(tunnel.MockDialer)
			mockDialer.On("Dial").Return(nil, fmt.Errorf("failed to dial"))

			results := make(chan tunnel.TunnelOrError)

			closeChan := tunnel.DialInRoutineWithTimeout(mockDialer, results, 2*time.Second)
			close(closeChan)

			// Wait a second just in case it takes a moment to close the channel.
			time.Sleep(1 * time.Second)

			timer := time.NewTimer(1 * time.Second)
			defer timer.Stop()

			// We expect the results channel to be closed.
			select {
			case _, ok := <-results:
				Expect(ok).Should(BeFalse())
			case <-timer.C:
				Fail("timed out waiting for result")
			}

			mockDialer.AssertExpectations(GinkgoT())
		})

		t.Run("returns nothing and closes the results channel if the close channel was closed", func(t *testing.T) {
			mockDialer := new(tunnel.MockDialer)
			mockDialer.On("Dial").Return(nil, fmt.Errorf("failed to dial"))

			results := make(chan tunnel.TunnelOrError)

			closeChan := tunnel.DialInRoutineWithTimeout(mockDialer, results, 100*time.Millisecond)
			defer close(closeChan)

			time.Sleep(1 * time.Second)

			timer := time.NewTimer(1 * time.Second)
			defer timer.Stop()

			// We expect the results channel to be closed.
			select {
			case _, ok := <-results:
				Expect(ok).Should(BeFalse())
			case <-timer.C:
				Fail("timed out waiting for result")
			}

			mockDialer.AssertExpectations(GinkgoT())
		})
	})
}
