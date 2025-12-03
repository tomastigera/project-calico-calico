package tunnelmgr_test

import (
	"crypto/tls"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/lib/std/chanutil"
	mocknet "github.com/projectcalico/calico/voltron/pkg/thirdpartymocks/net"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
	"github.com/projectcalico/calico/voltron/pkg/tunnelmgr"
)

type fakeAddr struct{}

func (f fakeAddr) Network() string {
	return ""
}

func (f fakeAddr) String() string {
	return "127.0.0.1:1234"
}

func TestManager(t *testing.T) {
	RegisterTestingT(t)
	t.Run("Open", func(t *testing.T) {
		t.Run("Successfully opens a single connection over the tunnel", func(t *testing.T) {
			tunnelErrors := make(chan struct{}, 2)
			defer close(tunnelErrors)

			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().Open().Return(new(mocknet.Conn), nil).Once()
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().Close().Return(nil)

			mgr := tunnelmgr.NewManager()
			defer func() { _ = mgr.Close() }()
			Expect(mgr.SetTunnel(mockTunnel)).ShouldNot(HaveOccurred())

			conn, err := mgr.Open()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(conn).ShouldNot(BeNil())

			Expect(mgr.CloseTunnel()).ShouldNot(HaveOccurred())
		})
		t.Run("Tunnel manager supports multiple open connections", func(t *testing.T) {
			tunnelErrors := make(chan struct{}, 2)
			defer close(tunnelErrors)

			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().Open().Return(new(mocknet.Conn), nil).Twice()
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().Close().Return(nil)

			mgr := tunnelmgr.NewManager()
			defer func() { _ = mgr.Close() }()
			Expect(mgr.SetTunnel(mockTunnel)).ShouldNot(HaveOccurred())

			conn, err := mgr.Open()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(conn).ShouldNot(BeNil())

			conn, err = mgr.Open()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(conn).ShouldNot(BeNil())

			Expect(mgr.CloseTunnel()).ShouldNot(HaveOccurred())
		})
		t.Run("Returns an error if the tunnel was closed before calling Open", func(t *testing.T) {
			tunnelErrors := make(chan struct{}, 2)

			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().LastErr().Return(tunnel.ErrTunnelClosed)

			mgr := tunnelmgr.NewManager()
			defer func() { _ = mgr.Close() }()
			Expect(mgr.SetTunnel(mockTunnel)).ShouldNot(HaveOccurred())
			errs := mgr.ListenForErrors()
			close(tunnelErrors)

			// Wait for the error to be returned.
			Eventually(errs).Should(Receive())

			conn, err := mgr.Open()
			Expect(err).Should(Equal(tunnel.ErrTunnelClosed))
			Expect(conn).Should(BeNil())
		})
	})

	t.Run("Listener", func(t *testing.T) {
		t.Run("Retrieves a listener from the tunnel successfully", func(t *testing.T) {
			mgr := tunnelmgr.NewManager()
			defer func() { _ = mgr.Close() }()

			done := make(chan bool)
			tunnelErrors := make(chan struct{}, 2)

			var connChan chan tunnel.ConnOrError
			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().AcceptWithChannel(mock.Anything).RunAndReturn(func(acceptChan chan tunnel.ConnOrError) chan bool {
				connChan = acceptChan
				return done
			})
			mockTunnel.EXPECT().Addr().Return(fakeAddr{})
			mockTunnel.EXPECT().Close().Return(nil)

			Expect(mgr.SetTunnel(mockTunnel)).ShouldNot(HaveOccurred())

			listener, err := mgr.Listener()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listener).ShouldNot(BeNil())

			Expect(chanutil.WriteWithDeadline(t.Context(), connChan, tunnel.ConnOrError{Conn: new(mocknet.Conn)}, 5*time.Second)).ShouldNot(HaveOccurred())
			conn, err := listener.Accept()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(conn).ShouldNot(BeNil())
		})
		t.Run("Retrieves multiple listener from the tunnel successfully", func(t *testing.T) {
			mgr := tunnelmgr.NewManager()
			defer func() { _ = mgr.Close() }()

			done := make(chan bool)
			tunnelErrors := make(chan struct{}, 2)

			var connChan1, connChan2 chan tunnel.ConnOrError
			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().AcceptWithChannel(mock.Anything).RunAndReturn(func(acceptChan chan tunnel.ConnOrError) chan bool {
				connChan1 = acceptChan
				return done
			}).Once()
			mockTunnel.EXPECT().AcceptWithChannel(mock.Anything).RunAndReturn(func(acceptChan chan tunnel.ConnOrError) chan bool {
				connChan2 = acceptChan
				return done
			}).Once()

			mockTunnel.EXPECT().Addr().Return(fakeAddr{})
			mockTunnel.EXPECT().Close().Return(nil)

			Expect(mgr.SetTunnel(mockTunnel)).ShouldNot(HaveOccurred())

			listener1, err := mgr.Listener()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listener1).ShouldNot(BeNil())

			Expect(chanutil.WriteWithDeadline(t.Context(), connChan1, tunnel.ConnOrError{Conn: new(mocknet.Conn)}, 5*time.Second)).ShouldNot(HaveOccurred())
			conn1, err := listener1.Accept()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(conn1).ShouldNot(BeNil())

			listener2, err := mgr.Listener()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listener2).ShouldNot(BeNil())

			Expect(chanutil.WriteWithDeadline(t.Context(), connChan2, tunnel.ConnOrError{Conn: new(mocknet.Conn)}, 5*time.Second)).ShouldNot(HaveOccurred())
			conn2, err := listener2.Accept()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(conn2).ShouldNot(BeNil())
		})
		t.Run("receives an error when the connection is closed while waiting to accept a connection", func(t *testing.T) {
			mgr := tunnelmgr.NewManager()
			defer func() { _ = mgr.Close() }()

			done := make(chan bool)
			tunnelErrors := make(chan struct{}, 2)

			var connChan chan tunnel.ConnOrError
			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().AcceptWithChannel(mock.Anything).RunAndReturn(func(acceptChan chan tunnel.ConnOrError) chan bool {
				connChan = acceptChan
				return done
			})
			mockTunnel.EXPECT().Addr().Return(fakeAddr{})
			mockTunnel.EXPECT().Close().Return(nil)

			Expect(mgr.SetTunnel(mockTunnel)).ShouldNot(HaveOccurred())

			listener, err := mgr.Listener()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(listener).ShouldNot(BeNil())

			close(connChan)

			conn, err := listener.Accept()
			Expect(err).Should(Equal(tunnel.ErrTunnelClosed))
			Expect(conn).Should(BeNil())
		})
		t.Run("Successfully dials for a tunnel", func(t *testing.T) {
			done := make(chan bool)
			tunnelErrors := make(chan struct{}, 2)

			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().AcceptWithChannel(mock.Anything).Return(done)
			mockTunnel.EXPECT().Addr().Return(fakeAddr{})
			mockTunnel.EXPECT().Close().Return(nil)

			mockDialer := new(tunnel.MockDialer)
			mockDialer.On("Dial").Return(mockTunnel, nil)
			mockDialer.On("Timeout").Return(5 * time.Second)

			mgr := tunnelmgr.NewManagerWithDialer(mockDialer)
			defer func() { _ = mgr.Close() }()

			Eventually(func() error {
				_, err := mgr.Listener()
				return err
			}, "5s", "100ms").ShouldNot(HaveOccurred())
		})
		t.Run("Returns an error when it's still dialing", func(t *testing.T) {
			done := make(chan bool)
			tunnelErrors := make(chan struct{}, 2)

			mockTunnel := new(tunnel.MockTunnel)
			mockTunnel.EXPECT().ErrChan().Return(tunnelErrors)
			mockTunnel.EXPECT().AcceptWithChannel(mock.Anything).Return(done)
			mockTunnel.EXPECT().Addr().Return(fakeAddr{})
			mockTunnel.EXPECT().Close().Return(nil)

			waitChan := make(chan time.Time)
			defer close(waitChan)

			mockDialer := new(tunnel.MockDialer)
			mockDialer.On("Dial").Return(mockTunnel, nil).WaitUntil(waitChan)
			mockDialer.On("Timeout").Return(5 * time.Second)

			mgr := tunnelmgr.NewManagerWithDialer(mockDialer)
			defer func() { _ = mgr.Close() }()

			_, err := mgr.Listener()
			Expect(err).Should(Equal(tunnelmgr.ErrStillDialing))

			waitChan <- time.Now()

			Eventually(func() error {
				_, err := mgr.Listener()
				return err
			}, "5s", "100ms").ShouldNot(HaveOccurred())
		})
	})

	t.Run("Closed manager returns errors", func(t *testing.T) {
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

		mockTunnel := new(tunnel.MockTunnel)
		Expect(m.SetTunnel(mockTunnel)).Should(Equal(tunnelmgr.ErrManagerClosed))
	})
}
