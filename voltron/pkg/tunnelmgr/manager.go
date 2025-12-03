package tunnelmgr

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/chanutil"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

// ErrManagerClosed is returned when a closed manager is used
var ErrManagerClosed = fmt.Errorf("manager closed")

// ErrTunnelSet is returned when the tunnel has already been set and you try to set it again with one of the SetTunnel.
var ErrTunnelSet = fmt.Errorf("tunnel already set")

// ErrStillDialing is returned when trying to open or accept a connection from the tunnel but the manager is still trying
// to open the tunnel with a dialer. This would only be returned if a dialer was set, i.e. creating a manager with
// NewManagerWithDialer.
var ErrStillDialing = fmt.Errorf("cannot access tunnel yet, still dialing")

// Manager is an interface used to manage access to tunnel(s). It synchronises access to the tunnel(s), and abstracts
// out logic necessary to interact with the tunnel(s). The main motivation for this was that both sides of the
// tunnel need to open and accept connections on a single tunnel, so instead of duplicating that logic on both the client
// and server side of the tunnel, it is abstracted out into a single component that both sides can use.
//
// [TODO] <brian mcmahon> The SetTunnel function required here may make this interface not very well defined. Currently
// [TODO] the implementation would only use SetTunnel on the "server" side of the tunnel (the side not initiating the
// [TODO] connection. We've rolled up "dialing" for the tunnel on the client side into the Manager implementation, it may
// [TODO] be a good idea to roll up "answering" that call in the Manager as well, instead of "answering" that call outside
// [TODO] of the Manager and passing the tunnel to the Manager.
type Manager interface {
	SetTunnel(t tunnel.Tunnel) error
	Open() (net.Conn, error)
	OpenTLS(*tls.Config) (net.Conn, error)
	Listener() (net.Listener, error)
	ListenForErrors() chan error
	CloseTunnel() error
	Close() error
}

type manager struct {
	setTunnel ThreadExchange[tunnel.Tunnel, any]
	dialer    tunnel.Dialer

	openConnection    ThreadExchange[*tls.Config, net.Conn]
	addListener       ThreadExchange[any, *listener]
	addErrorListener  ThreadExchange[any, chan error]
	dialerResultsChan chan tunnel.TunnelOrError

	errListeners []chan error

	tun        tunnel.Tunnel
	tunnelErrs chan struct{}

	closeTunnel ThreadExchange[any, any]
	// This is used to notify the listener that the manager is closed
	close chan struct{}
	// This is used to notify that the manager is actually closed.
	closed chan struct{}

	closeOnce sync.Once
}

// NewManager returns an instance of the Manager interface.
func NewManager() Manager {
	m := newManager()

	go m.startStateLoop()
	return m
}

func newManager() *manager {
	return &manager{
		setTunnel:        make(ThreadExchange[tunnel.Tunnel, any]),
		openConnection:   make(ThreadExchange[*tls.Config, net.Conn]),
		addListener:      make(ThreadExchange[any, *listener]),
		addErrorListener: make(ThreadExchange[any, chan error]),
		closeTunnel:      make(ThreadExchange[any, any]),
		close:            make(chan struct{}),
		closed:           make(chan struct{}),
	}
}

// NewManagerWithDialer returns an instance of the Manager interface that uses uses the given dialer to open connections
// over the tunnel.
func NewManagerWithDialer(dialer tunnel.Dialer) Manager {
	m := newManager()

	m.dialer = dialer

	go m.startStateLoop()
	return m
}

// startStateLoop starts the loop to accept requests over the channels used to synchronously access the manager's state.
// Access the manager's state this way ensures we don't run into deadlocks or race conditions when a tunnel is used for
// both opening and accepting connections.
func (m *manager) startStateLoop() {
	// Dialing to the tunnel is done in a separate go routine so it doesn't block the state loop and this channel is
	// used to send the dialing result back to the state loop.
	var dialerCloseChan chan struct{}
	defer func() {
		close(m.setTunnel)
		close(m.openConnection)
		close(m.addListener)
		close(m.addErrorListener)
		close(m.closeTunnel)

		// If dialerCloseChan isn't nil then it's guaranteed to not be closed since the switch case that closes the channel
		// sets dialerCloseChan to nil immediately.
		if dialerCloseChan != nil {
			close(dialerCloseChan)
		}
		if m.tun != nil {
			_ = m.tun.Close()
		}

		close(m.closed)
	}()

	for {
		if m.tun == nil && m.dialer != nil && (m.dialerResultsChan == nil) {
			m.dialerResultsChan = make(chan tunnel.TunnelOrError)
			dialerCloseChan = tunnel.DialInRoutineWithTimeout(m.dialer, m.dialerResultsChan, 2*time.Second)
		}

		if m.tun != nil {
			m.tunnelErrs = m.tun.ErrChan()
		}

		select {
		case req := <-m.setTunnel:
			log.Debug("Received request to set a new tunnel.")

			if m.tun != nil {
				req.ReturnError(ErrTunnelSet)
			} else {
				m.tun = req.Get()
				req.Return(nil)
			}
		case result := <-m.dialerResultsChan:
			log.Debug("Received result for dialer channel.")
			close(dialerCloseChan)

			// It's the responsibility of the channel writer to close the channel, so at this point we can assume it's
			// safe to set it to nil (if it's not closed, this is an error with the channel writer).
			m.dialerResultsChan = nil
			dialerCloseChan = nil

			if result.Error != nil {
				m.handleError(result.Error)
			} else {
				// The tunnel will always be unset at this point since we only dial if it's not set.
				m.tun = result.Tunnel
				m.tunnelErrs = m.tun.ErrChan()
			}
		case req := <-m.openConnection:
			log.Debug("Received request open a new connection.")

			conn, err := m.handleOpenConnection(req.Get())
			if err != nil {
				req.ReturnError(err)

				if errors.Is(err, tunnel.ErrTunnelClosed) {
					m.tun = nil
					m.tunnelErrs = nil
				}
			} else {
				req.Return(conn)
			}

		case req := <-m.addListener:
			log.Debug("Received request for a new listener.")
			listener, err := m.handleAddListener()
			if err != nil {
				req.ReturnError(err)

				if errors.Is(err, tunnel.ErrTunnelClosed) {
					m.tun = nil
					m.tunnelErrs = nil
				}
			} else {
				req.Return(listener)
			}
		case req := <-m.addErrorListener:
			log.Debug("Received request to add a new err listener.")

			errListener := make(chan error, 1)
			m.errListeners = append(m.errListeners, errListener)
			req.Return(errListener)
		case req := <-m.closeTunnel:
			log.Debug("Received request to close the tunnel.")
			if m.tun == nil {
				req.ReturnError(tunnel.ErrTunnelClosed)
			} else {
				if err := m.tun.Close(); err != nil {
					log.WithError(err).Error("An error occurred while closing the tunnel.")
				}
				m.tun = nil
				m.tunnelErrs = nil

				req.Return(nil)
			}
		case <-m.tunnelErrs:
			log.Debug("Received a tunnel error.")
			if m.tun != nil {
				m.handleError(m.tun.LastErr())
			}
		case <-m.close:
			log.Debug("Received request to close the tunnel manager.")
			return
		}
	}
}

func (m *manager) tunnel() (tunnel.Tunnel, error) {
	if m.dialerResultsChan != nil {
		log.Debug("Still dialing tunnel.")
		return nil, ErrStillDialing
	}

	if m.tun == nil {
		log.Debug("Tunnel is nil.")
		return nil, tunnel.ErrTunnelClosed
	}

	return m.tun, nil
}

func (m *manager) handleError(err error) {
	for _, listener := range m.errListeners {
		chanutil.WriteNonBlocking(listener, err)
	}

	if errors.Is(err, tunnel.ErrTunnelClosed) {
		m.tun = nil
		m.tunnelErrs = nil
	}
}

// handleOpenConnection is used by the state loop to handle a request to open a connection over the tunnel
func (m *manager) handleOpenConnection(tlsCfg *tls.Config) (net.Conn, error) {
	tun, err := m.tunnel()
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		return tun.OpenTLS(tlsCfg)
	}

	return tun.Open()
}

// handleAddListener is used by the request loop to handle a request to retrieve a listener listening over the tunnel
func (m *manager) handleAddListener() (*listener, error) {
	tun, err := m.tunnel()
	if err != nil {
		return nil, err
	}

	// A buffer size of 10 is chosen to give some room in case multiple connections are being established to stop
	// the underlying muxer from blocking. This is theoretical, but it doesn't hurt to give it a little room to
	// work with.
	conResults := make(chan tunnel.ConnOrError, 10)
	done := tun.AcceptWithChannel(conResults)
	return &listener{
		conns: conResults,
		done:  done,
		addr:  tun.Addr(),
		close: m.close,
	}, nil
}

// SetTunnel sets the tunnel for the manager and returns an error if it's already running.
func (m *manager) SetTunnel(t tunnel.Tunnel) error {
	if m.isClosed() {
		return ErrManagerClosed
	}

	_, err := m.setTunnel.Send(context.Background(), t)
	return err
}

// Open opens a connection over the tunnel
func (m *manager) Open() (net.Conn, error) {
	if m.isClosed() {
		return nil, ErrManagerClosed
	}

	return m.openConnection.Send(context.Background(), nil)
}

// OpenTLS opens a tls connection over the tunnel
func (m *manager) OpenTLS(cfg *tls.Config) (net.Conn, error) {
	if m.isClosed() {
		return nil, ErrManagerClosed
	}

	return m.openConnection.Send(context.Background(), cfg)
}

// Listener retrieves a listener listening on the tunnel for connections
func (m *manager) Listener() (net.Listener, error) {
	if m.isClosed() {
		return nil, ErrManagerClosed
	}

	return m.addListener.Send(context.Background(), nil)
}

// ListenForErrors allows the user to register a channel to listen to errors on
func (m *manager) ListenForErrors() chan error {
	if m.isClosed() {
		errChan := make(chan error, 1)
		errChan <- ErrManagerClosed
		close(errChan)
		return errChan
	}

	errChan, _ := m.addErrorListener.Send(context.Background(), nil)
	return errChan
}

// CloseTunnel closes the managers tunnel. If a dialer is set (i.e. NewManagerWithDialer was used to create the Manager)
// then the Manager will try to re open a connection over the tunnel. If there is no dialer set (i.e. NewManager was used
// to create the Manager) then the Manager will wait for a tunnel to be set using SetTunnel.
func (m *manager) CloseTunnel() error {
	if m.isClosed() {
		return ErrManagerClosed
	}

	_, err := m.closeTunnel.Send(context.Background(), true)
	return err
}

func (m *manager) isClosed() bool {
	select {
	case <-m.close:
		return true
	default:
		return false
	}
}

// Close closes the manager. A closed manager cannot be reused.
func (m *manager) Close() error {
	m.closeOnce.Do(func() {
		close(m.close)
	})

	// Give the manager 5 seconds to close, just in case it needs it (which it shouldn't) to avoid hanging forever.
	_, err := chanutil.ReadWithDeadline(context.Background(), m.closed, 5*time.Second)
	if !errors.Is(err, chanutil.ErrChannelClosed) {
		return err
	}
	return nil
}
