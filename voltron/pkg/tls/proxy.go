package tls

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/voltron/pkg/conn"
)

// Proxy allows you to proxy https connections with redirection based on the SNI in the client hello
type Proxy interface {
	ListenAndProxy(listener net.Listener) error
}

type proxy struct {
	defaultURL               string
	proxyOnSNI               bool
	sniServiceMap            map[string]string
	retryAttempts            int
	retryInterval            time.Duration
	connectTimeout           time.Duration
	maxConcurrentConnections int

	// Server used by the proxy for connections directly to Voltron.
	server        *http.Server
	innerListener MultiListener
}

const (
	defaultRetryAttempts            = 5
	defaultRetryInterval            = 2 * time.Second
	defaultConnectTimeout           = 30 * time.Second
	defaultMaxConcurrentConnections = 500
)

// NewProxy creates and returns a new Proxy instance
func NewProxy(options ...ProxyOption) (Proxy, error) {
	p := &proxy{
		retryAttempts:            defaultRetryAttempts,
		retryInterval:            defaultRetryInterval,
		connectTimeout:           defaultConnectTimeout,
		maxConcurrentConnections: defaultMaxConcurrentConnections,
		innerListener:            NewMultiListener(),
	}

	for _, option := range options {
		if err := option(p); err != nil {
			return nil, err
		}
	}

	if p.defaultURL == "" && !p.proxyOnSNI {
		return nil, errors.New("either a default url must be provided or ProxyOnSNI must be enabled")
	}

	if p.proxyOnSNI && len(p.sniServiceMap) == 0 {
		return nil, errors.New("proxyOnSNI has been set but no SNI service map has been provided")
	}

	return p, nil
}

// ListenAndProxy listens for connections on the given listener and proxies the data sent on them. If proxyOnSNI is enabled
// then this proxy will attempt to extract out the SNI from the TLS request and proxy it.
func (p *proxy) ListenAndProxy(listener net.Listener) error {
	// tokenPool is generated here so that it can be closed before we return. This stops us from needing a "Close" function
	// for the proxy, and allows us to use the same proxy multiple times.
	tokenPool := make(chan struct{}, p.maxConcurrentConnections)
	for i := 0; i < p.maxConcurrentConnections; i++ {
		tokenPool <- struct{}{}
	}
	defer close(tokenPool)

	var wg sync.WaitGroup

	err := p.acceptConnections(listener, tokenPool, &wg)

	wg.Wait()

	return err
}

// acceptConnections accepts connections from the given listener. Before accepting a connection a token is taken off the
// the given token pool, and put back into the pool when we're finished with the connection. This ensures we don't go past
// our maximum connection concurrency limit.
// The WaitGroup should be waited on, and Wait will return once all the go routines have finished
func (p *proxy) acceptConnections(listener net.Listener, tokenPool chan struct{}, wg *sync.WaitGroup) error {
	shutDown := make(chan struct{})

	// ensure that we close any connections that are open when returning from this function (this triggers a close of all
	// outstanding connections)
	defer close(shutDown)

	if p.server != nil {
		// Start a goroutine which serves TLS for inner connections received over the tunnel for Voltron.
		// This routine will handle connections from managed cluster clients to Linseed. Connections received
		// over the mTLS tunnel will be passed to this server via the proxies inner listener.
		go func() {
			for {
				// We don't need to pass a key / cert, since the server TLS configuration already
				// includes them.
				err := p.server.ServeTLS(p.innerListener, "", "")
				if err != nil {
					logrus.WithError(err).Errorf("Error handling a local connection")
				}

				// Avoid tight-looping by sleeping.
				time.Sleep(1 * time.Second)
			}
		}()
	}

	// Listen for tunnel connections from guardian.
	for {
		token := <-tokenPool
		srcConn, err := listener.Accept()
		if err != nil {
			return err
		}

		wg.Add(1)
		go func(conn net.Conn, token struct{}) {
			defer wg.Done()
			defer func() { tokenPool <- token }()

			if err := p.proxyConnectionWithConfirmedShutdown(conn, shutDown); err != nil {
				logrus.WithError(err).Error("failed to proxy the connection")
				// If an error was returned, then the source connection wasn't closed, so close it
				if err := conn.Close(); err != nil {
					logrus.WithError(err).Debug("failed to close source connection")
				}
			}
		}(srcConn, token)
	}
}

// proxyConnectionWithConfirmedShutdown makes sure that the connection is closed when the shutDown channel is closed
func (p *proxy) proxyConnectionWithConfirmedShutdown(srcConn net.Conn, shutDown chan struct{}) error {
	done := make(chan struct{})
	defer close(done)

	go func(srcConn net.Conn, done chan struct{}, shutDown chan struct{}) {
		select {
		case <-shutDown:
			if err := srcConn.Close(); err != nil {
				logrus.WithError(err).Error("failed to close connection after shutdown")
			}
		case <-done:
		}
	}(srcConn, done, shutDown)

	return p.proxyConnection(srcConn)
}

// proxyLocal proxies the given connection using this particular cluster's HTTPS server.
func (p *proxy) proxyLocal(srcConn net.Conn) error {
	p.innerListener.Send(srcConn)
	return nil
}

// proxyConnection proxies the data from the given connection to the downstream (downstream is determined by the SNI settings
// / the default URL). If this connection is not a tls connection then it will return an error.
func (p *proxy) proxyConnection(srcConn net.Conn) error {
	url := p.defaultURL
	var bytesRead []byte

	// We try to extract the SNI so that we can verify this is a tls connection
	serverName, bytesRead, err := extractSNI(srcConn)
	if err != nil {
		logrus.WithError(err).Error("failed to extract SNI from connection")
		return err
	}

	if p.proxyOnSNI {
		if serverName != "" {
			if serverNameURL, ok := p.sniServiceMap[serverName]; ok {
				logrus.Debugf("Extracted SNI '%s' from client hello", serverName)
				url = serverNameURL
			}
		}
	}

	if isLinseedServerName(serverName) {
		// This connection is destined to Linseed from over the mTLS tunnel with Guardian.
		// Rather than forward the connection, we should handle it ourselves. Terminate TLS and proxy onwards.
		c := NewLocalConnection(srcConn, bytesRead)
		return p.proxyLocal(c)
	}

	logrus.Debugf("Proxying connection with server name '%s' to '%s'", serverName, url)

	if url == "" {
		return errors.New("couldn't figure out where to send the request")
	}

	dstConn, err := p.dial(url)
	if err != nil {
		logrus.WithError(err).Errorf("failed to open a connection to %s", url)
		if err := srcConn.Close(); err != nil {
			logrus.WithError(err).Error("failed to close source connection")
		}
		return nil
	}

	if len(bytesRead) > 0 {
		if err := writeBytesToConn(bytesRead, dstConn); err != nil {
			if err := dstConn.Close(); err != nil {
				logrus.WithError(err).Debug("failed to close destination connection")
			}

			return err
		}
	}

	conn.Forward(srcConn, dstConn)

	return nil
}

func isLinseedServerName(serverName string) bool {
	linseedHostMatches := []string{
		"tigera-linseed",
		"tigera-linseed.tigera-elasticsearch.svc",
		"tigera-linseed.tigera-elasticsearch.svc.cluster.local",
	}
	return slices.Contains(linseedHostMatches, serverName)
}

func writeBytesToConn(bytes []byte, conn net.Conn) error {
	bytesWritten := 0
	for bytesWritten < len(bytes) {
		i, err := conn.Write(bytes[bytesWritten:])
		if err != nil {
			return err
		}

		bytesWritten += i
	}

	return nil
}

func (p *proxy) dial(url string) (net.Conn, error) {
	var dstConn net.Conn
	var err error

	// retryAttempts+1 for the initial dial
	for i := 1; i <= p.retryAttempts+1; i++ {
		dstConn, err = net.DialTimeout("tcp", url, p.connectTimeout)
		if err == nil {
			return dstConn, nil
		}

		logrus.WithError(err).Errorf("failed to open a connection to %s, will retry in %d seconds (attempt %d of %d)", url, p.retryInterval, i, p.retryAttempts+1)
		time.Sleep(p.retryInterval)
	}

	return nil, err
}

func NewLocalConnection(src net.Conn, alreadyRead []byte) net.Conn {
	ar := bytes.NewBuffer(alreadyRead)
	return &localConnection{
		reader: io.MultiReader(ar, src),
		src:    src,
	}
}

// localConnection is a wrapper around a connection that has already had some bytes read from it,
// to allow for reading the entire stream of bytes from the connection. Calls to Read() will return
// the already read bytes first, until there are none, and then will read directly from the connection.
type localConnection struct {
	reader io.Reader
	src    net.Conn
}

func (l *localConnection) Read(b []byte) (int, error) {
	return l.reader.Read(b)
}

func (l *localConnection) Write(b []byte) (n int, err error) {
	return l.src.Write(b)
}

func (l *localConnection) Close() error {
	return l.src.Close()
}

func (l *localConnection) LocalAddr() net.Addr {
	return l.src.LocalAddr()
}

func (l *localConnection) RemoteAddr() net.Addr {
	return l.src.RemoteAddr()
}

func (l *localConnection) SetDeadline(t time.Time) error {
	return l.src.SetDeadline(t)
}

func (l *localConnection) SetReadDeadline(t time.Time) error {
	return l.src.SetReadDeadline(t)
}

func (l *localConnection) SetWriteDeadline(t time.Time) error {
	return l.src.SetWriteDeadline(t)
}
