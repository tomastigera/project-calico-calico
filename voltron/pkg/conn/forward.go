package conn

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// Forward sends all data coming from the srcConn to the dstConn, and all data coming from dstConn to srcConn. Both
// srcConn and dstConn are closed when this function returns
func Forward(srcConn net.Conn, dstCon net.Conn) {
	var wg sync.WaitGroup

	wg.Add(2)
	go forwardConnection(srcConn, dstCon, &wg)
	go forwardConnection(dstCon, srcConn, &wg)

	wg.Wait()
}

// forwardConnection forwards data from srcConn to dstConn. This function attempts to close both srcConn and dstConn, and
// ignores all "use of closed network connection" errors, as these errors are benign.
func forwardConnection(srcConn net.Conn, dstCon net.Conn, wg *sync.WaitGroup) {
	defer func() {
		if err := srcConn.Close(); err != nil && !isUseOfClosedNetworkErr(err) {
			log.WithError(err).Error("failed to close src connection")
		}
	}()
	defer func() {
		if err := dstCon.Close(); err != nil && !isUseOfClosedNetworkErr(err) {
			log.WithError(err).Error("failed to close dst connection")
		}
	}()
	defer wg.Done()

	if _, err := io.Copy(dstCon, srcConn); err != nil && !isUseOfClosedNetworkErr(err) && !isConnectionResetErr(err) {
		log.WithError(err).Error("failed to forward data")
	}
}

func isUseOfClosedNetworkErr(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	switch err := err.(type) {
	case *net.OpError:
		if strings.Contains(err.Err.Error(), "use of closed network connection") {
			return true
		}
	}
	return false
}

// isConnectionResetErr returns true if the error is due to a connection reset. These are benign and do not warrant
// a log statement. Done as a result of CI-1763.
func isConnectionResetErr(err error) bool {
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	if strings.Contains(err.Error(), "connection reset by peer") {
		return true
	}
	return false
}
