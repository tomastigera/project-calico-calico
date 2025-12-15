package tunnel

import (
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lma/pkg/logutils"
)

// NewClientTunnel returns a new tunnel that uses the provided stream as the
// carrier. The stream must be the client side of the stream
func NewClientTunnel(stream io.ReadWriteCloser, opts ...Option) (Tunnel, error) {
	t := &tunnel{
		stream: stream,
		errCh:  make(chan struct{}),
		// Defaults
		keepAliveEnable: true,

		keepAliveInterval: 100 * time.Millisecond,
		dialTimeout:       60 * time.Second,
	}

	var mux *yamux.Session
	var err error

	for _, o := range opts {
		if err := o(t); err != nil {
			return nil, errors.WithMessage(err, "applying option failed")
		}
	}

	// XXX all the config options should probably become options taken by New()
	// XXX that can override the defaults set here
	config := yamux.DefaultConfig()
	config.AcceptBacklog = 1000
	config.EnableKeepAlive = t.keepAliveEnable
	config.KeepAliveInterval = t.keepAliveInterval
	config.LogOutput = logutils.NewLogrusWriter(logrus.WithField("component", "tunnel-yamux"))

	mux, err = yamux.Client(stream, config)

	if err != nil {
		return nil, fmt.Errorf("new failed creating muxer: %s", err)
	}

	t.mux = mux

	return t, nil
}
