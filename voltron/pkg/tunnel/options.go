package tunnel

import (
	"time"
)

// Option is a common format for New() options
type Option func(*tunnel) error

// WithKeepAliveSettings sets the Keep Alive settings for the tunnel.
func WithKeepAliveSettings(enable bool, intervalDuration time.Duration) Option {
	return func(t *tunnel) error {
		t.keepAliveEnable = enable
		t.keepAliveInterval = intervalDuration
		return nil
	}
}

// WithDialTimeout sets the dial timeout for the tunnel.
func WithDialTimeout(dialTimeout time.Duration) Option {
	return func(t *tunnel) error {
		t.dialTimeout = dialTimeout
		return nil
	}
}
