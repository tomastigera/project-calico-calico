// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package fv

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

var dialer = &net.Dialer{
	Timeout:   30 * time.Second,
	KeepAlive: 30 * time.Second,
}

func dialContextFromLocalPort(port int) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// This is a workaround to avoid triggering "Host header is a numeric IP address" WAF rule in tests.
		if strings.HasPrefix(addr, "example.com") {
			addr = fmt.Sprintf("127.0.0.1:%d", port)
		}
		return dialer.DialContext(ctx, network, addr)
	}
}
