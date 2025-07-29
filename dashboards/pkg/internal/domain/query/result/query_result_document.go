package result

import (
	"net"
	"time"
)

type QueryResultDocument struct {
	Timestamp time.Time
	Content   any
}

func QueryResultDocumentContentIP(ip *net.IP) string {
	if ip == nil {
		return "0.0.0.0"
	}
	return ip.String()
}
