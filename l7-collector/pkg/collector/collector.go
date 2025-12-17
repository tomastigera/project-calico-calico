// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package collector

import (
	"context"
	"sync"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/l7-collector/pkg/config"
)

const (
	ProtocolTCP string = "tcp"
)

const (
	LogTypeTCP string = "tcp"
	LogTypeTLS string = "tls"
)

type EnvoyCollector interface {
	ReadLogs(context.Context)
	Report() <-chan EnvoyInfo
	ParseRawLogs(string) (EnvoyLog, error)
	ReadAccessLogs(context.Context, LicenseChecker)
	ParseAccessLogs(string) (EnvoyLog, error)
	ReceiveLogs(*accesslogv3.HTTPAccessLogEntry)
	Start(context.Context)
	SetEnricher(EnvoyLogEnricher)
}

func NewEnvoyCollector(cfg *config.Config, ch chan EnvoyInfo) EnvoyCollector {
	// Currently it will only return a log file collector but
	// this should inspect the config to return other collectors
	// once they need to be implemented.
	return EnvoyCollectorNew(cfg, ch)
}

type EnvoyInfo struct {
	Logs        map[EnvoyLogKey]EnvoyLog
	Connections map[TupleKey]int
}

type EnvoyLog struct {
	// some of the fields are relevant for collector only and are not sent to felix Ex. RequestId, StartTime etc
	// for the information that is sent to felix check HttpData proto
	Reporter      string `json:"reporter"`
	StartTime     string `json:"start_time"`
	Duration      int32  `json:"duration"`
	ResponseCode  int32  `json:"response_code"`
	BytesSent     int32  `json:"bytes_sent"`
	BytesReceived int32  `json:"bytes_received"`
	UserAgent     string `json:"user_agent"`
	RequestPath   string `json:"request_path"`
	RequestMethod string `json:"request_method"`
	RequestId     string `json:"request_id"`
	Type          string `json:"type"`
	Domain        string `json:"domain"`
	RouteName     string `json:"route_name"`

	// these are the addresses we extract 5 tuple information from
	DSRemoteAddress string `json:"downstream_remote_address"`
	DSLocalAddress  string `json:"downstream_local_address"`

	// used to calculate latency
	UpstreamServiceTime string `json:"upstream_service_time"`

	// gateway specific fields
	// This represents the main address of the upstream host to which Envoy is proxying the request. Envoy var: %UPSTREAM_HOST%
	UpstreamHost string `json:"upstream_host"`
	// This represents the address of the gateway that is proxying the request. Envoy var: %UPSTREAM_LOCAL_ADDRESS%
	UpstreamLocalAddress string `json:"upstream_local_address"`
	// This represents the address of the downstream direct remote address host that is proxying the request. Envoy var: %DOWNSTREAM_DIRECT_REMOTE_ADDRESS%
	// This is if your Gateway is deployed with a direct connection to the client, without any proxy in between. (Edge, Mobile, etc.)
	DSDirectRemoteAddress string `json:"downstream_direct_remote_address"`
	// This represents the address of the downstream local address host that is proxying the request.
	// This is if your Gateway is deployed with trusted proxies in between the client and the gateway.
	// Requires the proper XFF (xff_num_trusted_hops) configuration to be set in the gateway.
	// Envoy var: %REQ(X-FORWARDED-FOR)%
	XForwardedFor string `json:"x_forwarded_for"`
	GatewayName   string `json:"gateway_name"`
	Protocol      string `json:"protocol"`

	SrcIp       string
	DstIp       string
	SrcPort     int32
	DstPort     int32
	Count       int32
	DurationMax int32
	Latency     int32

	// Gateway API enrichment fields (populated by gateway collector's enricher)
	GatewayNamespace     string `json:"gateway_namespace,omitempty"`
	GatewayClass         string `json:"gateway_class,omitempty"`
	GatewayStatus        string `json:"gateway_status,omitempty"`
	GatewayStatusMessage string `json:"gateway_status_message,omitempty"`

	// Gateway listener context fields
	GatewayListenerName     string `json:"gateway_listener_name,omitempty"`
	GatewayListenerPort     int    `json:"gateway_listener_port,omitempty"`
	GatewayListenerProtocol string `json:"gateway_listener_protocol,omitempty"`
	GatewayListenerFullName string `json:"gateway_listener_full_name,omitempty"`
	GatewayListenerHostname string `json:"gateway_listener_hostname,omitempty"`

	// Collector identification fields
	CollectorName string `json:"collector_name,omitempty"`
	CollectorType string `json:"collector_type,omitempty"`
	Host          string `json:"host,omitempty"`

	// Gateway route context fields
	GatewayRouteType          string `json:"gateway_route_type,omitempty"`
	GatewayRouteName          string `json:"gateway_route_name,omitempty"`
	GatewayRouteNamespace     string `json:"gateway_route_namespace,omitempty"`
	GatewayRouteHostname      string `json:"gateway_route_hostname,omitempty"`
	GatewayRouteStatus        string `json:"gateway_route_status,omitempty"`
	GatewayRouteStatusMessage string `json:"gateway_route_status_message,omitempty"`
}

// TupleKey is an object just for holding the
// Envoy log's 5 tuple information. Since the protocol is always tcp its replaced by type
type TupleKey struct {
	SrcIp   string
	DstIp   string
	SrcPort int32
	DstPort int32
	Type    string
}

// EnvoyLogKey is an object that contains all the distinct information we get from logs
// used as a key for de-duplication for http and tcp logs
type EnvoyLogKey struct {
	TupleKey TupleKey

	UserAgent     string
	RequestPath   string
	RequestMethod string
	ResponseCode  int32
	Domain        string
}

type BatchEnvoyLog struct {
	logs map[EnvoyLogKey]EnvoyLog
	size int
	mu   sync.Locker
}

func NewBatchEnvoyLog(size int) *BatchEnvoyLog {
	return &BatchEnvoyLog{
		logs: make(map[EnvoyLogKey]EnvoyLog),
		size: size,
		mu:   &sync.Mutex{},
	}
}

func (b *BatchEnvoyLog) Insert(entry EnvoyLog) {
	b.mu.Lock()
	defer b.mu.Unlock()

	log.Debugf("Inserting log into batch: %v", entry)

	logKey := GetEnvoyLogKey(entry)
	// for tcp and tls types we don't get much information so we treat this as a single connection and
	// add the duration, bytes_sent, bytes_received.
	// same goes for cases where http logs comes with same EnvoyLogKey (same l7 fields) for multiple requests
	// this happens even when the batch is full
	if val, ok := b.logs[logKey]; ok {
		// set max duration per request level
		if entry.Duration > val.DurationMax {
			val.DurationMax = entry.Duration
		}

		val.Duration = val.Duration + entry.Duration
		val.Latency = val.Latency + entry.Latency
		val.BytesReceived = val.BytesReceived + entry.BytesReceived
		val.BytesSent = val.BytesSent + entry.BytesSent
		val.Count++
		b.logs[logKey] = val
	} else {
		// add unique logs ony to the batch, if there is space otherwise we drop it
		if !b.full() {
			entry.Count = 1
			entry.DurationMax = entry.Duration
			b.logs[logKey] = entry
		}
	}
}

func (b *BatchEnvoyLog) GetLogs() map[EnvoyLogKey]EnvoyLog {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.logs
}

func GetEnvoyLogKey(entry EnvoyLog) EnvoyLogKey {
	// We create a key using all the distinct values we get for each type
	// for TCP it's just the 5 tuple information, for http we include all the other l7 info fields
	return EnvoyLogKey{
		TupleKey:      TupleKeyFromEnvoyLog(entry),
		UserAgent:     entry.UserAgent,
		RequestPath:   entry.RequestPath,
		RequestMethod: entry.RequestMethod,
		ResponseCode:  entry.ResponseCode,
		Domain:        entry.Domain,
	}
}

func (b *BatchEnvoyLog) full() bool {
	if b.size < 0 {
		return false
	}
	return len(b.logs) == b.size
}

func TupleKeyFromEnvoyLog(entry EnvoyLog) TupleKey {
	return TupleKey{
		SrcIp:   entry.SrcIp,
		DstIp:   entry.DstIp,
		SrcPort: entry.SrcPort,
		DstPort: entry.DstPort,
		Type:    entry.Type,
	}
}

func EnvoyLogFromTupleKey(key TupleKey) EnvoyLog {
	return EnvoyLog{
		SrcIp:    key.SrcIp,
		DstIp:    key.DstIp,
		SrcPort:  key.SrcPort,
		DstPort:  key.DstPort,
		Type:     key.Type,
		Protocol: ProtocolTCP,
	}
}
