// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package api

import (
	"context"

	accesslogv3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
)

const (
	ProtocolTCP string = "tcp"
)

type EnvoyCollector interface {
	ReadLogs(context.Context)
	Report() <-chan EnvoyInfo
	ParseRawLogs(string) (EnvoyLog, error)
	ReadAccessLogs(context.Context)
	ParseAccessLogs(string) (EnvoyLog, error)
	ReceiveLogs(*accesslogv3.HTTPAccessLogEntry)
	Start(context.Context)
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

	Protocol    string `json:"protocol"`
	SrcIp       string
	DstIp       string
	SrcPort     int32
	DstPort     int32
	Count       int32
	DurationMax int32
	Latency     int32
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
