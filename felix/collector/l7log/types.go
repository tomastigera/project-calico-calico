// Copyright (c) 2021-2023 Tigera, Inc. All rights reserved.

package l7log

import (
	"fmt"
	"time"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
)

// L7 Update represents the data that is sent to us straight from the envoy logs?
type Update struct {
	Tuple tuple.Tuple
	SrcEp calc.EndpointData
	DstEp calc.EndpointData

	Duration      int
	DurationMax   int
	BytesReceived int
	BytesSent     int
	Latency       int

	ServiceName      string
	ServiceNamespace string
	ServicePortName  string
	ServicePortNum   int

	ResponseCode string
	Method       string
	Domain       string
	Path         string
	UserAgent    string
	Type         string
	Count        int
	RouteName    string
	GatewayName  string
	Protocol     string

	// Gateway API enrichment fields
	GatewayNamespace    string
	GatewayClass        string
	GatewayStatus       string
	GatewayStatusMessage string

	// Gateway listener context fields
	GatewayListenerName     string
	GatewayListenerPort     int
	GatewayListenerProtocol string
	GatewayListenerFullName string
	GatewayListenerHostname string

	// Route resource identification
	RouteNamespace    string
	RouteResourceName string
	RouteType         string

	// Gateway route context fields
	GatewayRouteType          string
	GatewayRouteName          string
	GatewayRouteNamespace     string
	GatewayRouteHostname      string
	GatewayRouteStatus        string
	GatewayRouteStatusMessage string
}

// L7Log represents the JSON representation of a L7Log we are pushing to fluentd/elastic.
type L7Log struct {
	StartTime int64 `json:"start_time"`
	EndTime   int64 `json:"end_time"`

	DurationMean time.Duration `json:"duration_mean"`
	DurationMax  time.Duration `json:"duration_max"`
	Latency      time.Duration `json:"latency"`
	BytesIn      int           `json:"bytes_in"`
	BytesOut     int           `json:"bytes_out"`
	Count        int           `json:"count"`

	// TODO: make a breaking change on the elastic schema + re-index to change these src_ fields to be prefixed by source_
	SourceNameAggr  string        `json:"src_name_aggr"` // aliased as source_name_aggr on ee_l7.template
	SourceNamespace string        `json:"src_namespace"` // aliased as source_namespace on ee_l7.template
	SourceType      endpoint.Type `json:"src_type"`      // aliased as source_type on ee_l7.template
	SourcePortNum   int           `json:"source_port_num"`

	DestNameAggr  string        `json:"dest_name_aggr"`
	DestNamespace string        `json:"dest_namespace"`
	DestType      endpoint.Type `json:"dest_type"`
	DestPortNum   int           `json:"dest_port_num"`

	DestServiceName      string `json:"dest_service_name"`
	DestServiceNamespace string `json:"dest_service_namespace"`
	// TODO: make a breaking change on the elastic schema + re-index to change this field to dest_service_port_name
	DestServicePortName string `json:"dest_service_port_name"`
	DestServicePortNum  int    `json:"dest_service_port"` // aliased as dest_service_port_num on ee_l7.template

	Method       string `json:"method"`
	UserAgent    string `json:"user_agent"`
	URL          string `json:"url"`
	ResponseCode string `json:"response_code"`
	RouteName    string `json:"route_name"`
	Type         string `json:"type"`
	GatewayName  string `json:"gateway_name"`
	Protocol     string `json:"protocol"`

	// Gateway API enrichment fields
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

	// Route resource identification
	RouteNamespace    string `json:"route_namespace,omitempty"`
	RouteResourceName string `json:"route_resource_name,omitempty"`
	RouteType         string `json:"route_type,omitempty"`

	// Gateway route context fields
	GatewayRouteType          string `json:"gateway_route_type,omitempty"`
	GatewayRouteName          string `json:"gateway_route_name,omitempty"`
	GatewayRouteNamespace     string `json:"gateway_route_namespace,omitempty"`
	GatewayRouteHostname      string `json:"gateway_route_hostname,omitempty"`
	GatewayRouteStatus        string `json:"gateway_route_status,omitempty"`
	GatewayRouteStatusMessage string `json:"gateway_route_status_message,omitempty"`
}

// L7Meta represents the identifiable information for an L7 log.
type L7Meta struct {
	SrcNameAggr   string
	SrcNamespace  string
	SrcType       endpoint.Type
	SourcePortNum int

	DestNameAggr  string
	DestNamespace string
	DestType      endpoint.Type
	DestPortNum   int

	ServiceName      string
	ServiceNamespace string
	ServicePortName  string
	ServicePortNum   int

	ResponseCode string
	RouteName    string
	GatewayName  string
	Protocol     string
	Method       string
	Domain       string
	Path         string
	UserAgent    string
	Type         string

	// Gateway API enrichment fields
	GatewayNamespace     string
	GatewayClass         string
	GatewayStatus        string
	GatewayStatusMessage string

	// Gateway listener context fields
	GatewayListenerName     string
	GatewayListenerPort     int
	GatewayListenerProtocol string
	GatewayListenerFullName string
	GatewayListenerHostname string

	// Route resource identification
	RouteNamespace    string
	RouteResourceName string
	RouteType         string

	// Gateway route context fields
	GatewayRouteType          string
	GatewayRouteName          string
	GatewayRouteNamespace     string
	GatewayRouteHostname      string
	GatewayRouteStatus        string
	GatewayRouteStatusMessage string
}

// L7Spec represents the stats and collections of L7 data
type L7Spec struct {
	Duration      int
	DurationMax   int
	BytesReceived int
	BytesSent     int
	Latency       int
	Count         int
}

func (a *L7Spec) Merge(b L7Spec) {
	a.Duration = a.Duration + b.Duration
	if b.DurationMax > a.DurationMax {
		a.DurationMax = b.DurationMax
	}
	a.BytesReceived = a.BytesReceived + b.BytesReceived
	a.BytesSent = a.BytesSent + b.BytesSent
	a.Latency = a.Latency + b.Latency
	a.Count = a.Count + b.Count
}

type L7Data struct {
	L7Meta
	L7Spec
}

const (
	L7LogTypeUnLogged string = "unlogged"
)

func (ld L7Data) ToL7Log(startTime, endTime time.Time) *L7Log {
	res := &L7Log{
		StartTime: startTime.Unix(),
		EndTime:   endTime.Unix(),
		BytesIn:   ld.BytesReceived,
		BytesOut:  ld.BytesSent,
		Count:     ld.Count,

		SourceNameAggr:  ld.SrcNameAggr,
		SourceNamespace: ld.SrcNamespace,
		SourceType:      ld.SrcType,
		SourcePortNum:   ld.SourcePortNum,

		DestNameAggr:  ld.DestNameAggr,
		DestNamespace: ld.DestNamespace,
		DestType:      ld.DestType,
		DestPortNum:   ld.DestPortNum,

		DestServiceName:      ld.ServiceName,
		DestServiceNamespace: ld.ServiceNamespace,
		DestServicePortName:  ld.ServicePortName,
		DestServicePortNum:   ld.ServicePortNum,

		Method:       ld.Method,
		UserAgent:    ld.UserAgent,
		ResponseCode: ld.ResponseCode,
		RouteName:    ld.RouteName,
		GatewayName:  ld.GatewayName,
		Protocol:     ld.Protocol,
		Type:         ld.Type,

		// Gateway API enrichment fields
		GatewayNamespace:     ld.GatewayNamespace,
		GatewayClass:         ld.GatewayClass,
		GatewayStatus:        ld.GatewayStatus,
		GatewayStatusMessage: ld.GatewayStatusMessage,

		// Gateway listener context fields
		GatewayListenerName:     ld.GatewayListenerName,
		GatewayListenerPort:     ld.GatewayListenerPort,
		GatewayListenerProtocol: ld.GatewayListenerProtocol,
		GatewayListenerFullName: ld.GatewayListenerFullName,
		GatewayListenerHostname: ld.GatewayListenerHostname,

		// Route resource identification
		RouteNamespace:    ld.RouteNamespace,
		RouteResourceName: ld.RouteResourceName,
		RouteType:         ld.RouteType,

		// Gateway route context fields
		GatewayRouteType:          ld.GatewayRouteType,
		GatewayRouteName:          ld.GatewayRouteName,
		GatewayRouteNamespace:     ld.GatewayRouteNamespace,
		GatewayRouteHostname:      ld.GatewayRouteHostname,
		GatewayRouteStatus:        ld.GatewayRouteStatus,
		GatewayRouteStatusMessage: ld.GatewayRouteStatusMessage,
	}

	// Calculate and convert durations
	res.DurationMean = (time.Duration(ld.Duration) * time.Millisecond) / time.Duration(ld.Count)
	res.DurationMax = time.Duration(ld.DurationMax) * time.Millisecond
	res.Latency = time.Duration(ld.Latency) * time.Millisecond

	// Create the URL from the domain and path
	// Path is expected to have a leading "/" character.
	if ld.Domain != utils.FieldNotIncluded && ld.Path != utils.FieldNotIncluded {
		res.URL = fmt.Sprintf("%s%s", ld.Domain, ld.Path)
	} else if ld.Domain != utils.FieldNotIncluded && ld.Path == utils.FieldNotIncluded {
		res.URL = ld.Domain
	}

	return res
}
