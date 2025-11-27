// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package query

import (
	"fmt"
)

var (
	L7LogsKeys = map[string]Validator{
		"host":                       NullValidator,
		"start_time":                 DateValidator,
		"end_time":                   DateValidator,
		"duration_mean":              PositiveIntValidator,
		"duration_max":               PositiveIntValidator,
		"bytes_in":                   PositiveIntValidator,
		"bytes_out":                  PositiveIntValidator,
		"count":                      PositiveIntValidator,
		"latency":                    PositiveIntValidator,
		"source_type":                SetValidator("wep", "hep", "ns", "net"),
		"source_name_aggr":           DomainValidator,
		"source_namespace":           DomainValidator,
		"source_port_num":            IntRangeValidator(0, MaxTCPUDPPortNum),
		"src_type":                   SetValidator("wep", "hep", "ns", "net"),
		"src_name_aggr":              DomainValidator,
		"src_namespace":              DomainValidator,
		"dest_type":                  SetValidator("wep", "hep", "ns", "net"),
		"dest_name":                  DomainValidator,
		"dest_name_aggr":             DomainValidator,
		"dest_namespace":             DomainValidator,
		"dest_port_num":              IntRangeValidator(0, MaxTCPUDPPortNum),
		"dest_service_name":          DomainValidator,
		"dest_service_namespace":     DomainValidator,
		"dest_service_port":          IntRangeValidator(0, MaxTCPUDPPortNum),
		"dest_service_port_num":      IntRangeValidator(0, MaxTCPUDPPortNum),
		"dest_service_port_name":     DomainValidator,
		"method":                     NullValidator,
		"user_agent":                 NullValidator,
		"url":                        URLValidator,
		"response_code":              NullValidator,
		"type":                       NullValidator,
		"gateway_name":               NullValidator,
		"gateway_namespace":          NullValidator,
		"gateway_route_name":         NullValidator,
		"gateway_route_namespace":    NullValidator,
		"gateway_listener_full_name": NullValidator,
		"gateway_class":              NullValidator,
		"gateway_status":             NullValidator,
		"gateway_route_status":       NullValidator,
	}
)

func IsValidL7LogsAtom(a *Atom) error {
	if validator, ok := L7LogsKeys[a.Key]; ok {
		return validator(a)
	}

	return fmt.Errorf("invalid key: %s", a.Key)
}
