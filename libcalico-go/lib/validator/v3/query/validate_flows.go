// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	"fmt"
	"strconv"
)

func ProtoValidator(a *Atom) error {
	switch a.Value {
	case "icmp", "tcp", "udp", "ipip", "esp", "icmp6":
		return nil
	}

	_, err := strconv.ParseInt(a.Value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid value for %s: %s: %s", a.Key, a.Value, err)
	}

	return nil
}

var (
	flowsKeys = map[string]Validator{
		"start_time":                      DateValidator,
		"end_time":                        DateValidator,
		"action":                          SetValidator("allow", "deny"),
		"bytes_in":                        PositiveIntValidator,
		"bytes_out":                       PositiveIntValidator,
		"source_ip":                       IPValidator,
		"source_type":                     SetValidator("wep", "hep", "ns", "net"),
		"source_name":                     DomainValidator,
		"source_name_aggr":                DomainValidator,
		"source_namespace":                DomainValidator,
		"source_port":                     IntRangeValidator(0, MaxTCPUDPPortNum),
		"source_port_num":                 IntRangeValidator(0, MaxTCPUDPPortNum),
		"source_labels.labels":            RegexpValidator("^[^=]+=[^=]+$"),
		"dest_ip":                         IPValidator,
		"dest_type":                       SetValidator("wep", "hep", "ns", "net"),
		"dest_name":                       DomainValidator,
		"dest_name_aggr":                  DomainValidator,
		"dest_namespace":                  DomainValidator,
		"dest_port":                       IntRangeValidator(0, MaxTCPUDPPortNum),
		"dest_port_num":                   IntRangeValidator(0, MaxTCPUDPPortNum),
		"dest_service_name":               DomainValidator,
		"dest_service_namespace":          DomainValidator,
		"dest_service_port":               DomainValidator,
		"dest_service_port_num":           IntRangeValidator(0, MaxTCPUDPPortNum),
		"dest_service_port_name":          DomainValidator,
		"dest_labels.labels":              RegexpValidator("^[^=]+=[^=]+$"),
		"dest_domains":                    NullValidator,
		"host":                            NullValidator,
		"reporter":                        SetValidator("src", "dst"),
		"num_flows":                       PositiveIntValidator,
		"num_flows_completed":             PositiveIntValidator,
		"num_flows_started":               PositiveIntValidator,
		"http_requests_allowed_in":        PositiveIntValidator,
		"http_requests_denied_in":         PositiveIntValidator,
		"packets_in":                      PositiveIntValidator,
		"packets_out":                     PositiveIntValidator,
		"proto":                           ProtoValidator,
		"policies.all_policies":           NullValidator,
		"policies.enforced_policies":      NullValidator,
		"policies.pending_policies":       NullValidator,
		"policies.transit_policies":       NullValidator,
		"original_source_ips":             IPValidator,
		"num_original_source_ips":         PositiveIntValidator,
		"process_name":                    DomainValidator,
		"num_process_names":               PositiveIntValidator,
		"process_id":                      DomainValidator,
		"num_process_ids":                 PositiveIntValidator,
		"process_args":                    NullValidator,
		"num_process_args":                PositiveIntValidator,
		"tcp_lost_packets":                PositiveIntValidator,
		"tcp_max_min_rtt":                 PositiveIntValidator,
		"tcp_max_smooth_rtt":              PositiveIntValidator,
		"tcp_mean_min_rtt":                PositiveIntValidator,
		"tcp_mean_mss":                    PositiveIntValidator,
		"tcp_mean_send_congestion_window": PositiveIntValidator,
		"tcp_mean_smooth_rtt":             PositiveIntValidator,
		"tcp_min_mss":                     PositiveIntValidator,
		"tcp_min_send_congestion_window":  PositiveIntValidator,
		"tcp_total_retransmissions":       PositiveIntValidator,
		"tcp_unrecovered_to":              PositiveIntValidator,
	}
)

func IsValidFlowsAtom(a *Atom) error {
	if validator, ok := flowsKeys[a.Key]; ok {
		return validator(a)
	}

	return fmt.Errorf("invalid key: %s", a.Key)
}
