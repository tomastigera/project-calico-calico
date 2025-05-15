// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package dnslog

import (
	"net"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

type Update struct {
	ClientIP       net.IP
	ClientEP       calc.EndpointData
	ServerIP       net.IP
	ServerEP       calc.EndpointData
	DNS            *layers.DNS
	LatencyIfKnown *time.Duration
}

type EndpointMetadataWithIP struct {
	v1.Endpoint
	IP string
}

type DNSMeta struct {
	ClientMeta   EndpointMetadataWithIP
	Question     v1.DNSName
	ResponseCode v1.DNSResponseCode
	RRSetsString string
}

type DNSSpec struct {
	RRSets       v1.DNSRRSets
	Servers      map[EndpointMetadataWithIP]DNSLabels
	ClientLabels DNSLabels
	DNSStats
	Latency v1.DNSLatency
}

func (a *DNSSpec) Merge(b DNSSpec) {
	for e, l := range b.Servers {
		if _, ok := a.Servers[e]; ok {
			a.Servers[e] = utils.IntersectAndFilterLabels(a.Servers[e], l)
		} else {
			a.Servers[e] = l
		}
	}
	a.ClientLabels = utils.IntersectAndFilterLabels(a.ClientLabels, b.ClientLabels)
	a.Count += b.Count

	// Latency merging.
	if b.Latency.Count > 0 {
		// If the mean and count so far are M1 and C1, the sum of those latency measurements
		// was M1*C1.  If we're now combining that with a new set, with mean M2 and count
		// C2, the overall sum is M1*C1 + M2*C2, and the overall count is C1+C2, so the new
		// overall mean is...
		a.Latency.Mean = time.Duration(
			(int64(a.Latency.Mean)*int64(a.Latency.Count) + int64(b.Latency.Mean)*int64(b.Latency.Count)) /
				int64(a.Latency.Count+b.Latency.Count),
		)
	}
	if int64(b.Latency.Max) > int64(a.Latency.Max) {
		a.Latency.Max = b.Latency.Max
	}
	a.Latency.Count += b.Latency.Count
}

type DNSLabels = uniquelabels.Map

type DNSStats struct {
	Count uint `json:"count"`
}

type DNSData struct {
	DNSMeta
	DNSSpec
}

type DNSExcessLog struct {
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Type      v1.DNSLogType `json:"type"`
	Count     uint          `json:"count"`
}

func (d *DNSData) ToDNSLog(startTime, endTime time.Time, includeLabels bool) *v1.DNSLog {
	// Convert servers from a map to a slice.
	var dnsServers []v1.DNSServer
	for endpointMeta, labels := range d.Servers {
		dnsServers = append(dnsServers, v1.DNSServer{
			Endpoint: endpointMeta.Endpoint,
			IP:       net.ParseIP(endpointMeta.IP),
			Labels:   labels,
		})
	}

	res := &v1.DNSLog{
		StartTime:       startTime,
		EndTime:         endTime,
		Type:            v1.DNSLogTypeLog,
		Count:           d.Count,
		ClientName:      d.ClientMeta.Name,
		ClientNameAggr:  d.ClientMeta.AggregatedName,
		ClientNamespace: d.ClientMeta.Namespace,
		ClientLabels:    d.ClientLabels,
		Servers:         dnsServers,
		QName:           v1.QName(d.Question.Name),
		QClass:          d.Question.Class,
		QType:           d.Question.Type,
		RCode:           d.ResponseCode,
		RRSets:          d.RRSets,
		Latency:         d.Latency,
		LatencyCount:    d.Latency.Count,
		LatencyMean:     d.Latency.Mean,
		LatencyMax:      d.Latency.Max,
	}

	if d.ClientMeta.IP != utils.FieldNotIncluded {
		ip := net.ParseIP(d.ClientMeta.IP)
		res.ClientIP = &ip
	}

	if !includeLabels {
		res.ClientLabels = uniquelabels.Nil
		res.Servers = nil
		for _, server := range dnsServers {
			server.Labels = uniquelabels.Nil
			res.Servers = append(res.Servers, server)
		}
	}

	return res
}
