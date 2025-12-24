// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package collector

import (
	"net"
	"time"

	"github.com/gopacket/gopacket/layers"

	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	dpsets "github.com/projectcalico/calico/felix/dataplane/ipsets"
	"github.com/projectcalico/calico/felix/dataplane/windows/ipsets"
	"github.com/projectcalico/calico/felix/netlinkshim"
	"github.com/projectcalico/calico/felix/proto"
)

type Collector interface {
	Start() error
	ReportingChannel() chan<- *proto.DataplaneStats
	SetDNSLogReporter(types.Reporter)
	LogDNS(net.IP, net.IP, *layers.DNS, *time.Duration)
	SetL7LogReporter(types.Reporter)
	LogL7(*proto.HTTPData, *Data, tuple.Tuple, int)
	RegisterMetricsReporter(types.Reporter)
	SetDataplaneInfoReader(types.DataplaneInfoReader)
	SetPacketInfoReader(types.PacketInfoReader)
	SetConntrackInfoReader(types.ConntrackInfoReader)
	SetProcessInfoCache(types.ProcessInfoCache)
	SetDomainLookup(types.EgressDomainCache)
	AddNewDomainDataplaneToIpSetsManager(ipsets.IPFamily, *dpsets.IPSetsManager)
	SetNetlinkHandle(netlinkshim.Interface)
	WAFReportingHandler() func(*proto.WAFEvent)
	LogWAFEvents([]*proto.WAFEvent)
	SetWAFEventsReporter(types.Reporter)
	SetPolicyActivityReporter(types.Reporter)
}
