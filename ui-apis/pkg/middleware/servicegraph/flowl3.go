// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.

package servicegraph

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

// This file provides the main interface into L3 flows for service graph. It is used to load flows for a given
// time range, to correlate the source and destination flows and to aggregate out ports and protocols that are not
// accessed via a service. Where flow logs may contain separate source and destination flows, this
// will return a single flow with statistics for allowed, denied-at-source and denied-at-dest.

const (
	maxAggregatedProtocol              = 10
	maxAggregatedPortRangesPerProtocol = 5
)

var zeroGraphTCPStats = v1.GraphTCPStats{}

type FlowEndpoint struct {
	Type      v1.GraphNodeType
	Namespace string
	Name      string
	NameAggr  string
	PortNum   int
	Protocol  string
}

func (e FlowEndpoint) String() string {
	return fmt.Sprintf("FlowEndpoint(%s/%s/%s/%s:%s:%d)", e.Type, e.Namespace, e.Name, e.NameAggr, e.Protocol, e.PortNum)
}

type L3Flow struct {
	Edge                 FlowEdge
	AggregatedProtoPorts *v1.AggregatedProtoPorts
	Stats                v1.GraphL3Stats
	Processes            *v1.GraphProcesses
}

func (f L3Flow) String() string {
	return fmt.Sprintf("%s [%#v; %#v]", f.Edge, f.AggregatedProtoPorts, f.Stats)
}

type FlowEdge struct {
	Source      FlowEndpoint
	Dest        FlowEndpoint
	ServicePort *v1.ServicePort
}

func (e FlowEdge) String() string {
	if e.ServicePort == nil {
		return fmt.Sprintf("%s -> %s", e.Source, e.Dest)
	}
	return fmt.Sprintf("%s -> %s -> %s", e.Source, e.ServicePort, e.Dest)
}

// Internal value used for tracking.
type reporter byte

const (
	reportedAtSource reporter = iota
	reportedAtDest
)

type L3FlowData struct {
	Flows []L3Flow
}

// GetL3FlowData queries, correlates and aggregates L3 flow data.
//   - Source and dest flows are correlated so that we have a single flow with stats for denied-at-source,
//     allowed-at-dest and denied-at-dest.
//   - Port information is aggregated when an endpoint port is not part of a service - this prevents bloating a graph
//     when an endpoint is subjected to a port scan.
//   - Stats for TCP and Processes are aggregated for each flow.
func GetL3FlowData(
	ctx context.Context, linseed lsclient.Client, cluster string, namespaces string, tr lmav1.TimeRange,
	fc *FlowConfig, cfg *Config,
) (fs []L3Flow, err error) {
	// Trace progress.
	progress := newProgress("l3", tr)
	defer func() {
		progress.Complete(err)
	}()

	addFlows := func(dgd *destinationGroupData, lastDestGp *FlowEndpoint) {
		fs = append(fs, dgd.getFlows(lastDestGp)...)
		progress.SetAggregated(len(fs))
	}

	// Create the list pager.
	var nsMatches []lsv1.NamespaceMatch
	if namespaces != "" {
		nsMatches = []lsv1.NamespaceMatch{
			{
				Type:       lsv1.MatchTypeAny,
				Namespaces: strings.Split(namespaces, ","),
			},
		}
	}

	params := lsv1.L3FlowParams{
		QueryParams:      lsv1.QueryParams{TimeRange: &tr},
		NamespaceMatches: nsMatches,
	}
	pager := lsclient.NewListPager[lsv1.L3Flow](&params)
	results, errors := pager.Stream(ctx, linseed.L3Flows(cluster).List)

	var lastDestGp *FlowEndpoint
	var dgd *destinationGroupData
	for page := range results {
		for _, flow := range page.Items {
			progress.IncRaw()
			reporter := string(flow.Key.Reporter)
			action := string(flow.Key.Action)
			proto := flow.Key.Protocol
			processName := ""
			if flow.Process != nil {
				processName = flow.Process.Name
			}

			source := FlowEndpoint{
				Type:      mapRawTypeToGraphNodeType(string(flow.Key.Source.Type), true, flow.SourceLabels),
				NameAggr:  flow.Key.Source.AggregatedName,
				Namespace: flow.Key.Source.Namespace,
			}
			svc := v1.ServicePort{}
			if flow.Service != nil {
				svc = v1.ServicePort{
					NamespacedName: v1.NamespacedName{
						Name:      flow.Service.Name,
						Namespace: flow.Service.Namespace,
					},
					PortName: flow.Service.PortName,
					Port:     int(flow.Service.Port),
					Protocol: proto,
				}
			}
			dest := FlowEndpoint{
				Type:      mapRawTypeToGraphNodeType(string(flow.Key.Destination.Type), true, flow.DestinationLabels),
				NameAggr:  flow.Key.Destination.AggregatedName,
				Namespace: flow.Key.Destination.Namespace,
				PortNum:   int(flow.Key.Destination.Port),
				Protocol:  proto,
			}
			gcs := v1.GraphConnectionStats{}
			if flow.LogStats != nil {
				gcs = v1.GraphConnectionStats{
					TotalPerSampleInterval: flow.LogStats.LogCount,
					Started:                flow.LogStats.Started,
					Completed:              flow.LogStats.Completed,
				}
			}
			gps := &v1.GraphPacketStats{}
			if flow.TrafficStats != nil {
				gps = &v1.GraphPacketStats{
					PacketsIn:  flow.TrafficStats.PacketsIn,
					PacketsOut: flow.TrafficStats.PacketsOut,
					BytesIn:    flow.TrafficStats.BytesIn,
					BytesOut:   flow.TrafficStats.BytesOut,
				}
			}

			// Determine the endpoint key used to group together service groups.
			destGp := GetServiceGroupFlowEndpointKey(dest)

			var tcp *v1.GraphTCPStats
			if proto == "tcp" && flow.TCPStats != nil {
				tcpStats := flow.TCPStats
				tcp = &v1.GraphTCPStats{
					SumTotalRetransmissions:  tcpStats.TotalRetransmissions,
					SumLostPackets:           tcpStats.LostPackets,
					SumUnrecoveredTo:         tcpStats.UnrecoveredTo,
					MinSendCongestionWindow:  tcpStats.MinSendCongestionWindow,
					MinSendMSS:               tcpStats.MinMSS,
					MaxSmoothRTT:             tcpStats.MaxSmoothRTT,
					MaxMinRTT:                tcpStats.MaxMinRTT,
					MeanSendCongestionWindow: tcpStats.MeanSendCongestionWindow,
					MeanSmoothRTT:            tcpStats.MeanSmoothRTT,
					MeanMinRTT:               tcpStats.MeanMinRTT,
					MeanMSS:                  tcpStats.MeanMSS,
				}

				// TCP stats have min and means which could be adversely impacted by zero data which indicates
				// no data rather than actually 0. Only set the document number if the data is non-zero. This prevents us
				// diluting when merging with non-zero data.
				if *tcp != zeroGraphTCPStats && flow.LogStats != nil {
					tcp.Count = flow.LogStats.FlowLogCount
				} else {
					tcp = nil
				}
			}

			// If the source and/or dest group have changed, and we were in the middle of reconciling multiple flows then
			// calculate the final flows.
			if dgd != nil && (destGp == nil || lastDestGp == nil || *destGp != *lastDestGp) {
				addFlows(dgd, lastDestGp)
				dgd = nil
			}

			// Determine the process info if available in the logs.
			var processes v1.GraphEndpointProcesses
			key := fmt.Sprintf("%s:%s:%s", source.NameAggr, dest.NameAggr, processName)
			if processName != "" && flow.ProcessStats != nil {
				processes = v1.GraphEndpointProcesses{
					key: v1.GraphEndpointProcess{
						Name:               processName,
						Source:             source.NameAggr,
						Destination:        dest.NameAggr,
						MinNumNamesPerFlow: flow.ProcessStats.MinNumNamesPerFlow,
						MaxNumNamesPerFlow: flow.ProcessStats.MaxNumNamesPerFlow,
						MinNumIDsPerFlow:   flow.ProcessStats.MinNumIDsPerFlow,
						MaxNumIDsPerFlow:   flow.ProcessStats.MaxNumIDsPerFlow,
					},
				}
			} else {
				if flow.ProcessStats != nil {
					processes = v1.GraphEndpointProcesses{
						key: v1.GraphEndpointProcess{
							Name:               defaultProcessName(processName),
							Source:             source.NameAggr,
							Destination:        dest.NameAggr,
							MinNumNamesPerFlow: flow.ProcessStats.MinNumNamesPerFlow,
							MaxNumNamesPerFlow: flow.ProcessStats.MaxNumNamesPerFlow,
							MinNumIDsPerFlow:   flow.ProcessStats.MinNumIDsPerFlow,
							MaxNumIDsPerFlow:   flow.ProcessStats.MaxNumIDsPerFlow,
						},
					}
				} else {
					processes = v1.GraphEndpointProcesses{
						key: v1.GraphEndpointProcess{
							Name:               defaultProcessName(processName),
							Source:             source.NameAggr,
							Destination:        dest.NameAggr,
							MinNumNamesPerFlow: 0,
							MaxNumNamesPerFlow: 0,
							MinNumIDsPerFlow:   0,
							MaxNumIDsPerFlow:   0,
						},
					}
				}
			}

			// The enumeration order ensures that for any endpoint pair we'll enumerate services before no-services for all
			// sources.
			if dgd == nil {
				log.Debugf("Collating flows: %s -> %s", source, destGp)
				dgd = newDestinationGroupData()
			}
			if log.IsLevelEnabled(log.DebugLevel) {
				if svc.Name != "" {
					log.Debugf("- Processing %s reported flow: %s -> %s -> %s", reporter, source, svc, dest)
				} else {
					log.Debugf("- Processing %s reported flow: %s -> %s", reporter, source, dest)
				}
			}
			dgd.add(reporter, action, source, svc, dest,
				flowStats{packetStats: gps, connStats: gcs, tcpStats: tcp, processes: processes},
			)

			// Store the last dest group.
			lastDestGp = destGp

			// Track the number of aggregated flows. Bail if we hit the absolute maximum number of aggregated flows.
			if len(fs) > cfg.ServiceGraphCacheMaxAggregatedRecords {
				return fs, errDataTruncatedError
			}
		}
	}

	// If we were reconciling multiple flows then calculate the final flows.
	if dgd != nil {
		addFlows(dgd, lastDestGp)
	}

	// Adjust some of the statistics based on the aggregation interval.
	timeInterval := tr.Duration()
	l3Flushes := float64(timeInterval) / float64(fc.L3FlowFlushInterval)
	for i := range fs {
		fs[i].Stats.Connections.TotalPerSampleInterval = int64(float64(fs[i].Stats.Connections.TotalPerSampleInterval) / l3Flushes)
	}
	return fs, <-errors
}

func defaultProcessName(processName string) string {
	if processName == "" {
		return "-"
	}
	return processName
}

func blankToSingleDash(val string) string {
	if val == "" {
		return "-"
	}
	return val
}

func mapRawTypeToGraphNodeType(val string, agg bool, labels []lsv1.FlowLabels) v1.GraphNodeType {
	switch val {
	case "wep":
		if agg {
			return v1.GraphNodeTypeReplicaSet
		}
		return v1.GraphNodeTypeWorkload
	case "hep":
		return determineHostEndpointGraphNodeType(labels)
	case "net":
		return v1.GraphNodeTypeNetwork
	case "ns":
		return v1.GraphNodeTypeNetworkSet
	}
	return v1.GraphNodeTypeUnknown
}

// determineHostEndpointGraphNodeType determines the type of host endpoint based on the labels.
// It searches for HostEndpointTypeLabelKey and returns the corresponding GraphNodeType.
// If the label is not found or the value is unknown, it defaults to v1.GraphNodeTypeHost.
func determineHostEndpointGraphNodeType(labels []lsv1.FlowLabels) v1.GraphNodeType {
	for _, label := range labels {
		if label.Key == names.HostEndpointTypeLabelKey && len(label.Values) > 0 {
			// Only the first label value is used when extracting the host endpoint type.
			// It is a programming error if there are multiple values for this label.
			switch names.HostEndpointType(label.Values[0].Value) {
			case names.HostEndpointTypeClusterNode:
				return v1.GraphNodeTypeClusterNode
			case names.HostEndpointTypeNonClusterHost:
				return v1.GraphNodeTypeHost
			default:
				return v1.GraphNodeTypeHost
			}
		}
	}
	return v1.GraphNodeTypeHost
}

func mapGraphNodeTypeToRawType(val v1.GraphNodeType) (string, bool) {
	switch val {
	case v1.GraphNodeTypeWorkload:
		return "wep", false
	case v1.GraphNodeTypeReplicaSet:
		return "wep", true
	case v1.GraphNodeTypeClusterNodes, v1.GraphNodeTypeHosts:
		return "hep", true
	case v1.GraphNodeTypeClusterNode, v1.GraphNodeTypeHost:
		return "hep", false
	case v1.GraphNodeTypeNetwork:
		return "net", true
	case v1.GraphNodeTypeNetworkSet:
		return "ns", true
	}
	return "", false
}

type ports struct {
	ranges []v1.PortRange
}

func (p *ports) add(port int) {
	for i := range p.ranges {
		if p.ranges[i].MinPort >= port && p.ranges[i].MaxPort <= port {
			// Already have this port range. Nothing to do.
			return
		}
		if p.ranges[i].MinPort == port+1 {
			// Expand the lower value of this range.
			p.ranges[i].MinPort = port
			if i > 0 && p.ranges[i-1].MaxPort == port {
				// Consolidate previous with this entry.
				p.ranges[i-1].MaxPort = p.ranges[i].MaxPort
				p.ranges = append(p.ranges[:i-1], p.ranges[i:]...)
			}
			return
		}
		if p.ranges[i].MaxPort == port-1 {
			// Expand the upper value of this range.
			p.ranges[i].MaxPort = port
			if i < len(p.ranges)-1 && p.ranges[i+1].MinPort == port {
				// Consolidate this with next entry.
				p.ranges[i].MaxPort = p.ranges[i+1].MaxPort
				p.ranges = append(p.ranges[:i], p.ranges[i+1:]...)
			}
			return
		}
		if p.ranges[i].MinPort > port {
			// This entry is between the previous and this one. Shift along and insert. Note that the append copies
			// this entry twice which is then copied over - but this makes for simple code.
			p.ranges = append(p.ranges[:i+1], p.ranges[i:]...)
			p.ranges[i] = v1.PortRange{MinPort: port, MaxPort: port}
			return
		}
	}
	// Extend the slice with this port.
	p.ranges = append(p.ranges, v1.PortRange{MinPort: port, MaxPort: port})
}

func newDestinationGroupData() *destinationGroupData {
	return &destinationGroupData{
		sources:                make(map[FlowEndpoint]*sourceData),
		allServiceDestinations: make(map[FlowEndpoint]bool),
	}
}

// destinationGroupData is used to temporarily collate flow data associated with a common source -> destination group.
type destinationGroupData struct {
	sources                map[FlowEndpoint]*sourceData
	allServiceDestinations map[FlowEndpoint]bool
}

func (d destinationGroupData) add(
	reporter, action string, source FlowEndpoint, svc v1.ServicePort, destination FlowEndpoint, stats flowStats,
) {
	if svc.Name != "" {
		d.allServiceDestinations[destination] = true
	}

	sourceGroup := d.sources[source]
	if sourceGroup == nil {
		sourceGroup = newSourceData()
		d.sources[source] = sourceGroup
	}
	sourceGroup.add(reporter, action, svc, destination, stats, d.allServiceDestinations[destination])
}

func (d *destinationGroupData) getFlows(destGp *FlowEndpoint) []L3Flow {
	var fs []L3Flow
	log.Debug("Handling source/dest reconciliation")
	for source, data := range d.sources {
		fs = append(fs, data.getFlows(source, destGp)...)
	}
	return fs
}

type sourceData struct {
	// Service Endpoints.
	serviceDestinations map[FlowEndpoint]*flowReconciliationData

	// AggregatedProtoPorts data for non-service Endpoints.
	other      *flowReconciliationData
	protoPorts map[string]*ports
}

func newSourceData() *sourceData {
	return &sourceData{
		serviceDestinations: make(map[FlowEndpoint]*flowReconciliationData),
		protoPorts:          make(map[string]*ports),
	}
}

func (s *sourceData) add(
	reporter, action string, svc v1.ServicePort, destination FlowEndpoint, stats flowStats, isServiceEndpoint bool,
) {
	rc := s.serviceDestinations[destination]
	if rc == nil && isServiceEndpoint {
		// If there is a service then we can create a service destination (since services are enumerated before
		// no service).
		rc = newFlowReconciliationData()
		s.serviceDestinations[destination] = rc
	}
	if rc != nil {
		// We have a flowReconciliationData for the service. Combine the stats to that.
		log.Debug("  endpoint is part of a service")
		rc.add(reporter, action, svc, stats)
		return
	}

	// Aggregate the port and Protocol information.
	log.Debug("  endpoint is not part of a service - aggregate port and proto info")

	// We do not have a flowReconciliationData which means we must be aggregating out the Port and Protocol for this
	// (non-service related) flow.
	if rc = s.other; rc == nil {
		// There is no existing service destination and this flow does not contain a service. Since services are
		// enumerated first then this Port and Protocol combination is not part of a service and we should consolidate
		// the Protocol and ports.
		log.Debug("  create new aggregated reconciliation data")
		rc = newFlowReconciliationData()
		s.other = rc
	}

	p, ok := s.protoPorts[svc.Protocol]
	if !ok {
		if destination.PortNum != 0 {
			p = &ports{}
		}
		s.protoPorts[svc.Protocol] = p
	}
	if p != nil {
		p.add(destination.PortNum)
	}

	// Combine the data to the aggregated data set.
	rc.add(reporter, action, v1.ServicePort{}, stats)
}

func (s *sourceData) getFlows(source FlowEndpoint, destGp *FlowEndpoint) []L3Flow {
	var fs []L3Flow

	// Combine the reconciled flows for each endpoint/Protocol that is part of one or more services.
	for dest, frd := range s.serviceDestinations {
		fs = append(fs, frd.getFlows(source, dest)...)
	}

	// Combine the aggregated info. There should at most a single flow here.
	if s.other != nil {
		log.Debug(" add flow with aggregated ports and protocols")
		dest := FlowEndpoint{
			Type:      destGp.Type,
			Namespace: destGp.Namespace,
			Name:      destGp.Name,
			NameAggr:  destGp.NameAggr,
		}
		if other := s.other.getFlows(source, dest); len(other) == 1 {
			log.Debug(" calculate aggregated ports and protocols")
			f := other[0]
			f.AggregatedProtoPorts = &v1.AggregatedProtoPorts{}
			for proto, ports := range s.protoPorts {
				aggPorts := v1.AggregatedPorts{
					Protocol: proto,
				}
				if ports != nil {
					for i := range ports.ranges {
						if len(aggPorts.PortRanges) >= maxAggregatedPortRangesPerProtocol {
							aggPorts.NumOtherPorts += ports.ranges[i].Num()
						} else {
							aggPorts.PortRanges = append(aggPorts.PortRanges, ports.ranges[i])
						}
					}
				}
				f.AggregatedProtoPorts.ProtoPorts = append(f.AggregatedProtoPorts.ProtoPorts, aggPorts)

				if len(f.AggregatedProtoPorts.ProtoPorts) >= maxAggregatedProtocol {
					f.AggregatedProtoPorts.NumOtherProtocols = len(s.protoPorts) - len(f.AggregatedProtoPorts.ProtoPorts)
					break
				}
			}

			fs = append(fs, f)
		} else {
			log.Errorf("Multiple flows with aggregated ports and protocols: %#v", other)
		}
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		if len(fs) == 0 {
			log.Debug("Collated flows discarded")
		} else {
			log.Debug("Collated flows converted")
			for _, f := range fs {
				log.Debugf("- %s", f)
			}
		}
	}

	return fs
}

func newFlowReconciliationData() *flowReconciliationData {
	return &flowReconciliationData{
		sourceReportedDenied:  make(map[v1.ServicePort]flowStats),
		sourceReportedAllowed: make(map[v1.ServicePort]flowStats),
		destReportedDenied:    make(map[v1.ServicePort]flowStats),
		destReportedAllowed:   make(map[v1.ServicePort]flowStats),
	}
}

type flowStats struct {
	packetStats *v1.GraphPacketStats
	connStats   v1.GraphConnectionStats
	tcpStats    *v1.GraphTCPStats
	processes   v1.GraphEndpointProcesses
}

func (f flowStats) add(f2 flowStats) flowStats {
	return flowStats{
		packetStats: f.packetStats.Add(f2.packetStats),
		connStats:   f.connStats.Add(f2.connStats),
		tcpStats:    f.tcpStats.Combine(f2.tcpStats),
		processes:   f.processes.Combine(f2.processes),
	}
}

// flowReconciliationData is used to temporarily collate source and dest statistics when the flow will be recorded by
// both source and dest.
//
// Service information available in source reported flows may be missing from the destination flows. The destination
// flows have the final verdict (allow or deny) that is missing from the source flow. This helper divvies up the
// destination allowed and denied flows with the source reported allowed flows. We use the source data for the actual
// total packets stats and the destination data for the proportional values of which flows were allowed and denied at
// dest. This is obviously an approximation, but the best we can do without additional data to correlate.
type flowReconciliationData struct {
	sourceReportedDenied  map[v1.ServicePort]flowStats
	sourceReportedAllowed map[v1.ServicePort]flowStats
	destReportedAllowed   map[v1.ServicePort]flowStats
	destReportedDenied    map[v1.ServicePort]flowStats
}

func (d *flowReconciliationData) add(
	reporter, action string, svc v1.ServicePort, f flowStats,
) {
	if reporter == "src" {
		if action == "allow" {
			log.Debug("  found source reported allowed flow")
			d.sourceReportedAllowed[svc] = d.sourceReportedAllowed[svc].add(f)
		} else {
			log.Debug("  found source reported denied flow")
			d.sourceReportedDenied[svc] = d.sourceReportedDenied[svc].add(f)
		}
	} else {
		if action == "allow" {
			log.Debug("  found dest reported allowed flow")
			d.destReportedAllowed[svc] = d.destReportedAllowed[svc].add(f)
		} else {
			log.Debug("  found dest reported denied flow")
			d.destReportedDenied[svc] = d.destReportedDenied[svc].add(f)
		}
	}
}

// getFlows returns the final reconciled flows. This essentially divvies up the destination edges across the
// various source reported flows based on simple proportion.
func (d *flowReconciliationData) getFlows(source, dest FlowEndpoint) []L3Flow {
	var f []L3Flow

	addFlow := func(svc v1.ServicePort, stats v1.GraphL3Stats, processes *v1.GraphProcesses) {
		log.Debugf("  Including flow for service: %s", svc)
		var spp *v1.ServicePort
		if svc.Name != "" {
			spp = &svc
		}

		f = append(f, L3Flow{
			Edge: FlowEdge{
				Source:      source,
				Dest:        dest,
				ServicePort: spp,
			},
			Stats:     stats,
			Processes: processes,
		})
	}

	allServices := func(allowed, denied map[v1.ServicePort]flowStats) set.Set[v1.ServicePort] {
		services := set.New[v1.ServicePort]()
		for s := range allowed {
			services.Add(s)
		}
		for s := range denied {
			services.Add(s)
		}
		return services
	}

	addSingleReportedFlows := func(allowed, denied map[v1.ServicePort]flowStats, rep reporter) {
		allServices(allowed, denied).Iter(func(svc v1.ServicePort) error {
			stats := v1.GraphL3Stats{
				Connections: allowed[svc].connStats.Add(denied[svc].connStats),
				Allowed:     allowed[svc].packetStats,
				TCP:         allowed[svc].tcpStats,
			}
			epProcesses := allowed[svc].processes.Combine(denied[svc].processes)
			var processes *v1.GraphProcesses

			if rep == reportedAtSource {
				stats.DeniedAtSource = denied[svc].packetStats
				if len(epProcesses) > 0 {
					processes = &v1.GraphProcesses{
						Source: epProcesses,
					}
				}
			} else {
				stats.DeniedAtDest = denied[svc].packetStats
				if len(epProcesses) > 0 {
					processes = &v1.GraphProcesses{
						Dest: epProcesses,
					}
				}
			}

			addFlow(svc, stats, processes)
			return nil
		})
	}

	sourceReported := len(d.sourceReportedAllowed) > 0 || len(d.sourceReportedDenied) > 0
	destReported := len(d.destReportedAllowed) > 0 || len(d.destReportedDenied) > 0

	if sourceReported {
		if !destReported {
			log.Debug("  L3Flow reported at source only")
			addSingleReportedFlows(d.sourceReportedAllowed, d.sourceReportedDenied, reportedAtSource)
			return f
		}
	} else if destReported {
		if !sourceReported {
			log.Debug("  L3Flow reported at dest only")
			addSingleReportedFlows(d.destReportedAllowed, d.destReportedDenied, reportedAtDest)
			return f
		}
	}

	// The flow will be reported at source and dest, which most importantly means the allowed flows at source need to be
	// divvied up to be allowed or denied at dest.
	log.Debug("  L3Flow reported at source and dest")
	allServices(d.sourceReportedAllowed, d.sourceReportedDenied).Iter(func(svc v1.ServicePort) error {
		// Get the stats for allowed and denied at dest.  Combine the stats for direct A->B and A->SVC->B. We don't expect
		// the latter, but just in case...
		totalAllowedAtDest := d.destReportedAllowed[v1.ServicePort{Protocol: svc.Protocol}].packetStats.
			Add(d.destReportedAllowed[svc].packetStats)
		totalDeniedAtDest := d.destReportedDenied[v1.ServicePort{Protocol: svc.Protocol}].packetStats.
			Add(d.destReportedDenied[svc].packetStats)

		var allowed, deniedAtDest *v1.GraphPacketStats
		if totalAllowedAtDest == nil {
			deniedAtDest = d.sourceReportedAllowed[svc].packetStats
		} else if totalDeniedAtDest == nil {
			allowed = d.sourceReportedAllowed[svc].packetStats
		} else {
			// Get the proportion allowed at dest and we'll assume the remainder is denied.
			propAllowed := totalAllowedAtDest.Prop(totalDeniedAtDest)
			allowed = d.sourceReportedAllowed[svc].packetStats.Multiply(propAllowed)
			deniedAtDest = d.sourceReportedAllowed[svc].packetStats.Sub(allowed)
		}

		// Determine graph processes.
		var processes *v1.GraphProcesses

		sourceProcesses := d.sourceReportedAllowed[svc].processes.
			Combine(d.sourceReportedDenied[svc].processes)
		destProcesses := d.destReportedAllowed[v1.ServicePort{Protocol: svc.Protocol}].processes.
			Combine(d.destReportedAllowed[svc].processes).
			Combine(d.destReportedDenied[v1.ServicePort{Protocol: svc.Protocol}].processes).
			Combine(d.destReportedDenied[svc].processes)
		if len(destProcesses) > 0 || len(sourceProcesses) > 0 {
			processes = &v1.GraphProcesses{
				Source: sourceProcesses,
				Dest:   destProcesses,
			}
		}

		addFlow(svc, v1.GraphL3Stats{
			Allowed:        allowed,
			DeniedAtSource: d.sourceReportedDenied[svc].packetStats,
			DeniedAtDest:   deniedAtDest,
			Connections:    d.sourceReportedAllowed[svc].connStats.Add(d.sourceReportedDenied[svc].connStats),
			TCP: d.sourceReportedAllowed[svc].tcpStats.Combine(d.sourceReportedDenied[svc].tcpStats).
				Combine(d.destReportedAllowed[svc].tcpStats).Combine(d.destReportedDenied[svc].tcpStats),
		}, processes)
		return nil
	})
	return f
}
