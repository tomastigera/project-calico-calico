package testutils

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/flows"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
	lmaapi "github.com/projectcalico/calico/lma/pkg/api"
)

func NewFlowLogBuilder() *FlowLogBuilder {
	return &FlowLogBuilder{
		// Initialize to an empty flow log.
		activeLog: &v1.FlowLog{},
	}
}

type FlowLogBuilder struct {
	cluster string

	activeLog *v1.FlowLog

	// For tracking how to build the log.
	randomFlowStats   bool
	randomPacketStats bool

	// Tracking logs that we've built.
	logs []v1.FlowLog
}

func (b *FlowLogBuilder) Copy() *FlowLogBuilder {
	n := *b
	return &n
}

func (b *FlowLogBuilder) Clear() {
	b.activeLog = &v1.FlowLog{}
}

func (b *FlowLogBuilder) Build() (*v1.FlowLog, error) {
	// If no start and end times were set, default them.
	if b.activeLog.StartTime == 0 {
		b.WithStartTime(time.Now())
	}
	if b.activeLog.EndTime == 0 {
		b.WithEndTime(time.Now())
	}

	if b.randomPacketStats {
		b.activeLog.PacketsIn = 1
		b.activeLog.PacketsOut = 2
		b.activeLog.BytesIn = 32
		b.activeLog.BytesOut = 128
		b.activeLog.TransitPacketsIn = 0
		b.activeLog.TransitPacketsOut = 0
		b.activeLog.TransitBytesIn = 0
		b.activeLog.TransitBytesOut = 0
	}
	if b.randomFlowStats {
		b.activeLog.NumFlows = 1
		b.activeLog.NumFlowsStarted = 3
		b.activeLog.NumFlowsCompleted = 2
	}

	// Keep track of the logs that have been built so that we can
	// produce an expected flow from them if requested. We take a copy
	// so that the caller can modify the next iteration of this log if desired.
	cp := *b.activeLog
	b.logs = append(b.logs, cp)

	// Perform any validation here to ensure the log that we're building is legit.
	return &cp, nil
}

// ExpectedFlow returns a baseline flow to expect, given the flow log's configuration.
// Note that some fields on a Flow are aggregated, and so will need to be calculated based
// on the sum total of flow logs used to build the flow.
// Our aggregation logic within the builder is fairly limited.
func (b *FlowLogBuilder) ExpectedFlow(t *testing.T, info bapi.ClusterInfo) *v1.L3Flow {
	// Initialize the flow with identifying information. For now, we
	// don't support multiple flows from a single builder, so we assume
	// all of the logs have the same Key fields.
	f := &v1.L3Flow{
		Key: v1.L3FlowKey{
			Cluster:  info.Cluster,
			Action:   v1.FlowAction(b.activeLog.Action),
			Reporter: v1.FlowReporter(b.activeLog.Reporter),
			Protocol: b.activeLog.Protocol,
			Source: v1.Endpoint{
				Namespace:      b.activeLog.SourceNamespace,
				Type:           v1.EndpointType(b.activeLog.SourceType),
				AggregatedName: b.activeLog.SourceNameAggr,
			},
			Destination: v1.Endpoint{
				Namespace:      b.activeLog.DestNamespace,
				Type:           v1.EndpointType(b.activeLog.DestType),
				AggregatedName: b.activeLog.DestNameAggr,
			},
		},
		TrafficStats: &v1.TrafficStats{},
		LogStats:     &v1.LogStats{},
		HTTPStats:    &v1.HTTPStats{},
		Service: &v1.Service{
			Name:      b.activeLog.DestServiceName,
			Namespace: b.activeLog.DestServiceNamespace,
			PortName:  b.activeLog.DestServicePortName,
		},
	}

	if b.activeLog.DestPort != nil {
		f.Key.Destination.Port = *b.activeLog.DestPort
	}
	if b.activeLog.DestServicePortNum != nil {
		f.Service.Port = *b.activeLog.DestServicePortNum
	}

	if b.activeLog.ProcessName != "" {
		f.Process = &v1.Process{Name: b.activeLog.ProcessName}
		f.ProcessStats = &v1.ProcessStats{}
	}

	slt := flows.NewLabelTracker()
	dlt := flows.NewLabelTracker()
	sourceIPsSet := make(map[string]struct{})
	destinationIPsSet := make(map[string]struct{})

	if f.Key.Protocol == "tcp" {
		f.TCPStats = &v1.TCPStats{
			TotalRetransmissions:     0,
			LostPackets:              0,
			UnrecoveredTo:            0,
			MinSendCongestionWindow:  0,
			MinMSS:                   0,
			MaxSmoothRTT:             0,
			MaxMinRTT:                0,
			MeanSendCongestionWindow: 0,
			MeanSmoothRTT:            0,
			MeanMinRTT:               0,
			MeanMSS:                  0,
		}
	}

	// Now populate the expected non-identifying information based on the logs we
	// have created, simulating aggregation done by ES.
	for _, log := range b.logs {
		f.TrafficStats.BytesIn += log.BytesIn
		f.TrafficStats.BytesOut += log.BytesOut
		f.TrafficStats.PacketsIn += log.PacketsIn
		f.TrafficStats.PacketsOut += log.PacketsOut
		f.TrafficStats.TransitBytesIn += log.TransitBytesIn
		f.TrafficStats.TransitBytesOut += log.TransitBytesOut
		f.TrafficStats.TransitPacketsIn += log.TransitPacketsIn
		f.TrafficStats.TransitPacketsOut += log.TransitPacketsOut
		f.LogStats.Completed += log.NumFlowsCompleted
		f.LogStats.Started += log.NumFlowsStarted
		f.LogStats.LogCount += log.NumFlows
		f.LogStats.FlowLogCount += 1
		f.HTTPStats.AllowedIn += log.HTTPRequestsAllowedIn
		f.HTTPStats.DeniedIn += log.HTTPRequestsDeniedIn

		// Update trackers with label information.
		if log.SourceLabels != nil {
			for _, l := range log.SourceLabels.Labels {
				labelParts := strings.Split(l, "=")
				key := labelParts[0]
				value := labelParts[1]
				slt.Add(key, value, log.NumFlows)
			}
		}
		if log.DestLabels != nil {
			for _, l := range log.DestLabels.Labels {
				labelParts := strings.Split(l, "=")
				key := labelParts[0]
				value := labelParts[1]
				dlt.Add(key, value, log.NumFlows)
			}
		}

		if log.SourceIP != nil {
			sourceIPsSet[*log.SourceIP] = struct{}{}
		}
		if log.DestIP != nil {
			destinationIPsSet[*log.DestIP] = struct{}{}
		}

		if f.TCPStats != nil {
			f.TCPStats.TotalRetransmissions += log.TCPTotalRetransmissions
			f.TCPStats.LostPackets += log.TCPLostPackets
			f.TCPStats.UnrecoveredTo += log.TCPUnrecoveredTo
			f.TCPStats.MinSendCongestionWindow += float64(log.TCPMinSendCongestionWindow)
			f.TCPStats.MinMSS += float64(log.TCPMinMSS)
			f.TCPStats.MaxSmoothRTT += float64(log.TCPMaxSmoothRTT)
			f.TCPStats.MaxMinRTT += float64(log.TCPMaxMinRTT)
			f.TCPStats.MeanSendCongestionWindow += float64(log.TCPMeanSendCongestionWindow)
			f.TCPStats.MeanSmoothRTT += float64(log.TCPMeanSmoothRTT)
			f.TCPStats.MeanMinRTT += float64(log.TCPMeanMinRTT)
			f.TCPStats.MeanMSS += float64(log.TCPMeanMSS)
		}
	}

	// Set labels.
	f.SourceLabels = slt.Labels()
	f.DestinationLabels = dlt.Labels()

	// Set the IPs
	f.SourceIPs = keys(sourceIPsSet)
	f.DestinationIPs = keys(destinationIPsSet)

	// Add in expected policies. Right now, we don't support aggregation
	// of policies across multiple logs in this builder, and we assume
	// every log in the flow has the same policies.
	if b.activeLog != nil && b.activeLog.Policies != nil {
		// A helper to avoid repetition.
		addPolicies := func(pols []string, targetPolicy *[]v1.Policy) {
			if len(pols) == 0 {
				return
			}
			if *targetPolicy == nil {
				*targetPolicy = make([]v1.Policy, 0)
			}

			// Parse each string into a policy hit.
			// Then, sort the hits to ensure deterministic order.
			var hits lmaapi.SortablePolicyHits
			for _, p := range pols {
				h, err := lmaapi.PolicyHitFromFlowLogPolicyString(p)
				require.NoError(t, err)
				hits = append(hits, h)
			}
			sort.Sort(hits)

			for _, h := range hits {
				*targetPolicy = append(*targetPolicy, v1.Policy{
					Tier:         h.Tier(),
					Kind:         h.Kind(),
					Name:         h.Name(),
					Namespace:    h.Namespace(),
					Action:       string(h.Action()),
					Count:        f.LogStats.FlowLogCount,
					RuleID:       h.RuleIndex(),
					IsProfile:    lmaapi.IsProfile(h.Kind()),
					IsStaged:     lmaapi.IsStaged(h.Kind()),
					IsKubernetes: lmaapi.IsKubernetes(h.Kind()),
				})
			}
		}

		addPolicies(b.activeLog.Policies.AllPolicies, &f.Policies)
		addPolicies(b.activeLog.Policies.EnforcedPolicies, &f.EnforcedPolicies)
		addPolicies(b.activeLog.Policies.PendingPolicies, &f.PendingPolicies)
		addPolicies(b.activeLog.Policies.TransitPolicies, &f.TransitPolicies)
	}

	// Add in TCP stats.
	if f.Key.Protocol == "tcp" {
		f.TCPStats = &v1.TCPStats{
			TotalRetransmissions:     0,
			LostPackets:              0,
			UnrecoveredTo:            0,
			MinSendCongestionWindow:  0,
			MinMSS:                   0,
			MaxSmoothRTT:             0,
			MaxMinRTT:                0,
			MeanSendCongestionWindow: 0,
			MeanSmoothRTT:            0,
			MeanMinRTT:               0,
			MeanMSS:                  0,
		}
	}

	// Add in the destination domains.
	domains := []string{}
	for _, log := range b.logs {
		for _, dom := range log.DestDomains {
			if !containsValue(domains, dom) {
				domains = append(domains, dom)
			}
		}
	}
	sort.Strings(domains)
	f.DestDomains = domains

	return f
}

func keys(set map[string]struct{}) []string {
	var mapKeys []string

	for k := range set {
		mapKeys = append(mapKeys, k)
	}

	sort.Strings(mapKeys)

	return mapKeys
}

func (b *FlowLogBuilder) WithSourceIP(ip string) *FlowLogBuilder {
	b.activeLog.SourceIP = testutils.StringPtr(ip)
	return b
}

func (b *FlowLogBuilder) WithDestIP(ip string) *FlowLogBuilder {
	b.activeLog.DestIP = testutils.StringPtr(ip)
	return b
}

func (b *FlowLogBuilder) WithProcessName(n string) *FlowLogBuilder {
	if b.activeLog.ProcessName != "" {
		panic("Cannot set process name - it is already set")
	}
	b.activeLog.ProcessName = n
	return b
}

func (b *FlowLogBuilder) WithSourceName(n string) *FlowLogBuilder {
	b.activeLog.SourceNameAggr = n
	return b
}

func (b *FlowLogBuilder) WithDestName(n string) *FlowLogBuilder {
	b.activeLog.DestNameAggr = n
	return b
}

func (b *FlowLogBuilder) WithStartTime(t time.Time) *FlowLogBuilder {
	b.activeLog.StartTime = time.Now().Unix()
	return b
}

func (b *FlowLogBuilder) WithEndTime(t time.Time) *FlowLogBuilder {
	b.activeLog.EndTime = t.Unix()
	return b
}

func (b *FlowLogBuilder) WithProtocol(p string) *FlowLogBuilder {
	b.activeLog.Protocol = p
	return b
}

func (b *FlowLogBuilder) WithDestPort(port int) *FlowLogBuilder {
	b.activeLog.DestPort = testutils.Int64Ptr(int64(port))
	return b
}

func (b *FlowLogBuilder) WithSourcePort(port int) *FlowLogBuilder {
	b.activeLog.SourcePort = testutils.Int64Ptr(int64(port))
	return b
}

func (b *FlowLogBuilder) WithDestService(name string, port int) *FlowLogBuilder {
	b.activeLog.DestServiceName = name
	b.activeLog.DestServicePortName = fmt.Sprintf("%d", port)
	b.activeLog.DestServicePortNum = testutils.Int64Ptr(int64(port))
	return b
}

func (b *FlowLogBuilder) WithCluster(c string) *FlowLogBuilder {
	b.cluster = c
	return b
}

func (b *FlowLogBuilder) WithReporter(r string) *FlowLogBuilder {
	b.activeLog.Reporter = r
	return b
}

func (b *FlowLogBuilder) WithAction(a string) *FlowLogBuilder {
	b.activeLog.Action = a
	return b
}

func (b *FlowLogBuilder) WithPolicies(p ...string) *FlowLogBuilder {
	b.activeLog.Policies = &v1.FlowLogPolicy{AllPolicies: p}
	return b
}

func (b *FlowLogBuilder) WithEnforcedPolicies(p ...string) *FlowLogBuilder {
	b.activeLog.Policies = &v1.FlowLogPolicy{EnforcedPolicies: p}
	return b
}

func (b *FlowLogBuilder) WithPendingPolicies(p ...string) *FlowLogBuilder {
	b.activeLog.Policies = &v1.FlowLogPolicy{PendingPolicies: p}
	return b
}

func (b *FlowLogBuilder) WithTransitPolicies(p ...string) *FlowLogBuilder {
	b.activeLog.Policies = &v1.FlowLogPolicy{TransitPolicies: p}
	return b
}

func (b *FlowLogBuilder) WithPolicy(p string) *FlowLogBuilder {
	if b.activeLog.Policies == nil {
		b.activeLog.Policies = &v1.FlowLogPolicy{
			AllPolicies:      []string{},
			EnforcedPolicies: []string{},
			PendingPolicies:  []string{},
			TransitPolicies:  []string{},
		}
	}
	b.activeLog.Policies.AllPolicies = append(b.activeLog.Policies.AllPolicies, p)
	return b
}

func (b *FlowLogBuilder) WithEnforcedPolicy(p string) *FlowLogBuilder {
	if b.activeLog.Policies == nil {
		b.activeLog.Policies = &v1.FlowLogPolicy{
			AllPolicies:      []string{},
			EnforcedPolicies: []string{},
			PendingPolicies:  []string{},
			TransitPolicies:  []string{},
		}
	}
	b.activeLog.Policies.EnforcedPolicies = append(b.activeLog.Policies.EnforcedPolicies, p)
	return b
}

func (b *FlowLogBuilder) WithPendingPolicy(p string) *FlowLogBuilder {
	if b.activeLog.Policies == nil {
		b.activeLog.Policies = &v1.FlowLogPolicy{
			AllPolicies:      []string{},
			EnforcedPolicies: []string{},
			PendingPolicies:  []string{},
			TransitPolicies:  []string{},
		}
	}
	b.activeLog.Policies.PendingPolicies = append(b.activeLog.Policies.PendingPolicies, p)
	return b
}

func (b *FlowLogBuilder) WithTransitPolicy(p string) *FlowLogBuilder {
	if b.activeLog.Policies == nil {
		b.activeLog.Policies = &v1.FlowLogPolicy{
			AllPolicies:      []string{},
			EnforcedPolicies: []string{},
			PendingPolicies:  []string{},
			TransitPolicies:  []string{},
		}
	}
	b.activeLog.Policies.TransitPolicies = append(b.activeLog.Policies.TransitPolicies, p)
	return b
}

// WithType sets both source and dest types at once.
func (b *FlowLogBuilder) WithType(t string) *FlowLogBuilder {
	b.activeLog.DestType = t
	b.activeLog.SourceType = t
	return b
}

func (b *FlowLogBuilder) WithDestDomains(c ...string) *FlowLogBuilder {
	b.activeLog.DestDomains = c
	return b
}

func (b *FlowLogBuilder) WithDestType(c string) *FlowLogBuilder {
	b.activeLog.DestType = c
	return b
}

func (b *FlowLogBuilder) WithSourceType(c string) *FlowLogBuilder {
	b.activeLog.SourceType = c
	return b
}

// WithNamespace sets all namespace fields at once.
func (b *FlowLogBuilder) WithNamespace(n string) *FlowLogBuilder {
	b.activeLog.SourceNamespace = n
	b.activeLog.DestNamespace = n
	b.activeLog.DestServiceNamespace = n
	return b
}

func (b *FlowLogBuilder) WithSourceNamespace(n string) *FlowLogBuilder {
	b.activeLog.SourceNamespace = n
	return b
}

func (b *FlowLogBuilder) WithDestNamespace(n string) *FlowLogBuilder {
	b.activeLog.DestNamespace = n
	b.activeLog.DestServiceNamespace = n
	return b
}

func (b *FlowLogBuilder) WithSourceLabels(labels ...string) *FlowLogBuilder {
	b.activeLog.SourceLabels = &v1.FlowLogLabels{
		Labels: labels,
	}
	return b
}

func (b *FlowLogBuilder) WithDestLabels(labels ...string) *FlowLogBuilder {
	b.activeLog.DestLabels = &v1.FlowLogLabels{
		Labels: labels,
	}
	return b
}

func (b *FlowLogBuilder) WithRandomFlowStats() *FlowLogBuilder {
	b.randomFlowStats = true
	return b
}

func (b *FlowLogBuilder) WithRandomPacketStats() *FlowLogBuilder {
	b.randomPacketStats = true
	return b
}

func (b *FlowLogBuilder) WithHost(host string) *FlowLogBuilder {
	b.activeLog.Host = host
	return b
}

func (b *FlowLogBuilder) WithTCPLostPackets(tcpLostPackets int64) *FlowLogBuilder {
	b.activeLog.TCPLostPackets = tcpLostPackets
	return b
}

func (b *FlowLogBuilder) WithTCPMeanSendCongestionWindow(tcpMeanSendCongestionWindow int64) *FlowLogBuilder {
	b.activeLog.TCPMeanSendCongestionWindow = tcpMeanSendCongestionWindow
	return b
}

func (b *FlowLogBuilder) WithTCPMinSendCongestionWindow(tcpMinSendCongestionWindow int64) *FlowLogBuilder {
	b.activeLog.TCPMinSendCongestionWindow = tcpMinSendCongestionWindow
	return b
}

func (b *FlowLogBuilder) WithTCPTotalRetransmissions(tcpTotalRetransmissions int64) *FlowLogBuilder {
	b.activeLog.TCPTotalRetransmissions = tcpTotalRetransmissions
	return b
}

func (b *FlowLogBuilder) WithTCPUnrecoveredTo(tcpUnrecoveredTo int64) *FlowLogBuilder {
	b.activeLog.TCPUnrecoveredTo = tcpUnrecoveredTo
	return b
}

func (b *FlowLogBuilder) WithTCPMeanMSS(tcpMeanMSS int64) *FlowLogBuilder {
	b.activeLog.TCPMeanMSS = tcpMeanMSS
	return b
}

func (b *FlowLogBuilder) WithTCPMinMSS(tcpMinMSS int64) *FlowLogBuilder {
	b.activeLog.TCPMinMSS = tcpMinMSS
	return b
}

func (b *FlowLogBuilder) WithTCPMaxMinRTT(tcpMaxMinRTT int64) *FlowLogBuilder {
	b.activeLog.TCPMaxMinRTT = tcpMaxMinRTT
	return b
}

func (b *FlowLogBuilder) WithTCPMaxSmoothRTT(tcpMaxSmoothRTT int64) *FlowLogBuilder {
	b.activeLog.TCPMaxSmoothRTT = tcpMaxSmoothRTT
	return b
}

func (b *FlowLogBuilder) WithTCPMeanMinRTT(tcpMeanMinRTT int64) *FlowLogBuilder {
	b.activeLog.TCPMeanMinRTT = tcpMeanMinRTT
	return b
}

func (b *FlowLogBuilder) WithTCPMeanSmoothRTT(tcpMeanSmoothRTT int64) *FlowLogBuilder {
	b.activeLog.TCPMeanSmoothRTT = tcpMeanSmoothRTT
	return b
}

// containsValue returns true if the value already exists in the slice.
func containsValue(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}

	return false
}
