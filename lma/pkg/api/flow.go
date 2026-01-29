// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package api

import (
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/lib/std/uniquestr"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

const (
	FlowlogBuckets = "flog_buckets"
)

const (
	FlowLogEndpointTypeInvalid    = ""
	FlowLogEndpointTypeWEP        = "wep"
	FlowLogEndpointTypeHEP        = "hep"
	FlowLogEndpointTypeNetworkSet = "ns"
	FlowLogEndpointTypeNetwork    = "net"
	FlowLogNetworkPublic          = "pub"
	FlowLogNetworkPrivate         = "pvt"
)

// Container type to hold the EndpointsReportFlow and/or an error.
type FlowLogResult struct {
	*apiv3.EndpointsReportFlow
	Err error
}

type EndpointType string

const (
	GlobalEndpointType = "-"

	EndpointTypeInvalid EndpointType = ""
	EndpointTypeWep     EndpointType = "wep"
	EndpointTypeHep     EndpointType = "hep"
	EndpointTypeNs      EndpointType = "ns"
	EndpointTypeNet     EndpointType = "net"
)

func StringToEndpointType(str string) EndpointType {
	for _, et := range []EndpointType{EndpointTypeWep, EndpointTypeHep, EndpointTypeNs, EndpointTypeNet} {
		if str == string(et) {
			return et
		}
	}

	return EndpointTypeInvalid
}

type ReporterType string

const (
	ReporterTypeInvalid     ReporterType = ""
	ReporterTypeSource      ReporterType = "src"
	ReporterTypeDestination ReporterType = "dst"
)

func FromLinseedFlow(lsf lapi.L3Flow) *Flow {
	// Ports and protocol.
	srcPort := uint16(lsf.Key.Source.Port)
	dstPort := uint16(lsf.Key.Destination.Port)

	// If the protocol already parses as an int, just
	// use that.
	var proto *uint8
	pn, err := strconv.Atoi(lsf.Key.Protocol)
	if err != nil {
		logrus.WithField("proto", lsf.Key.Protocol).Debug("Handling string protocol")
		p := numorstring.ProtocolFromString(lsf.Key.Protocol)
		proto = GetProtocolNumber(&p)
	} else {
		uipn := uint8(pn)
		proto = &uipn
	}

	flow := &Flow{
		Reporter: ReporterType(lsf.Key.Reporter),
		Source: FlowEndpointData{
			Type:      EndpointType(lsf.Key.Source.Type),
			Name:      lsf.Key.Source.AggregatedName,
			Namespace: lsf.Key.Source.Namespace,
			IPs:       getIPs(lsf.SourceIPs),
			Port:      &srcPort,
			Labels:    GetLinseedFlowLabels(lsf.SourceLabels),
		},
		Destination: FlowEndpointData{
			Type:        EndpointType(lsf.Key.Destination.Type),
			Name:        lsf.Key.Destination.AggregatedName,
			Namespace:   lsf.Key.Destination.Namespace,
			IPs:         getIPs(lsf.DestinationIPs),
			Port:        &dstPort,
			Labels:      GetLinseedFlowLabels(lsf.DestinationLabels),
			Domains:     strings.Join(lsf.DestDomains, ","),
			ServiceName: GetServiceName(lsf.Service),
		},
		ActionFlag: ActionFlagFromString(string(lsf.Key.Action)),
		Proto:      proto,
		Policies:   GetPolicyHits(lsf.Policies),
	}

	// Set IP version based on source IP, defaulting to v4.
	var ipVersion *int
	if len(flow.Source.IPs) != 0 {
		ipVersion = getVersion(flow.Source.IPs)
	} else if len(flow.Destination.IPs) != 0 {
		ipVersion = getVersion(flow.Destination.IPs)
	}

	if ipVersion != nil {
		flow.IPVersion = ipVersion
	} else {
		defaultIPVersion := 4
		flow.IPVersion = &defaultIPVersion
	}

	return flow
}

// GetLinseedFlowLabels extracts the flow endpoint labels from the composite aggregation key.
func GetLinseedFlowLabels(labels []lapi.FlowLabels) uniquelabels.Map {
	// Find the most frequently seen label value.
	l := make(map[string]string)
	for _, labelKey := range labels {
		weight := int64(0)
		val := ""
		for _, v := range labelKey.Values {
			if v.Count > weight {
				val = v.Value
			}
		}
		l[labelKey.Key] = val
	}
	return uniquelabels.Make(l)
}

// getIPs will extract net.IP from raw string
func getIPs(rawIPs []string) []net.IP {
	var ips []net.IP
	for _, raw := range rawIPs {
		ip := net.ParseIP(raw)
		ips = append(ips, *ip)
	}
	return ips
}

// getVersion will return the ip version across all IPs
// if this version is consistent or nil (marking it as unknown)
func getVersion(ips []net.IP) *int {
	if len(ips) == 0 {
		return nil
	}

	if len(ips) == 1 {
		version := ips[0].Version()
		return &version
	}

	version := ips[0].Version()

	for _, ip := range ips {
		if version != ip.Version() {
			return nil
		}
	}

	return &version
}

func GetPolicyHits(pols []lapi.Policy) []PolicyHit {
	hits := []PolicyHit{}
	for i, p := range pols {
		hit, err := NewPolicyHit(Action(p.Action), p.Count, i, p.Name, p.Namespace, p.Kind, p.Tier, p.RuleID)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"name":      p.Name,
				"namespace": p.Namespace,
				"kind":      p.Kind,
			}).Warn("Skipping invalid policy")
			continue
		}
		hits = append(hits, hit)
	}
	return hits
}

// GetServiceName returns the name of a service, an empty string if the service is nil.
func GetServiceName(service *lapi.Service) string {
	if service != nil {
		return service.Name
	}

	return ""
}

type Flow struct {
	// Reporter
	Reporter ReporterType

	// Source endpoint data for the flow.
	Source FlowEndpointData

	// Destination endpoint data for the flow.
	Destination FlowEndpointData

	// Original action for the flow.
	ActionFlag ActionFlag

	// The protocol of the flow. Nil if unknown.
	Proto *uint8

	// The IP version of the flow. Nil if unknown.
	IPVersion *int

	// Policies applied to the reporting endpoint.
	Policies []PolicyHit
}

// FlowEndpointData can be used to describe the source or destination
// of a flow log.
type FlowEndpointData struct {
	// Endpoint type.
	Type EndpointType

	// Name.
	Name string

	// Namespace - should only be set for namespaces endpoints.
	Namespace string

	// Labels - only relevant for Calico endpoints.
	Labels uniquelabels.Map

	// IPs, or no data if unknown.
	IPs []net.IP

	// Domains.
	Domains string

	// Port, or nil if unknown.
	Port *uint16

	// ServiceAccount, or nil if unknown.
	ServiceAccount *string

	// NamedPorts is the set of named ports for this endpoint.
	NamedPorts []EndpointNamedPort

	// ServiceName.
	ServiceName string
}

// IsCalicoManagedEndpoint returns if the endpoint is managed by Calico.
func (e *FlowEndpointData) IsCalicoManagedEndpoint() bool {
	switch e.Type {
	// Only HEPs and WEPs are calico-managed endpoints.  NetworkSets are handled by Calico, but are not endpoints in
	// the sense that policy is not applied directly to them.
	case EndpointTypeHep, EndpointTypeWep:
		return true
	default:
		return false
	}
}

// IsLabelledEndpoint returns if the endpoint represents a labelled endpoint (i.e. one that can be matched with
// selectors).
func (e *FlowEndpointData) IsLabelledEndpoint() bool {
	switch e.Type {
	// HEPs, WEPs and NetworkSets are all labelled endpoint types that may be selected by calico selectors.
	case EndpointTypeHep, EndpointTypeWep, EndpointTypeNs:
		return true
	default:
		return false
	}
}

var (
	labelNamespace = uniquestr.Make(apiv3.LabelNamespace)
	labelOrch      = uniquestr.Make(apiv3.LabelOrchestrator)
)

// Implement the label Get method for use with the selector processing. This allows us to inject additional labels
// without having to update the dictionary.
func (e *FlowEndpointData) GetHandle(labelName uniquestr.Handle) (handle uniquestr.Handle, present bool) {
	switch labelName {
	case labelNamespace:
		return uniquestr.Make(e.Namespace), e.Namespace != ""
	case labelOrch:
		return uniquestr.Make(apiv3.OrchestratorKubernetes), e.Namespace != ""
	default:
		return e.Labels.GetHandle(labelName)
	}
}

// EndpointNamedPort encapsulates details about a named port on an endpoint.
type EndpointNamedPort struct {
	Name     string
	Protocol uint8
	Port     uint16
}
