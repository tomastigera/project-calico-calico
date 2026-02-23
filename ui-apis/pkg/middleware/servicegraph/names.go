// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

// The NameHelper is used to modify the names in the flow and event data based on request-specific parameters.

type NameHelper interface {
	// ConvertL3Flow used to modify name data in an L3Flow.
	ConvertL3Flow(f L3Flow) L3Flow

	// ConvertL7Flow used to modify name data in an L7Flow.
	ConvertL7Flow(f L7Flow) L7Flow

	// ConvertEvent used to modify name data in an Event.
	ConvertEvent(e Event) Event

	// GetCompiledHostNamesFromAggregatedName returns the set of host names associated with a host aggregated name.
	// This method does not update the helper. It returns the final compiled set of hosts associated with the
	// aggregated name.
	GetCompiledHostNamesFromAggregatedName(aggrName string) []string
}

type nameHelper struct {
	lock sync.RWMutex

	// If hosts are being aggregated into groups these will be non-nil.
	hostNameToAggrName  map[string]string
	aggrNameToHostnames map[string][]string

	// Host endpoint to host name lookup.
	hepToHostname map[string]string
}

func NewNameHelper(ctx context.Context, cs k8s.ClientSet, selectors []v1.NamedSelector) (NameHelper, error) {
	hh := &nameHelper{
		hostNameToAggrName:  make(map[string]string),
		aggrNameToHostnames: make(map[string][]string),
		hepToHostname:       make(map[string]string),
	}

	wg := sync.WaitGroup{}

	var errHosts, errNodes error
	wg.Go(func() {

		// If the user has specified a set of host aggregation selectors then query the Node resource and determine
		// which selectors match which nodes. The nodes (hosts) matching a selector will be put in a hosts buckets
		// with the name assigned to the selector.
		nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			errNodes = err
			return
		}

	next_node:
		for _, node := range nodes.Items {
			for _, selector := range selectors {
				if selector.Selector.Evaluate(node.Labels) {
					log.Debugf("Host to aggregated name mapping: %s -> %s", node.Name, selector.Name)
					hh.hostNameToAggrName[node.Name] = selector.Name
					hh.aggrNameToHostnames[selector.Name] = append(hh.aggrNameToHostnames[selector.Name], node.Name)
					continue next_node
				}
			}

			log.Debugf("Host to aggregated name mapping: %s -> *", node.Name)
			hh.hostNameToAggrName[node.Name] = "*"
			hh.aggrNameToHostnames["*"] = append(hh.aggrNameToHostnames["*"], node.Name)
		}
	})

	wg.Go(func() {

		// Get the HostEndpoints to determine a HostEndpoint -> Host name mapping. We use this to correlate events
		// related to HostEndpoint resources with the host or hosts node types.
		hostEndpoints, err := cs.ProjectcalicoV3().HostEndpoints().List(ctx, metav1.ListOptions{})
		if err != nil {
			errHosts = err
			return
		}
		for _, hep := range hostEndpoints.Items {
			log.Debugf("Hostendpoint to host name mapping: %s -> %s", hep.Name, hep.Spec.Node)
			hh.hepToHostname[hep.Name] = hep.Spec.Node
		}
	})

	wg.Wait()

	if errNodes != nil && !errors.IsForbidden(errNodes) {
		return nil, errNodes
	} else if errHosts != nil && !errors.IsForbidden(errHosts) {
		return nil, errHosts
	}

	return hh, nil
}

// ProcessL3Flow updates an L3 flow to include additional aggregation details, and will also update the aggregation
// helper to track additional mappings that were not found during instantiation.
func (ah *nameHelper) ConvertL3Flow(f L3Flow) L3Flow {
	ah.lock.RLock()
	defer ah.lock.RUnlock()

	// The aggregated name for hosts is actually the full name. Swap over, and apply the calculated aggregated name.
	if f.Edge.Source.Type == v1.GraphNodeTypeClusterNode || f.Edge.Source.Type == v1.GraphNodeTypeHost {
		f.Edge.Source.Name = f.Edge.Source.NameAggr
		if nameAggr := ah.hostNameToAggrName[f.Edge.Source.Name]; nameAggr != "" {
			f.Edge.Source.NameAggr = nameAggr
		} else {
			// The node name in the flow is not currently configured - include in the "*" bucket.
			f.Edge.Source.NameAggr = "*"
			ah.addAdditionalWildcardAggregatedNode(f.Edge.Source.Name)
		}
	}
	if f.Edge.Dest.Type == v1.GraphNodeTypeClusterNode || f.Edge.Dest.Type == v1.GraphNodeTypeHost {
		f.Edge.Dest.Name = f.Edge.Dest.NameAggr
		if nameAggr := ah.hostNameToAggrName[f.Edge.Dest.Name]; nameAggr != "" {
			f.Edge.Dest.NameAggr = nameAggr
		} else {
			// The node name in the flow is not currently configured - include in the "*" bucket.
			f.Edge.Dest.NameAggr = "*"
			ah.addAdditionalWildcardAggregatedNode(f.Edge.Dest.Name)
		}
	}

	return f
}

// ProcessL7Flow updates an L7 flow to include additional aggregation details, and will also update the aggregation
// helper to track additional mappings that were not found during instantiation.
func (ah *nameHelper) ConvertL7Flow(f L7Flow) L7Flow {
	ah.lock.RLock()
	defer ah.lock.RUnlock()

	// The aggregated name for hosts is actually the full name. Swap over, and apply the calculated aggregated name.
	if f.Edge.Source.Type == v1.GraphNodeTypeClusterNode || f.Edge.Source.Type == v1.GraphNodeTypeHost {
		f.Edge.Source.Name = f.Edge.Source.NameAggr
		if nameAggr := ah.hostNameToAggrName[f.Edge.Source.Name]; nameAggr != "" {
			f.Edge.Source.NameAggr = nameAggr
		} else {
			// The node name in the flow is not currently configured - include in the "*" bucket.
			f.Edge.Source.NameAggr = "*"
			ah.addAdditionalWildcardAggregatedNode(f.Edge.Source.Name)
		}
	}
	if f.Edge.Dest.Type == v1.GraphNodeTypeClusterNode || f.Edge.Dest.Type == v1.GraphNodeTypeHost {
		f.Edge.Dest.Name = f.Edge.Dest.NameAggr
		if nameAggr := ah.hostNameToAggrName[f.Edge.Dest.Name]; nameAggr != "" {
			f.Edge.Dest.NameAggr = nameAggr
		} else {
			// The node name in the flow is not currently configured - include in the "*" bucket.
			f.Edge.Dest.NameAggr = "*"
			ah.addAdditionalWildcardAggregatedNode(f.Edge.Dest.Name)
		}
	}

	return f
}

// ProcessEvent updates an event to include additional aggregation details, and will also update the aggregation
// helper to track additional mappings that were not found during instantiation.
func (ah *nameHelper) ConvertEvent(e Event) Event {
	ah.lock.RLock()
	defer ah.lock.RUnlock()

	// Be careful not to modify the original data which is cached.
	eps := e.Endpoints
	e.Endpoints = make([]FlowEndpoint, len(eps))
	for i, ep := range eps {
		switch ep.Type {
		case v1.GraphNodeTypeClusterNode, v1.GraphNodeTypeHost:
			ep.Name = ep.NameAggr
			if nameAggr := ah.hostNameToAggrName[ep.NameAggr]; nameAggr != "" {
				ep.NameAggr = nameAggr
			} else {
				// The node in the event is not currently configured in the cluster - include in the "*" bucket.
				ep.NameAggr = "*"
				ah.addAdditionalWildcardAggregatedNode(e.Endpoints[i].Name)
			}
		case v1.GraphNodeTypeHostEndpoint:
			// We don't expose host endpoints - just hosts - so adjust the event endpoint and include the appropriate
			// aggregated name.
			ep.Type = v1.GraphNodeTypeHost
			if name, ok := ah.hepToHostname[ep.NameAggr]; ok {
				ep.Name = name
				if nameAggr := ah.hostNameToAggrName[ep.NameAggr]; nameAggr != "" {
					ep.NameAggr = nameAggr
				} else {
					// The node name in the event is not currently configured - include in the "*" bucket.
					ep.NameAggr = "*"
					ah.addAdditionalWildcardAggregatedNode(e.Endpoints[i].Name)
				}
			} else {
				// We have a HEP in the logs that we no longer know about. Just keep the name.
				ep.Name = ep.NameAggr
				ep.NameAggr = "*"
			}
		}
		e.Endpoints[i] = ep
	}

	return e
}

// GetCompiledHostNamesFromAggregatedName returns the set of host names that correspond to the aggregated name.
// This returns nil if nodes are not aggregated into multiple groups.
func (ah *nameHelper) GetCompiledHostNamesFromAggregatedName(aggrName string) []string {
	if len(ah.aggrNameToHostnames) <= 1 {
		return nil
	}
	ah.lock.RLock()
	defer ah.lock.RUnlock()
	return ah.aggrNameToHostnames[aggrName]
}

// addAdditionalWildcardAggregatedNode includes an additional node in the "*" bucket.
// The caller should be holding the read-lock.
func (ah *nameHelper) addAdditionalWildcardAggregatedNode(name string) {
	ah.lock.RUnlock()
	defer ah.lock.RLock()
	ah.lock.Lock()
	defer ah.lock.Unlock()
	ah.hostNameToAggrName[name] = "*"
	ah.aggrNameToHostnames["*"] = append(ah.aggrNameToHostnames["*"], name)
}

// ---- Mocked helper for testing ----

func NewMockNameHelper(hostNameToAggrName map[string]string, hepToHostname map[string]string) NameHelper {
	if hostNameToAggrName == nil {
		hostNameToAggrName = make(map[string]string)
	}
	if hepToHostname == nil {
		hepToHostname = make(map[string]string)
	}
	aggrNameToHostnames := make(map[string][]string)
	for h, a := range hostNameToAggrName {
		aggrNameToHostnames[a] = append(aggrNameToHostnames[a], h)
	}
	return &nameHelper{
		hostNameToAggrName:  hostNameToAggrName,
		aggrNameToHostnames: aggrNameToHostnames,
		hepToHostname:       hepToHostname,
	}
}
