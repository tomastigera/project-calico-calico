package intdataplane

import (
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

type VXLANConflictHandler struct {
	ipVersion uint8
	logCtx    *logrus.Entry

	vtepAccessor     func(node string) *proto.VXLANTunnelEndpointUpdate
	vtepRoutesByDest map[string]*proto.RouteUpdate
	nodesByVTEPMAC   map[string]set.Set[string]
}

func (m *VXLANConflictHandler) vtepIPRoutedByNode(cidr string, node string) bool {
	return m.vtepRoutesByDest[cidr] != nil && m.vtepRoutesByDest[cidr].DstNodeName == node
}

func (m *VXLANConflictHandler) addVTEPToAddressTracking(msg *proto.VXLANTunnelEndpointUpdate) {
	vtepMAC, err := parseMacForIPVersion(msg, m.ipVersion)
	if err != nil {
		// MAC address is invalid, no need to track this (VTEPs that conflict with it will fail to parse too)
		return
	}
	if m.nodesByVTEPMAC[vtepMAC.String()] == nil {
		m.nodesByVTEPMAC[vtepMAC.String()] = set.New[string]()
	}
	m.nodesByVTEPMAC[vtepMAC.String()].Add(msg.Node)
}

func (m *VXLANConflictHandler) deleteVTEPFromAddressTracking(msg *proto.VXLANTunnelEndpointUpdate) {
	vtepMAC, err := parseMacForIPVersion(msg, m.ipVersion)
	if err != nil {
		// MAC address is invalid, no need to delete as this was not part of our tracking state to begin with.
		return
	}
	m.nodesByVTEPMAC[vtepMAC.String()].Discard(msg.Node)
	if m.nodesByVTEPMAC[vtepMAC.String()].Len() == 0 {
		delete(m.nodesByVTEPMAC, vtepMAC.String())
	}
}

func (m *VXLANConflictHandler) vtepConflicts(ip string, suffix string, mac string, node string) bool {
	if model.GetRemoteClusterPrefix(node) == "" {
		// No prefix means it's a local node, local nodes win any conflicts.
		return false
	}

	logCtx := m.logCtx.WithFields(logrus.Fields{
		"vtepCIDR":         ip + suffix,
		"vtepMAC":          mac,
		"vtepRoutesByDest": m.vtepRoutesByDest,
		"nodesByVTEPMAC":   m.nodesByVTEPMAC[mac],
	})

	// Check if VTEP conflicts based on IP address.
	// If the VTEP IP does not have a route, or is routed by a different node, this VTEP lost an IP conflict in the Calc Graph.
	if !m.vtepIPRoutedByNode(ip+suffix, node) {
		logCtx.Warn("VTEP conflicts with another based on IP address. VTEP will not be programmed.")
		return true
	}

	// Validate that our VTEP MAC address state is valid.
	if m.nodesByVTEPMAC[mac] == nil || !m.nodesByVTEPMAC[mac].Contains(node) {
		logCtx.Error("BUG: MAC address state missing node associated with VTEP. VTEP will be not be programmed.")
		return true
	}

	// Then, check if VTEP conflicts based on MAC address.
	preferredNodeForVTEPMAC := m.getPreferredNodeForVTEPMAC(mac)
	if preferredNodeForVTEPMAC != node {
		logCtx.Warnf("VTEP conflicts with another node (%s) based on MAC address. VTEP will not be programmed.", preferredNodeForVTEPMAC)
		return true
	}

	return false
}

func (m *VXLANConflictHandler) getPreferredNodeForVTEPMAC(mac string) string {
	var programmableNodesForVTEPMAC []string

	for node := range m.nodesByVTEPMAC[mac].All() {
		vtepIP, err := m.getVTEPIPForNode(node)
		if err == nil && m.vtepIPRoutedByNode(vtepIP, node) {
			programmableNodesForVTEPMAC = append(programmableNodesForVTEPMAC, node)
		}
	}

	if len(programmableNodesForVTEPMAC) == 0 {
		return ""
	} else {
		sort.Strings(programmableNodesForVTEPMAC)
		return programmableNodesForVTEPMAC[0]
	}
}

func (m *VXLANConflictHandler) getVTEPIPForNode(node string) (string, error) {
	vtep := m.vtepAccessor(node)

	if vtep == nil {
		return "", fmt.Errorf("could not resolve VTEP for node %s", node)
	}

	if m.ipVersion == 4 {
		return vtep.Ipv4Addr + "/32", nil
	} else {
		return vtep.Ipv6Addr + "/128", nil
	}
}

func (m *VXLANConflictHandler) handleRouteUpdate(msg *proto.RouteUpdate) bool {
	if (isType(msg, proto.RouteType_LOCAL_TUNNEL) || isType(msg, proto.RouteType_REMOTE_TUNNEL)) && msg.IpPoolType == proto.IPPoolType_VXLAN {
		m.logCtx.WithField("msg", msg).Debug("Handling VTEP route update")
		m.vtepRoutesByDest[msg.Dst] = msg
		return true
	} else if _, routeExists := m.vtepRoutesByDest[msg.Dst]; routeExists {
		// The route exists but no longer represents a VTEP - it should no longer be tracked.
		return m.handleRouteRemove(&proto.RouteRemove{Dst: msg.Dst})
	}
	return false
}

func (m *VXLANConflictHandler) handleRouteRemove(msg *proto.RouteRemove) bool {
	if _, exists := m.vtepRoutesByDest[msg.Dst]; exists {
		logrus.Debug("deleting tunnel dst ", msg.Dst)
		delete(m.vtepRoutesByDest, msg.Dst)
		return true
	}
	return false
}

func (m *VXLANConflictHandler) handleVTEPUpdate(msg *proto.VXLANTunnelEndpointUpdate) {
	m.addVTEPToAddressTracking(msg)
}

func (m *VXLANConflictHandler) handleVTEPRemove(msg *proto.VXLANTunnelEndpointRemove) {
	vtep := m.vtepAccessor(msg.Node)
	if vtep != nil {
		m.deleteVTEPFromAddressTracking(vtep)
	} else {
		m.logCtx.WithField("msg", msg).Warn("Received remove for unknown VTEP. VTEP state may be invalid.")
	}
}
