// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package calc

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

func NewIPSecBindingCalculator() *IPSecBindingCalculator {
	return &IPSecBindingCalculator{
		nodeNameToNodeInfo: map[string]nodeInfo{},
		addressToNodeNames: map[ip.Addr][]string{},

		ipToEndpointKeys:  map[ip.Addr][]model.WorkloadEndpointKey{},
		endpointKeysToIPs: map[model.WorkloadEndpointKey][]ip.Addr{},
	}
}

// IPSecBindingCalculator resolves the set of IPs behind each IPsec tunnel.  There is an IPsec tunnel
// to each host's IP, and the IPs behind its tunnel are all the workloads on that host.
//
// In order to make the calculation robust against races and misconfiguration, we need to deal with:
//
//   - host IPs being missing (these are populated asynchronously by the kubelet, for example)
//   - host IPs being duplicated (where one node is being deleted async, while its IP is being reused)
//   - host IPs being deleted before/after workload IPs (where felix's general contract applies: it should apply
//     the same policy given the same state of the datastore, no matter what path was taken to get there)
//   - workload IPs being reused (and so transiently appearing on multiple workload endpoints on a host)
//   - incorrect data created by a user (which may only be resolved much later when they spot their mistake).
//
// In particular, we need to do something safe while the misconfiguration is in place and then we need to
// correct the state when the misconfiguration is removed.
type IPSecBindingCalculator struct {
	nodeNameToNodeInfo map[string]nodeInfo
	addressToNodeNames map[ip.Addr][]string

	ipToEndpointKeys  map[ip.Addr][]model.WorkloadEndpointKey
	endpointKeysToIPs map[model.WorkloadEndpointKey][]ip.Addr

	OnTunnelAdded      func(tunnelAddr ip.Addr)
	OnTunnelRemoved    func(tunnelAddr ip.Addr)
	OnBindingAdded     func(b IPSecBinding)
	OnBindingRemoved   func(b IPSecBinding)
	OnBlacklistAdded   func(workloadAddr ip.Addr)
	OnBlacklistRemoved func(workloadAddr ip.Addr)
}

type nodeInfo struct {
	addr          ip.Addr
	workloadCount int
}

type IPSecBinding struct {
	TunnelAddr, WorkloadAddr ip.Addr
}

func (c *IPSecBindingCalculator) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	allUpdDispatcher.Register(model.HostIPKey{}, c.OnHostIPUpdate)
	allUpdDispatcher.Register(model.WorkloadEndpointKey{}, c.OnEndpointUpdate)
}

func (c *IPSecBindingCalculator) OnHostIPUpdate(update api.Update) (_ bool) {
	hostIPKey := update.Key.(model.HostIPKey)
	nodeName := hostIPKey.Hostname
	oldNodeInfo := c.nodeNameToNodeInfo[nodeName]
	oldIP := oldNodeInfo.addr
	var newIP ip.Addr
	logCxt := log.WithField("host", hostIPKey.Hostname)
	if update.Value != nil {
		logCxt = logCxt.WithField("newIP", update.Value)
		logCxt.Debug("Updating IP for host")
		newIP = ip.FromNetIP(update.Value.(*net.IP).IP)
	} else {
		logCxt.Debug("Host deleted")
	}

	if oldIP == newIP {
		// No change. Ignore.
		logCxt.Debug("IP didn't change, ignoring")
		return
	}

	// First remove the old IP.  For simplicity we treat a mutation as a remove followed by an add.
	if oldIP != nil {
		// Figure out how many active (i.e. with workloads) nodes were sharing the old IP before and after updating the
		// index.  The delta will tell us if we have any clean up to do.
		oldNumNodesSharingIP := c.numActiveNodesSharingIP(oldIP)

		// Fix up the index.
		if oldNodeInfo.workloadCount == 0 {
			delete(c.nodeNameToNodeInfo, nodeName)
		} else {
			newNodeInfo := oldNodeInfo
			newNodeInfo.addr = nil
			c.nodeNameToNodeInfo[nodeName] = newNodeInfo
		}
		updatedNodeNames := filterOutString(c.addressToNodeNames[oldIP], nodeName)
		deactivateTunnel := false
		if len(updatedNodeNames) == 0 {
			delete(c.addressToNodeNames, oldIP)
			deactivateTunnel = true
		} else {
			c.addressToNodeNames[oldIP] = updatedNodeNames
		}

		newNumNodesSharingIP := c.numActiveNodesSharingIP(oldIP)

		if oldNumNodesSharingIP > 1 && newNumNodesSharingIP == 1 {
			// Previously, we were sharing this IP with another node (so we couldn't emit any bindings for either node)
			// but now it only belongs to the other node. Emit any bindings that belong to the other node.
			logCxt.Debug("Removing node made IP unique, emitting bindings for other node")
			otherNode := c.findActiveNodeByIP(oldIP)
			c.activateBindingsForNode(otherNode, oldIP)
		} else if oldNumNodesSharingIP == 1 && newNumNodesSharingIP == 0 {
			logCxt.Debug("IP was unique before, removing bindings")
			c.deactivateBindingsForNode(nodeName, oldIP)
		}

		if deactivateTunnel {
			c.OnTunnelRemoved(oldIP)
		}
	}

	if newIP != nil {
		// Figure out how many active (i.e. with workloads) nodes were sharing the new IP before and after updating the
		// index.  The exact values will tell us if we have any clean up to do.
		oldNumNodesSharingIP := c.numActiveNodesSharingIP(newIP)

		// Put the new IP in the node IP indexes.
		newNodeInfo := oldNodeInfo
		newNodeInfo.addr = newIP
		c.nodeNameToNodeInfo[nodeName] = newNodeInfo

		addrToNodeNames := c.addressToNodeNames[newIP]
		if len(addrToNodeNames) == 0 {
			c.OnTunnelAdded(newIP)
		}
		c.addressToNodeNames[newIP] = append(addrToNodeNames, nodeName)

		newNumNodesSharingIP := c.numActiveNodesSharingIP(newIP)

		if oldNumNodesSharingIP < 1 && newNumNodesSharingIP == 1 {
			// No active node had this IP before and we just claimed it.
			logCxt.Debug("New IP is unique, emitting bindings")
			c.activateBindingsForNode(nodeName, newIP)
		} else if oldNumNodesSharingIP == 1 && newNumNodesSharingIP > 1 {
			// IP previously belonged solely to another node but now it's ambiguous, need to remove the bindings that
			// were associated with the old node.
			logCxt.Warn("New IP was previously owned by another node but now it's shared, removing bindings")
			otherNode := c.addressToNodeNames[newIP][0]
			c.deactivateBindingsForNode(otherNode, newIP)
		}
	}
	return
}

func (c *IPSecBindingCalculator) numActiveNodesSharingIP(nodeIP ip.Addr) (count int) {
	if nodeIP == nil {
		return
	}
	for _, nodeName := range c.addressToNodeNames[nodeIP] {
		nodeInfo := c.nodeNameToNodeInfo[nodeName]
		if nodeInfo.addr != nodeIP {
			log.WithFields(log.Fields{
				"expectedIP": nodeIP,
				"node":       nodeName,
				"recordedIP": nodeInfo.addr,
			}).Panic("Bug: forward and reverse indexes disagree")
		}
		if nodeInfo.workloadCount > 0 {
			count++
		}
	}
	return
}

func (c *IPSecBindingCalculator) findActiveNodeByIP(nodeIP ip.Addr) (nodeName string) {
	for _, nodeName = range c.addressToNodeNames[nodeIP] {
		nodeInfo := c.nodeNameToNodeInfo[nodeName]
		if nodeInfo.workloadCount != 0 {
			break
		}
	}
	if nodeName == "" {
		log.WithField("ip", nodeIP).Panic(
			"Bug: failed to find node matching IP after previously looking it up.")
	}
	return
}

func (c *IPSecBindingCalculator) activateBindingsForNode(nodeName string, nodeIP ip.Addr) {
	for wepKey, addrs := range c.endpointKeysToIPs {
		if wepKey.Hostname != nodeName {
			continue
		}

		for _, addr := range addrs {
			// Check the reverse index to verify that this binding is unique.
			numWepsWithThatIP := len(c.ipToEndpointKeys[addr])
			if numWepsWithThatIP != 1 {
				continue
			}
			// This is a unique binding, emit it.
			c.unblacklistIP(addr)
			c.OnBindingAdded(IPSecBinding{WorkloadAddr: addr, TunnelAddr: nodeIP})
		}
	}
}

func (c *IPSecBindingCalculator) deactivateBindingsForNode(nodeName string, nodeIP ip.Addr) {
	for wepKey, addrs := range c.endpointKeysToIPs {
		if wepKey.Hostname != nodeName {
			continue
		}

		for _, addr := range addrs {
			// Check the reverse index to verify that this binding is unique.
			numWepsWithThatIP := len(c.ipToEndpointKeys[addr])
			if numWepsWithThatIP != 1 {
				continue
			}
			// This was a unique binding, remove it.
			c.OnBindingRemoved(IPSecBinding{WorkloadAddr: addr, TunnelAddr: nodeIP})
			c.blacklistIP(addr)
		}
	}
}

func (c *IPSecBindingCalculator) OnEndpointUpdate(update api.Update) (_ bool) {
	wepKey := update.Key.(model.WorkloadEndpointKey)

	// Look up the old (possibly nil) and new (possibly nil) IPs for this endpoint.
	oldIPs := c.endpointKeysToIPs[wepKey]
	var newIPs []ip.Addr
	if update.Value != nil {
		for _, addr := range update.Value.(*model.WorkloadEndpoint).IPv4Nets {
			felixAddr := ip.FromNetIP(addr.IP)
			newIPs = append(newIPs, felixAddr)
		}
	}
	logCxt := log.WithFields(log.Fields{
		"oldIPs": oldIPs,
		"newIPs": newIPs,
	})
	logCxt.Debug("Updating endpoint IPs")

	// Look up the node that this workload is on and update the node->workload reference count.  If we're adding
	// or removing an endpoint then we may have made the node active or inactive and that may have a knock-on
	// effect on whether the node's IP is being shared.
	node := wepKey.Hostname
	nodeInfo := c.nodeNameToNodeInfo[node]
	nodeIP := nodeInfo.addr
	oldNodesWithThatIP := c.numActiveNodesSharingIP(nodeIP)

	if len(oldIPs) == 0 && len(newIPs) != 0 {
		nodeInfo.workloadCount++
		c.nodeNameToNodeInfo[node] = nodeInfo
	} else if len(newIPs) == 0 && len(oldIPs) != 0 {
		nodeInfo.workloadCount--
		if nodeInfo.workloadCount == 0 && nodeInfo.addr == nil {
			delete(c.nodeNameToNodeInfo, node)
		} else {
			c.nodeNameToNodeInfo[node] = nodeInfo
		}
	}

	newNodesWithThatIP := c.numActiveNodesSharingIP(nodeIP)

	if oldNodesWithThatIP == 1 && newNodesWithThatIP == 2 {
		// Adding this workload made a node active but that means that two nodes are now sharing an IP.  We need to
		// remove the bindings that were attached to the old node.
		for _, otherNodeName := range c.addressToNodeNames[nodeIP] {
			if node == otherNodeName {
				continue
			}
			otherNodeInfo := c.nodeNameToNodeInfo[otherNodeName]
			if otherNodeInfo.workloadCount == 0 {
				continue
			}

			// Found the other node...
			c.deactivateBindingsForNode(otherNodeName, nodeIP)
			break
		}
	} else if oldNodesWithThatIP == 2 && newNodesWithThatIP == 1 {
		// Removing this workload has made the node inactive and, previously, it was sharing an IP with another node.
		// Since the other node is now the sole owner of the IP, we need to emit the bindings for the other node.
		otherNode := c.findActiveNodeByIP(nodeIP)
		c.activateBindingsForNode(otherNode, nodeIP)
	}

	removedIPs := set.FromArray(oldIPs)
	addedIPs := set.New[ip.Addr]()
	for _, addr := range newIPs {
		if removedIPs.Contains(addr) {
			removedIPs.Discard(addr)
		} else {
			addedIPs.Add(addr)
		}
	}

	c.endpointKeysToIPs[wepKey] = newIPs

	for addr := range removedIPs.All() {
		// Remove old reverse index.
		c.removeIPToKey(addr, wepKey)
		// Now check what that leaves behind.
		numWepsStillSharingIP := len(c.ipToEndpointKeys[addr])
		if numWepsStillSharingIP > 1 {
			// IP wasn't unique before and it's still not unique.  IP should already be blacklisted so we have nothing
			// to do.
			log.WithField("ip", addr).Warn("Workload IP is not unique, unable to do IPsec to IP.")
			continue
		} else if numWepsStillSharingIP == 1 {
			// Must have been 2 workloads sharing that IP before but now there's only one.  Previously we'll have
			// blacklisted the IP.  We need to look up the other workload and see if its binding is now unambiguous.
			otherWepKey := c.ipToEndpointKeys[addr][0]
			otherNode := otherWepKey.Hostname
			otherNodesIP := c.nodeNameToNodeInfo[otherNode].addr
			if otherNodesIP == nil {
				log.WithField("node", otherNode).Warn(
					"Missing node IP, unable to do IPsec for workload on that node.")
				continue
			}
			if c.numActiveNodesSharingIP(otherNodesIP) != 1 {
				log.WithFields(log.Fields{"ip": otherNodesIP, "nodes": c.addressToNodeNames[addr]}).Warn(
					"Node's IP is not unique, unable to do IPsec for workloads on that node.")
				continue
			}
			c.unblacklistIP(addr)
			c.OnBindingAdded(IPSecBinding{TunnelAddr: otherNodesIP, WorkloadAddr: addr})
			continue
		}

		// If we get here, numWepsStillSharingIP == 0: there must have been exactly one workload with this IP.
		if oldNodesWithThatIP == 0 {
			// The workload was on a node with missing IP; we'll previously have blacklisted the workload's IP.
			// Remove the blacklist.
			log.WithFields(log.Fields{"workloadIP": addr, "nodeIP": nodeIP}).Debug(
				"Removing IP from endpoint that had missing node IP.")
			c.unblacklistIP(addr)
			continue
		} else if oldNodesWithThatIP > 1 {
			// The workload was on a node with conflicting IP; we'll previously have blacklisted the workload's IP.
			// Remove the blacklist.
			log.WithFields(log.Fields{"workloadIP": addr, "nodeIP": nodeIP}).Debug(
				"Removing IP from endpoint that had conflicted node IP.")
			c.unblacklistIP(addr)
			continue
		}

		// Removed IP was unique and its node IP was unique.  There should have been an active binding.
		c.OnBindingRemoved(IPSecBinding{TunnelAddr: nodeIP, WorkloadAddr: addr})
	}

	for addr := range addedIPs.All() {
		// Before we add the IP to the index, check who has that IP already.  If we're about to give the IP multiple
		// owners then we'll need to remove the old binding because it's no longer unique.
		numWepsWithThatIP := len(c.ipToEndpointKeys[addr])

		if numWepsWithThatIP == 1 {
			// The IP currently has a unique owner, check if their node has a unique address...
			otherWepKey := c.ipToEndpointKeys[addr][0]
			otherNode := otherWepKey.Hostname
			otherNodesIP := c.nodeNameToNodeInfo[otherNode].addr
			if otherNodesIP != nil && c.numActiveNodesSharingIP(otherNodesIP) == 1 {
				log.WithField("node", otherNode).Warn(
					"IP address now owned by multiple workloads, unable to do IPsec for that IP.")
				c.OnBindingRemoved(IPSecBinding{TunnelAddr: otherNodesIP, WorkloadAddr: addr})
				c.blacklistIP(addr)
			}
		}

		// Add the new IP to the index.
		c.addIPToKey(addr, wepKey)

		if numWepsWithThatIP != 0 {
			// IP is shared; if it only just became so, we'll have blacklisted it above, otherwise, it should already
			// be blacklisted so we don't need to do anything.
			log.WithField("ip", addr).Warn(
				"Workload IP address not unique, unable to do IPsec for that IP.")
			continue
		}

		// If we get here, the new IP is uniquely owned by this workload.  Check whether we have a unique IP on its
		// node too.
		if newNodesWithThatIP == 0 {
			log.WithFields(log.Fields{"workloadIP": addr, "nodeIP": nodeIP, "node": node}).Debug(
				"Node IP not known. Unable to do IPsec for this workload.")
			c.blacklistIP(addr)
			continue
		} else if newNodesWithThatIP > 1 {
			log.WithFields(log.Fields{"workloadIP": addr, "nodeIP": nodeIP, "node": node}).Debug(
				"Node IP not unique. Unable to do IPsec for this workload.")
			c.blacklistIP(addr)
			continue
		}

		// Added IP is unique, as is its node's IP, emit a binding.
		c.OnBindingAdded(IPSecBinding{TunnelAddr: nodeIP, WorkloadAddr: addr})
	}

	return
}

func (c *IPSecBindingCalculator) blacklistIP(addr ip.Addr) {
	c.OnBlacklistAdded(addr)
}

func (c *IPSecBindingCalculator) unblacklistIP(addr ip.Addr) {
	c.OnBlacklistRemoved(addr)
}

func (c *IPSecBindingCalculator) addIPToKey(addr ip.Addr, wepKey model.WorkloadEndpointKey) {
	c.ipToEndpointKeys[addr] = append(c.ipToEndpointKeys[addr], wepKey)
}

func (c *IPSecBindingCalculator) removeIPToKey(addr ip.Addr, wepKey model.WorkloadEndpointKey) {
	updatedWeps := filterOutWepKey(c.ipToEndpointKeys[addr], wepKey)
	if len(updatedWeps) > 0 {
		c.ipToEndpointKeys[addr] = updatedWeps
	} else {
		delete(c.ipToEndpointKeys, addr)
	}
}

func filterOutWepKey(a []model.WorkloadEndpointKey, toSkip model.WorkloadEndpointKey) []model.WorkloadEndpointKey {
	var filtered []model.WorkloadEndpointKey
	for _, k := range a {
		if k == toSkip {
			continue
		}
		filtered = append(filtered, k)
	}
	return filtered
}

func filterOutString(a []string, toSkip string) []string {
	var filtered []string
	for _, s := range a {
		if s == toSkip {
			continue
		}
		filtered = append(filtered, s)
	}
	return filtered
}
