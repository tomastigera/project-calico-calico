// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package intdataplane

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
)

func newIPSecManager(ipSecDataplane ipSecDataplane) *ipsecManager {
	return &ipsecManager{
		dataplane: ipSecDataplane,
	}
}

type ipSecDataplane interface {
	AddBinding(tunnelAddress, workloadAddress string)
	RemoveBinding(tunnelAddress, workloadAddress string)
	AddBlacklist(workloadAddress string)
	RemoveBlacklist(workloadAddress string)
	AddTunnel(remoteAddr string)
	RemoveTunnel(remoteAddr string)
}

type ipsecManager struct {
	dataplane ipSecDataplane
}

func (d *ipsecManager) OnUpdate(msg any) {
	switch msg := msg.(type) {
	case *proto.IPSecTunnelAdd:
		log.WithFields(log.Fields{
			"remoteAddr": msg.TunnelAddr,
		}).Debug("Adding IPsec tunnel")
		d.dataplane.AddTunnel(msg.TunnelAddr)
	case *proto.IPSecTunnelRemove:
		log.WithFields(log.Fields{
			"remoteAddr": msg.TunnelAddr,
		}).Debug("Removing IPsec tunnel")
		d.dataplane.RemoveTunnel(msg.TunnelAddr)
	case *proto.IPSecBindingUpdate:
		log.WithFields(log.Fields{
			"tunnelAddr": msg.TunnelAddr,
			"numAdded":   len(msg.AddedAddrs),
			"numRemoved": len(msg.RemovedAddrs),
		}).Debug("IPSec bindings updated")
		for _, removed := range msg.RemovedAddrs {
			d.dataplane.RemoveBinding(msg.TunnelAddr, removed)
		}
		for _, added := range msg.AddedAddrs {
			d.dataplane.AddBinding(msg.TunnelAddr, added)
		}
	case *proto.IPSecBlacklistAdd:
		log.WithFields(log.Fields{
			"numAdded": len(msg.AddedAddrs),
		}).Debug("IPSec blacklist entries added")
		for _, added := range msg.AddedAddrs {
			d.dataplane.AddBlacklist(added)
		}
	case *proto.IPSecBlacklistRemove:
		log.WithFields(log.Fields{
			"numRemoved": len(msg.RemovedAddrs),
		}).Debug("IPSec blacklist entries removed")
		for _, added := range msg.RemovedAddrs {
			d.dataplane.RemoveBlacklist(added)
		}
	}
}

func (d *ipsecManager) CompleteDeferredWork() error {
	return nil
}
