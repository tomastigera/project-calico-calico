// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.
package cache

import (
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
)

type NodeCache interface {
	TotalNodes() int
	TotalNodesWithNoEndpoints() int
	TotalNodesWithNoWorkloadEndpoints() int
	TotalNodesWithNoHostEndpoints() int
	GetNodes() []api.Node
	GetNode(string) api.Node
	RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface)
}

func NewNodeCache() NodeCache {
	return &nodeCache{
		nodes:         make(map[string]*nodeData),
		hostEndpoints: make(map[model.Key]*nodeData),
	}
}

type nodeCache struct {
	nodes                         map[string]*nodeData
	numNodesWithEndpoints         int
	numNodesWithHostEndpoints     int
	numNodesWithWorkloadEndpoints int

	// The node that a host endpoint is on is not related to the hostendpoint name, thus we need
	// to separately track the mapping between the hostEndpoint key and the node name.
	hostEndpoints map[model.Key]*nodeData
}

func (c *nodeCache) GetNodes() []api.Node {
	nodes := make([]api.Node, 0, len(c.nodes))
	for _, nd := range c.nodes {
		nodes = append(nodes, nd)
	}
	return nodes
}

func (c *nodeCache) GetNode(name string) api.Node {
	if node := c.nodes[name]; node != nil {
		return node
	}
	return nil
}

func (c *nodeCache) TotalNodes() int {
	return len(c.nodes)
}

func (c *nodeCache) TotalNodesWithNoEndpoints() int {
	return len(c.nodes) - c.numNodesWithEndpoints
}

func (c *nodeCache) TotalNodesWithNoWorkloadEndpoints() int {
	return len(c.nodes) - c.numNodesWithWorkloadEndpoints
}

func (c *nodeCache) TotalNodesWithNoHostEndpoints() int {
	return len(c.nodes) - c.numNodesWithHostEndpoints
}

func (c *nodeCache) RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface) {
	dispatcher.RegisterHandler(internalapi.KindWorkloadEndpoint, c.onUpdate)
	dispatcher.RegisterHandler(apiv3.KindHostEndpoint, c.onUpdate)
	dispatcher.RegisterHandler(internalapi.KindNode, c.onUpdate)
}

func (c *nodeCache) onUpdate(update dispatcherv1v3.Update) {
	var nd *nodeData
	uv3 := update.UpdateV3
	rk := uv3.Key.(model.ResourceKey)
	switch uv3.UpdateType {
	case bapi.UpdateTypeKVNew:
		switch rk.Kind {
		case internalapi.KindNode:
			nd = c.getOrCreateNodeData(rk.Name)
			nd.resource = uv3.Value.(api.Resource)
		case internalapi.KindWorkloadEndpoint:
			nd = c.getOrCreateNodeData(c.getNodeFromWEPName(rk.Name))
			c.updateEndpointsCounts(nd, 1, 0)
		case apiv3.KindHostEndpoint:
			hep := uv3.Value.(*apiv3.HostEndpoint)
			v, ok := hep.Labels[names.HostEndpointTypeLabelKey]
			// Exclude non-cluster host endpoints from the node cache.
			if !ok || v != string(names.HostEndpointTypeNonClusterHost) {
				nd = c.getOrCreateNodeData(hep.Spec.Node)
				c.updateEndpointsCounts(nd, 0, 1)
				c.hostEndpoints[rk] = nd
			}
		}
	case bapi.UpdateTypeKVUpdated:
		switch rk.Kind {
		case internalapi.KindNode:
			nd = c.nodes[rk.Name]
			nd.resource = uv3.Value.(api.Resource)
		case apiv3.KindHostEndpoint:
			// The node of a HostEndpoint is adjustable, so to keep things simple add the
			// endpoint from the old node and add it to the new one (it's possible the node
			// hasn't changed, but this requires one less check).
			hep := uv3.Value.(*apiv3.HostEndpoint)
			v, ok := hep.Labels[names.HostEndpointTypeLabelKey]
			// Exclude non-cluster host endpoints from the node cache.
			if !ok || v != string(names.HostEndpointTypeNonClusterHost) {
				ndOld := c.hostEndpoints[rk]
				ndNew := c.getOrCreateNodeData(hep.Spec.Node)
				if ndOld != ndNew {
					c.updateEndpointsCounts(ndOld, 0, -1)
					c.updateEndpointsCounts(ndNew, 0, 1)
					c.hostEndpoints[rk] = ndNew
					c.maybeDelete(ndOld)
				}
			}
		}
	case bapi.UpdateTypeKVDeleted:
		switch rk.Kind {
		case internalapi.KindNode:
			nd = c.nodes[rk.Name]
			nd.resource = nil
		case internalapi.KindWorkloadEndpoint:
			nd = c.nodes[c.getNodeFromWEPName(rk.Name)]
			c.updateEndpointsCounts(nd, -1, 0)
		case apiv3.KindHostEndpoint:
			nd = c.hostEndpoints[rk]
			c.updateEndpointsCounts(nd, 0, -1)
			delete(c.hostEndpoints, rk)
		}
		c.maybeDelete(nd)
	}
}

func (c *nodeCache) getNodeFromWEPName(name string) string {
	w, err := names.ParseWorkloadEndpointName(name)
	if err != nil {
		return ""
	}
	return w.Node
}

func (c *nodeCache) getOrCreateNodeData(name string) *nodeData {
	nd, ok := c.nodes[name]
	if !ok {
		nd = &nodeData{name: name}
		c.nodes[name] = nd
	}
	return nd
}

func (c *nodeCache) maybeDelete(nd *nodeData) {
	if nd != nil && nd.canDelete() {
		delete(c.nodes, nd.name)
	}
}

func (c *nodeCache) updateEndpointsCounts(nd *nodeData, deltaWep, deltaHep int) {
	if nd != nil {
		beforeWep := nd.endpoints.NumWorkloadEndpoints
		beforeHep := nd.endpoints.NumHostEndpoints
		nd.endpoints.NumWorkloadEndpoints += deltaWep
		nd.endpoints.NumHostEndpoints += deltaHep
		afterWep := nd.endpoints.NumWorkloadEndpoints
		afterHep := nd.endpoints.NumHostEndpoints

		if beforeWep+beforeHep == 0 {
			c.numNodesWithEndpoints++
		} else if afterWep+afterHep == 0 {
			c.numNodesWithEndpoints--
		}
		if beforeWep == 0 && afterWep > 0 {
			c.numNodesWithWorkloadEndpoints++
		} else if beforeWep > 0 && afterWep == 0 {
			c.numNodesWithWorkloadEndpoints--
		}
		if beforeHep == 0 && afterHep > 0 {
			c.numNodesWithHostEndpoints++
		} else if beforeHep > 0 && afterHep == 0 {
			c.numNodesWithHostEndpoints--
		}
	}
}

type nodeData struct {
	name      string
	resource  api.Resource
	endpoints api.EndpointCounts
}

func (nd *nodeData) canDelete() bool {
	return nd.resource == nil && nd.endpoints.NumWorkloadEndpoints == 0 && nd.endpoints.NumHostEndpoints == 0
}

func (nd *nodeData) GetResource() api.Resource {
	return nd.resource
}

func (nd *nodeData) GetName() string {
	return nd.name
}

func (nd *nodeData) GetEndpointCounts() api.EndpointCounts {
	return nd.endpoints
}
