// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package panoramasyncer

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	panclient "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/backend/client"
	watchersyncer "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/backend/watcher"
	panutils "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/utils"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

type FirewallPolicySyncOptions struct {
	// Panorama client.
	Client panutils.PanoramaClient
	// Panorama device Group.
	DeviceGroup string
	// Polling ticker.
	Ticker *jitter.Ticker
	// Filter selector parsed from Panorama input filter of tags.
	FilterSelector *selector.Selector
	// Syncer callbacks.
	Callbacks *calc.SyncerCallbacksDecoupler
}

// New creates a new Panorama syncer. This particular syncer requires Panorama datastore.
func New(syncOpts FirewallPolicySyncOptions) api.Syncer {
	log.Debug("New Panorama syncer")

	clients := map[string]panclient.PanoramaFirewallPolicyClient{
		panclient.PanoramaRuleClientId: &panclient.PanoramaRuleClient{
			DeviceGroup: syncOpts.DeviceGroup,
			Client:      syncOpts.Client,
			ClientType:  panclient.PanoramaRuleClientId,
			Selector:    syncOpts.FilterSelector,
		},
	}
	resourceTypes := []watchersyncer.ResourceType{
		{
			ClientID:     panclient.PanoramaRuleClientId,
			ResourceKind: panclient.PanoramaRuleKind,
		},
	}

	return watchersyncer.NewMultiClient(clients, resourceTypes, syncOpts.Callbacks, syncOpts.Ticker)
}
