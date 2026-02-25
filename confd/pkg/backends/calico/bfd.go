// Copyright (c) 2024 Tigera, Inc. All rights reserved.

package calico

import (
	"fmt"
	"sort"

	"github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// newBFDResolver returns a new BFDResolver configured with the given local node name and node label manager reference.
// A bfdResolver is responsible for tracking BFDConfiguration resources and when requested, using these cached resources
// to generate the correct "resolved" configuration for the local node.
func newBFDResolver(node string, nlm *nodeLabelManager) *bfdResolver {
	return &bfdResolver{
		node:             node,
		nodeLabelManager: nlm,
		configs:          map[string]*apiv3.BFDConfiguration{},
	}
}

type bfdResolver struct {
	node             string
	nodeLabelManager *nodeLabelManager
	configs          map[string]*apiv3.BFDConfiguration
}

// OnUpdate handles updates to BFDConfiguration and Node resources. It returns true if the update
// is relevant to the local node, and false otherwise.
func (r *bfdResolver) OnUpdate(u api.Update) bool {
	// Make sure this is a BFDConfiguration or Node update. If it's not, that
	// indicates a bug in the caller.
	v3Key, ok := u.Key.(model.ResourceKey)
	if !ok {
		logrus.WithField("key", u.Key).Error("BUG: Update is not a ResourceKey")
		return false
	}

	switch v3Key.Kind {
	case apiv3.KindBFDConfiguration:
		// Check if the existing config for this key is relevant for this node.
		oldRelevant := false
		newRelevant := false
		if oldConfig, ok := r.configs[u.Key.String()]; ok {
			oldRelevant = r.nodeLabelManager.selectorMatchesNode(r.node, oldConfig.Spec.NodeSelector)
		}
		if u.Value == nil {
			delete(r.configs, u.Key.String())
		} else {
			// The BFDConfiguration is being created or updated.
			r.configs[u.Key.String()] = u.Value.(*apiv3.BFDConfiguration)
			newRelevant = r.nodeLabelManager.selectorMatchesNode(r.node, u.Value.(*apiv3.BFDConfiguration).Spec.NodeSelector)
		}
		return oldRelevant || newRelevant
	case internalapi.KindNode:
		// The node label manager is already updated. Use this opportunity to check if our own
		// node has been modified, and if so, recompute.
		return v3Key.Name == r.node
	}

	logrus.WithField("key", v3Key.Kind).Error("BUG: Update has unexpected key kind")
	return false
}

// Resolve uses the current aggregate state of BFDConfiguration in the system to generate
// the correct config for this node. This should be called whenever BFDConfiguration changes, or
// when local node labels change.
func (r *bfdResolver) Resolve() (*apiv3.BFDConfiguration, error) {
	// Find the BFD configuration objects that select this node.
	var localConfigs []*apiv3.BFDConfiguration
	for _, config := range r.configs {
		// Check if the selector matches the local node.
		if r.nodeLabelManager.selectorMatchesNode(r.node, config.Spec.NodeSelector) {
			localConfigs = append(localConfigs, config)
		}
	}

	// For now, we only support a single BFDConfiguration per-node. If there are multiple,
	// log an error and return one of the configurations, arbitrarily but deterministically.
	if len(localConfigs) > 1 {
		names := []string{}
		for _, config := range localConfigs {
			names = append(names, config.Name)
		}
		sort.Strings(names)
		selectedConfig := names[0]
		logrus.WithFields(logrus.Fields{
			"node":            r.node,
			"matchingConfigs": names,
		}).Errorf("Multiple BFD configurations match this node, but at most one is supported. Implementing '%s'.", selectedConfig)
		for _, config := range localConfigs {
			if config.Name == selectedConfig {
				// Create a DeepCopy of the resolved configuration to avoid accidental mutation.
				logrus.WithField("config", config).Info("Selected BFD configuration")
				return config.DeepCopy(), nil
			}
		}
		return nil, fmt.Errorf("BUG: selected configuration not found")
	}

	// If there are no matching configurations, return nil.
	if len(localConfigs) == 0 {
		return nil, nil
	}

	// Create a DeepCopy of the resolved configuration to avoid accidental mutation.
	return localConfigs[0].DeepCopy(), nil
}
