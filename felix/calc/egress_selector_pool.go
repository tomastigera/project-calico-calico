// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package calc

import (
	"reflect"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// EgressSelectorPool tracks and reference counts the egress selectors that are used by profiles,
// endpoints and egress gateway policies anywhere in the cluster. We need this to identify active
// local endpoints that match egress selectors, and hence should be privileged in the ways
// that are needed for endpoints acting as egress gateways.
type EgressSelectorPool struct {
	// "EnabledPerNamespaceOrPerPod" or "EnabledPerNamespace".
	supportLevel string

	// Known egress selectors and their ref counts.
	endpointSelectors map[model.WorkloadEndpointKey]string
	profileSelectors  map[model.ResourceKey]string
	policySelectors   map[model.ResourceKey][]string

	selectorRefCount map[string]int

	// Callbacks.
	OnEgressSelectorActive   func(selector string)
	OnEgressSelectorInactive func(selector string)
}

func NewEgressSelectorPool(supportLevel string) *EgressSelectorPool {
	esp := &EgressSelectorPool{
		supportLevel:      supportLevel,
		endpointSelectors: map[model.WorkloadEndpointKey]string{},
		profileSelectors:  map[model.ResourceKey]string{},
		policySelectors:   map[model.ResourceKey][]string{},
		selectorRefCount:  map[string]int{},
	}
	return esp
}

func (esp *EgressSelectorPool) RegisterWith(allUpdDispatcher *dispatcher.Dispatcher) {
	// Subject to support level, it needs all workload endpoints and v3 profiles.
	if esp.supportLevel == "EnabledPerNamespaceOrPerPod" {
		allUpdDispatcher.Register(model.WorkloadEndpointKey{}, esp.OnUpdate)
	}
	allUpdDispatcher.Register(model.ResourceKey{}, esp.OnUpdate)
}

func (esp *EgressSelectorPool) OnUpdate(update api.Update) (_ bool) {
	switch key := update.Key.(type) {
	case model.WorkloadEndpointKey:
		if update.Value != nil {
			log.Debugf("Updating ESP with endpoint %v", key)
			endpoint := update.Value.(*model.WorkloadEndpoint)
			esp.updateEndpoint(key, endpoint.EgressSelector)
		} else {
			log.Debugf("Deleting endpoint %v from ESP", key)
			esp.updateEndpoint(key, "")
		}
	case model.ResourceKey:
		switch key.Kind {
		case v3.KindProfile:
			if update.Value != nil {
				log.Debugf("Updating ESP with profile %v", key)
				profile := update.Value.(*v3.Profile)
				esp.updateProfile(key, profile.Spec.EgressGateway)
			} else {
				log.Debugf("Deleting profile %v from ESP", key)
				esp.updateProfile(key, nil)
			}
		case v3.KindEgressGatewayPolicy:
			if update.Value != nil {
				log.Debugf("Updating ESP with egress policy %v", key)
				egressPolicy := update.Value.(*v3.EgressGatewayPolicy)
				esp.updateEgressPolicy(key, egressPolicy.Spec.Rules)
			} else {
				log.Debugf("Deleting egress policy %v from ESP", key)
				esp.updateEgressPolicy(key, nil)
			}
		default:
			// Ignore other kinds of v3 resource.
		}
	default:
		log.Infof("Ignoring unexpected update: %v %#v",
			reflect.TypeOf(update.Key), update)
	}

	return
}

func (esp *EgressSelectorPool) updateEndpoint(key model.WorkloadEndpointKey, newSelector string) {
	oldSelector := esp.endpointSelectors[key]
	if newSelector == oldSelector {
		// No change.
		return
	}
	if newSelector != "" {
		esp.endpointSelectors[key] = newSelector
	} else {
		delete(esp.endpointSelectors, key)
	}
	esp.decRefSelector(oldSelector)
	esp.incRefSelector(newSelector)
}

func (esp *EgressSelectorPool) updateProfile(key model.ResourceKey, egress *v3.EgressGatewaySpec) {
	// Find the existing selector for this profile.
	oldSelector := esp.profileSelectors[key]

	// Calculate the new selector
	newSelector := ""
	if egress != nil && egress.Gateway != nil {
		newSelector = PreprocessEgressSelector(egress.Gateway, key.Name)
	}

	if newSelector == oldSelector {
		// No change.
		return
	}
	if newSelector != "" {
		esp.profileSelectors[key] = newSelector
	} else {
		delete(esp.profileSelectors, key)
	}
	esp.decRefSelector(oldSelector)
	esp.incRefSelector(newSelector)
}

func (esp *EgressSelectorPool) updateEgressPolicy(key model.ResourceKey, rules []v3.EgressGatewayRule) {
	// Find the existing selector for this profile.
	oldSelectors := esp.policySelectors[key]
	newSelectors := transformEGWRulesToSelectors(rules)

	if equalsSelectors(oldSelectors, newSelectors) {
		return
	}

	if len(newSelectors) > 0 {
		esp.policySelectors[key] = newSelectors
	} else {
		delete(esp.policySelectors, key)
	}

	for _, s := range newSelectors {
		esp.incRefSelector(s)
	}
	for _, s := range oldSelectors {
		esp.decRefSelector(s)
	}
}

func transformEGWRulesToSelectors(rules []v3.EgressGatewayRule) []string {
	var newSelectors []string
	for _, r := range rules {
		newSelector := ""
		if r.Gateway != nil {
			newSelector = PreprocessEgressSelector(r.Gateway, "")
		}
		newSelectors = append(newSelectors, newSelector)
	}
	return newSelectors
}

func equalsSelectors(s1, s2 []string) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i, s := range s1 {
		if s != s2[i] {
			return false
		}
	}
	return true
}

func (esp *EgressSelectorPool) incRefSelector(selector string) {
	if selector == "" {
		return
	}
	esp.selectorRefCount[selector]++
	if esp.selectorRefCount[selector] == 1 {
		esp.OnEgressSelectorActive(selector)
	}
}

func (esp *EgressSelectorPool) decRefSelector(selector string) {
	if selector == "" {
		return
	}
	esp.selectorRefCount[selector]--
	if esp.selectorRefCount[selector] == 0 {
		esp.OnEgressSelectorInactive(selector)
		delete(esp.selectorRefCount, selector)
	}
}

func (esp *EgressSelectorPool) HasSelector(selector string) bool {
	_, ok := esp.selectorRefCount[selector]
	return ok
}
