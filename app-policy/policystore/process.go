// Copyright (c) 2023-2025 Tigera, Inc. All rights reserved.
package policystore

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ProcessUpdate -  Update the PolicyStore with the information passed over the Sync API.
func (store *PolicyStore) ProcessUpdate(subscriptionType string, update *proto.ToDataplane, storeStaged bool) {
	// TODO: maybe coalesce-ing updater fits here
	switch payload := update.Payload.(type) {
	case *proto.ToDataplane_InSync:
		store.processInSync(payload.InSync)
	case *proto.ToDataplane_IpsetUpdate:
		store.processIPSetUpdate(payload.IpsetUpdate)
	case *proto.ToDataplane_IpsetDeltaUpdate:
		store.processIPSetDeltaUpdate(payload.IpsetDeltaUpdate)
	case *proto.ToDataplane_IpsetRemove:
		store.processIPSetRemove(payload.IpsetRemove)
	case *proto.ToDataplane_ActiveProfileUpdate:
		store.processActiveProfileUpdate(payload.ActiveProfileUpdate)
	case *proto.ToDataplane_ActiveProfileRemove:
		store.processActiveProfileRemove(payload.ActiveProfileRemove)
	case *proto.ToDataplane_ActivePolicyUpdate:
		if !storeStaged && model.KindIsStaged(payload.ActivePolicyUpdate.Id.Name) {
			log.WithFields(log.Fields{
				"id": payload.ActivePolicyUpdate.Id,
			}).Debug("Skipping StagedPolicy ActivePolicyUpdate")

			return
		}

		store.processActivePolicyUpdate(payload.ActivePolicyUpdate)
	case *proto.ToDataplane_ActivePolicyRemove:
		if !storeStaged && model.KindIsStaged(payload.ActivePolicyRemove.Id.Name) {
			log.WithFields(log.Fields{
				"id": payload.ActivePolicyRemove.Id,
			}).Debug("Skipping StagedPolicy ActivePolicyRemove")

			return
		}

		store.processActivePolicyRemove(payload.ActivePolicyRemove)
	case *proto.ToDataplane_WorkloadEndpointUpdate:
		store.processWorkloadEndpointUpdate(subscriptionType, payload.WorkloadEndpointUpdate)
	case *proto.ToDataplane_WorkloadEndpointRemove:
		store.processWorkloadEndpointRemove(subscriptionType, payload.WorkloadEndpointRemove)
	case *proto.ToDataplane_ServiceAccountUpdate:
		store.processServiceAccountUpdate(payload.ServiceAccountUpdate)
	case *proto.ToDataplane_ServiceAccountRemove:
		store.processServiceAccountRemove(payload.ServiceAccountRemove)
	case *proto.ToDataplane_NamespaceUpdate:
		store.processNamespaceUpdate(payload.NamespaceUpdate)
	case *proto.ToDataplane_NamespaceRemove:
		store.processNamespaceRemove(payload.NamespaceRemove)
	case *proto.ToDataplane_ConfigUpdate:
		store.processConfigUpdate(payload.ConfigUpdate)
	default:
		log.Debugf("unknown payload %v", update.String())
	}
}

func (store *PolicyStore) processInSync(inSync *proto.InSync) {
	log.Debug("Processing InSync")
}

func (store *PolicyStore) processConfigUpdate(update *proto.ConfigUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"config": update.Config,
		}).Debug("Processing ConfigUpdate")
	}

	// Update the DropActionOverride setting if it is available.
	if val, ok := update.Config["DropActionOverride"]; ok {
		log.Debug("DropActionOverride is present in config")
		var psVal DropActionOverride
		switch strings.ToLower(val) {
		case "drop":
			psVal = DROP
		case "accept":
			psVal = ACCEPT
		case "loganddrop":
			psVal = LOG_AND_DROP
		case "logandaccept":
			psVal = LOG_AND_ACCEPT
		default:
			log.Errorf("Unknown DropActionOverride value: %s", val)
			psVal = DROP
		}
		store.DropActionOverride = psVal
	}

	// Extract the flow logs settings, defaulting to false if not present.
	store.DataplaneStatsEnabledForAllowed = getBoolFromConfig(update.Config, "DataplaneStatsEnabledForAllowed", false)
	store.DataplaneStatsEnabledForDenied = getBoolFromConfig(update.Config, "DataplaneStatsEnabledForDenied", false)
}

func (store *PolicyStore) processIPSetUpdate(update *proto.IPSetUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id":      update.Id,
			"type":    update.Type.String(),
			"members": update.Members,
		}).Debug("Processing IPSetUpdate")
	}

	// IPSetUpdate replaces the existing set.
	if s := NewIPSet(update.Type); s != nil {
		for _, addr := range update.Members {
			s.AddString(addr)
		}
		store.IPSetByID[update.Id] = s
	}
}

func (store *PolicyStore) processIPSetDeltaUpdate(update *proto.IPSetDeltaUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id":      update.Id,
			"added":   update.AddedMembers,
			"removed": update.RemovedMembers,
		}).Debug("Processing IPSetDeltaUpdate")
	}
	s, ok := store.IPSetByID[update.Id]
	if !ok {
		log.Errorf("Unknown IPSet id: %v, skipping update", update.Id)
		return // we shouldn't be getting a delta update before we've seen the IPSet
	}

	for _, addr := range update.AddedMembers {
		s.AddString(addr)
	}
	for _, addr := range update.RemovedMembers {
		s.RemoveString(addr)
	}
}

func (store *PolicyStore) processIPSetRemove(update *proto.IPSetRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing IPSetRemove")
	}
	delete(store.IPSetByID, update.Id)
}

func (store *PolicyStore) processActiveProfileUpdate(update *proto.ActiveProfileUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing ActiveProfileUpdate")
	}
	if update.Id == nil {
		log.Error("got ActiveProfileUpdate with nil ProfileID")
		return
	}
	id := types.ProtoToProfileID(update.GetId())
	store.ProfileByID[id] = update.Profile
}

func (store *PolicyStore) processActiveProfileRemove(update *proto.ActiveProfileRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing ActiveProfileRemove")
	}
	if update.Id == nil {
		log.Error("got ActiveProfileRemove with nil ProfileID")
		return
	}
	id := types.ProtoToProfileID(update.GetId())
	delete(store.ProfileByID, id)
}

func (store *PolicyStore) processActivePolicyUpdate(update *proto.ActivePolicyUpdate) {
	log.WithFields(log.Fields{
		"id":             update.Id,
		"inbound_rules":  update.Policy.InboundRules,
		"outbound_rules": update.Policy.OutboundRules,
	}).Debug("Processing ActivePolicyUpdate")

	if update.Id == nil {
		log.Error("got ActivePolicyUpdate with nil PolicyID")
		return
	}
	id := types.ProtoToPolicyID(update.GetId())

	store.mergePolicyHTTPHeaders(update.Policy)
	store.PolicyByID[id] = update.Policy
}

// mergePolicyHTTPHeaders consolidates duplicate HTTP header rules within a policy
func (store *PolicyStore) mergePolicyHTTPHeaders(policy *proto.Policy) {
	if policy == nil {
		return
	}

	store.mergeHTTPHeadersInRules(policy.InboundRules)
	store.mergeHTTPHeadersInRules(policy.OutboundRules)
}

// mergeHTTPHeadersInRules consolidates duplicate HTTP headers within rules
func (store *PolicyStore) mergeHTTPHeadersInRules(rules []*proto.Rule) {
	for _, rule := range rules {
		store.mergeHTTPHeadersInRule(rule)
	}
}

// mergeHTTPHeadersInRule consolidates duplicate HTTP headers within a single rule
func (store *PolicyStore) mergeHTTPHeadersInRule(rule *proto.Rule) {
	if rule == nil || rule.HttpMatch == nil || len(rule.HttpMatch.Headers) <= 1 {
		headerCount := 0
		if rule != nil && rule.HttpMatch != nil {
			headerCount = len(rule.HttpMatch.Headers)
		}
		log.Debugf("Skipping merge - rule nil: %v, HttpMatch nil: %v, headers count: %d",
			rule == nil,
			rule != nil && rule.HttpMatch == nil,
			headerCount)
		return
	}

	log.Debugf("Starting header merge for rule with %d headers", len(rule.HttpMatch.Headers))

	// Group headers by name and operator
	headerMap := make(map[string]map[string][]string) // header -> operator -> values

	for _, header := range rule.HttpMatch.Headers {
		log.Infof("Processing header: %s %s %v", header.Header, header.Operator, header.Values)
		if headerMap[header.Header] == nil {
			headerMap[header.Header] = make(map[string][]string)
		}
		headerMap[header.Header][header.Operator] = append(
			headerMap[header.Header][header.Operator],
			header.Values...,
		)
	}

	log.Debugf("Header map after grouping: %+v", headerMap)

	// Replace headers with consolidated ones
	rule.HttpMatch.Headers = nil
	for headerName, operators := range headerMap {
		for operator, headerValues := range operators {
			uniqueHeaders := store.removeDuplicateStrings(headerValues)

			log.Debugf("Adding merged header: %s %s %v", headerName, operator, uniqueHeaders)
			rule.HttpMatch.Headers = append(rule.HttpMatch.Headers, &proto.HTTPMatch_HeadersMatch{
				Header:   headerName,
				Operator: operator,
				Values:   uniqueHeaders,
			})
		}
	}

	log.Debugf("Finished merge - rule now has %d headers", len(rule.HttpMatch.Headers))
}

// removeDuplicateStrings removes duplicate strings from a slice
func (store *PolicyStore) removeDuplicateStrings(values []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}

	return result
}

func (store *PolicyStore) processActivePolicyRemove(update *proto.ActivePolicyRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"id": update.Id,
		}).Debug("Processing ActivePolicyRemove")
	}
	if update.Id == nil {
		log.Error("got ActivePolicyRemove with nil PolicyID")
		return
	}
	id := types.ProtoToPolicyID(update.GetId())
	delete(store.PolicyByID, id)
}

func (store *PolicyStore) processWorkloadEndpointUpdate(subscriptionType string, update *proto.WorkloadEndpointUpdate) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"orchestratorID": update.GetId().GetOrchestratorId(),
			"workloadID":     update.GetId().GetWorkloadId(),
			"endpointID":     update.GetId().GetEndpointId(),
		}).Debug("Processing WorkloadEndpointUpdate")
	}
	switch subscriptionType {
	case "per-pod-policies", "":
		store.Endpoint = update.Endpoint
	case "per-host-policies":
		id := types.ProtoToWorkloadEndpointID(update.GetId())
		store.Endpoints[id] = update.Endpoint
		log.Debugf("%d endpoints received so far", len(store.Endpoints))
		store.wepUpdates.onWorkloadEndpointUpdate(update, store.IPToIndexes)
	}
}

func (store *PolicyStore) processWorkloadEndpointRemove(subscriptionType string, update *proto.WorkloadEndpointRemove) {
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"orchestratorID": update.GetId().GetOrchestratorId(),
			"workloadID":     update.GetId().GetWorkloadId(),
			"endpointID":     update.GetId().GetEndpointId(),
		}).Debug("Processing WorkloadEndpointRemove")
	}

	switch subscriptionType {
	case "per-pod-policies", "":
		store.Endpoint = nil
	case "per-host-policies":
		delete(store.Endpoints, types.ProtoToWorkloadEndpointID(update.Id))
		store.wepUpdates.onWorkloadEndpointRemove(update, store.IPToIndexes)
	}
}

func (store *PolicyStore) processServiceAccountUpdate(update *proto.ServiceAccountUpdate) {
	log.WithField("id", update.Id).Debug("Processing ServiceAccountUpdate")
	if update.Id == nil {
		log.Error("got ServiceAccountUpdate with nil ServiceAccountID")
		return
	}
	id := types.ProtoToServiceAccountID(update.GetId())
	store.ServiceAccountByID[id] = update
}

func (store *PolicyStore) processServiceAccountRemove(update *proto.ServiceAccountRemove) {
	log.WithField("id", update.Id).Debug("Processing ServiceAccountRemove")
	if update.Id == nil {
		log.Error("got ServiceAccountRemove with nil ServiceAccountID")
		return
	}
	id := types.ProtoToServiceAccountID(update.GetId())
	delete(store.ServiceAccountByID, id)
}

func (store *PolicyStore) processNamespaceUpdate(update *proto.NamespaceUpdate) {
	log.WithField("id", update.Id).Debug("Processing NamespaceUpdate")
	if update.Id == nil {
		log.Error("got NamespaceUpdate with nil NamespaceID")
		return
	}
	id := types.ProtoToNamespaceID(update.GetId())
	store.NamespaceByID[id] = update
}

func (store *PolicyStore) processNamespaceRemove(update *proto.NamespaceRemove) {
	log.WithField("id", update.Id).Debug("Processing NamespaceRemove")
	if update.Id == nil {
		log.Error("got NamespaceRemove with nil NamespaceID")
		return
	}
	id := types.ProtoToNamespaceID(update.GetId())
	delete(store.NamespaceByID, id)
}
