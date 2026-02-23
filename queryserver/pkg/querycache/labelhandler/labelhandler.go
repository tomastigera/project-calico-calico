// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
package labelhandler

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/utils"
)

type Interface interface {
	QueryEndpoints(selector string) ([]model.Key, error)
	QueryPolicies(labels map[string]string, profiles []string) []model.Key
	QueryRuleSelectors(labels map[string]string, profiles []string) []string
	RegisterPolicyHandler(pcb PolicyMatchFn)
	RegisterRuleHandler(rcb RuleMatchFn) RuleRegistrationInterface
	RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface)
}

// A rule handler is able to request which rule selectors it wants to monitor.
type RuleRegistrationInterface interface {
	AddRuleSelector(selector string) error
	RemoveRuleSelector(selector string)
}

type MatchType string

const (
	MatchStarted MatchType = "started"
	MatchStopped MatchType = "stopped"
)

type (
	PolicyMatchFn func(matchType MatchType, policy model.Key, endpoint model.Key)
	RuleMatchFn   func(matchType MatchType, selector string, endpoint model.Key)
)

func NewLabelHandler() Interface {
	cq := &labelHandler{}
	cq.index = labelindex.NewInheritIndex(cq.onMatchStarted, cq.onMatchStopped)
	return cq
}

type labelHandler struct {
	// InheritIndex helper.  This is used to track correlations between endpoints and
	// registered selectors.
	index *labelindex.InheritIndex

	// Callbacks.
	policyCallbacks []PolicyMatchFn
	ruleCallbacks   []RuleMatchFn

	// The accumulated matches added during a query.  If there is no query in progress
	// these are nil.
	results []model.Key

	// The accumulated rule selector ID matches added during a query on rule selectors.
	// If there is no rule selector query in progress, these are nil.
	ruleSelectorResults []string
}

// A policyQueryId is used to identify either a selector or endpoint that have been injected in to
// the InheritIndex helper when running a query. Match policyCallbacks with these identifiers can be
// ignored for our cache, but will be included in the query responses.
type policyQueryId uuid.UUID

// A ruleQueryId is used to identify a rule selector that is injected in to the InheritIndex
// helper when running a query. It is used exclusively for querying matches on the rule selectors
// on a policy, and returns a set of matching rule selector IDs that can then be cross referenced using
// the policy cache to locate the set of matching policy rules (since rule selectors are aggregated).
type ruleQueryId uuid.UUID

// The rule selector ID is simply the selector string.  To minimize occupancy and processing we consolidate
// common selectors across the rules and just track and send notifications once.
type ruleSelectorId string

func (c *labelHandler) RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface) {
	dispatcher.RegisterHandler(v3.KindProfile, c.onUpdate)
	dispatcher.RegisterHandler(internalapi.KindWorkloadEndpoint, c.onUpdate)
	dispatcher.RegisterHandler(v3.KindHostEndpoint, c.onUpdate)
	dispatcher.RegisterHandler(v3.KindNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(v3.KindGlobalNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(v3.KindStagedNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(v3.KindStagedGlobalNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(v3.KindStagedKubernetesNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(model.KindKubernetesNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(model.KindKubernetesAdminNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(model.KindKubernetesBaselineAdminNetworkPolicy, c.onUpdate)
}

func (c *labelHandler) RegisterPolicyHandler(pcb PolicyMatchFn) {
	c.policyCallbacks = append(c.policyCallbacks, pcb)
}

func (c *labelHandler) RegisterRuleHandler(rcb RuleMatchFn) RuleRegistrationInterface {
	c.ruleCallbacks = append(c.ruleCallbacks, rcb)
	return c
}

// QueryEndpoints returns a list of endpoint keys that match the supplied
// selector.
func (c *labelHandler) QueryEndpoints(selectorExpression string) ([]model.Key, error) {
	// Parse the selector expression.
	parsedSel, err := selector.Parse(selectorExpression)
	if err != nil {
		return nil, err
	}

	// Start by adding the query selector to the required list of selectors.
	selectorId := policyQueryId(uuid.New())
	c.registerSelector(selectorId, parsedSel)

	// The register selector call will result in synchronous matchStarted policyCallbacks to update our
	// endpoint matches. Thus our endpoints slice should now have the results we need.  All of
	// the updates will be for this specific selector since we only run a single query at a time.
	results := c.results
	c.results = nil

	// Remove the query selector so that we are no longer tracking it.
	c.unregisterSelector(selectorId)
	return results, nil
}

// QuerySelectors returns a list of SelectorIDs that match the supplied
// selector.
func (c *labelHandler) QueryPolicies(labels map[string]string, profiles []string) []model.Key {
	// Add a fake endpoint with the requested labels and profiles.
	endpointId := policyQueryId(uuid.New())
	c.index.UpdateLabels(endpointId, uniquelabels.Make(labels), profiles)

	// The addition of the endpoint will result in synchronous policyCallbacks to update our matches.  Thus
	// our match map should now have the results we need.  All of the updates will be for this specific
	// endpoint.
	results := c.results
	c.results = nil

	// Remove the fake endpoint so that we are no longer tracking it.
	c.index.DeleteLabels(endpointId)
	return results
}

func (c *labelHandler) QueryRuleSelectors(labels map[string]string, profiles []string) []string {
	// Add a fake endpoint with the requested labels and profiles.
	endpointId := ruleQueryId(uuid.New())
	c.index.UpdateLabels(endpointId, uniquelabels.Make(labels), profiles)

	// The addition of the endpoint will result in synchronous policyCallbacks to update our matches.  Thus
	// our match map should now have the results we need.  All of the updates will be for this specific
	// endpoint.
	results := c.ruleSelectorResults
	c.ruleSelectorResults = nil

	// Remove the fake endpoint so that we are no longer tracking it.
	c.index.DeleteLabels(endpointId)
	return results
}

// AddRuleSelector adds a rule selector, matches will be announced through the RuleMatchFn callbacks.
// Rule selectors are handled externally. To minimize occupancy and processing, rule selectors
// should be consolidated so that identical selectors aren't processed separately.
func (c *labelHandler) AddRuleSelector(s string) error {
	parsed, err := selector.Parse(s)
	if err != nil {
		return err
	}
	c.registerSelector(ruleSelectorId(s), parsed)
	return nil
}

// RemoveRuleSelector removes a rule selector
func (c *labelHandler) RemoveRuleSelector(s string) {
	c.unregisterSelector(ruleSelectorId(s))
}

// OnUpdate handler
func (c *labelHandler) onUpdate(update dispatcherv1v3.Update) {
	uv3 := update.UpdateV3
	rk, ok := uv3.Key.(model.ResourceKey)
	if !ok {
		log.WithField("key", uv3.Key).Error("Unexpected resource in event type")
	}
	switch rk.Kind {
	case v3.KindProfile:
		c.onUpdateProfile(update)
	case model.KindKubernetesAdminNetworkPolicy,
		model.KindKubernetesBaselineAdminNetworkPolicy,
		model.KindKubernetesNetworkPolicy:
		c.onUpdatePolicy(update)
	case v3.KindGlobalNetworkPolicy:
		c.onUpdatePolicy(update)
	case v3.KindNetworkPolicy:
		c.onUpdatePolicy(update)
	case v3.KindStagedGlobalNetworkPolicy:
		c.onUpdateStagedPolicy(update)
	case v3.KindStagedNetworkPolicy:
		c.onUpdateStagedPolicy(update)
	case v3.KindStagedKubernetesNetworkPolicy:
		c.onUpdateStagedPolicy(update)
	case internalapi.KindWorkloadEndpoint:
		c.onUpdateWorkloadEndpoint(update)
	case v3.KindHostEndpoint:
		c.onUpdateHostEndpoint(update)
	default:
		log.WithField("key", uv3.Key).Error("Unexpected resource in event type")
	}
}

// onUpdateWorkloadEndpoints is called when the syncer has an update for a WorkloadEndpoint.
// This updates the InheritIndex helper and tracks global counts.
func (c *labelHandler) onUpdateWorkloadEndpoint(update dispatcherv1v3.Update) {
	uv1 := update.UpdateV1
	uv3 := update.UpdateV3
	key := uv3.Key.(model.ResourceKey)
	if uv3.UpdateType == api.UpdateTypeKVDeleted {
		c.index.DeleteLabels(key)
		return
	}
	if uv1.Value == nil {
		// The v1 resource value is nil even though the v3 update is not a delete. The update processor
		// must be filtering this out, so treat as a delete.
		c.index.DeleteLabels(key)
		return
	}
	value := uv1.Value.(*model.WorkloadEndpoint)
	c.index.UpdateLabels(uv3.Key, value.Labels, value.ProfileIDs)
}

// onUpdateHostEndpoints is called when the syncer has an update for a HostEndpoint.
// This updates the InheritIndex helper and tracks global counts.
func (c *labelHandler) onUpdateHostEndpoint(update dispatcherv1v3.Update) {
	uv3 := update.UpdateV3
	key := uv3.Key.(model.ResourceKey)
	if uv3.UpdateType == api.UpdateTypeKVDeleted {
		c.index.DeleteLabels(key)
		return
	}
	value := uv3.Value.(*v3.HostEndpoint)
	c.index.UpdateLabels(uv3.Key, uniquelabels.Make(value.GetObjectMeta().GetLabels()), value.Spec.Profiles)
}

// onUpdateProfile is called when the syncer has an update for a Profile.
// This updates the InheritIndex helper tQ1o in turn update any endpoint labels that are
// inherited from the profile.
func (c *labelHandler) onUpdateProfile(update dispatcherv1v3.Update) {
	uv3 := update.UpdateV3
	key := uv3.Key.(model.ResourceKey)
	if uv3.UpdateType == api.UpdateTypeKVDeleted {
		c.index.DeleteParentLabels(key.Name)
		return
	}

	value := uv3.Value.(*v3.Profile)
	c.index.UpdateParentLabels(key.Name, value.Spec.LabelsToApply)
}

func (c *labelHandler) onUpdateStagedPolicy(update dispatcherv1v3.Update) {
	uv3 := update.UpdateV3

	if utils.DoExcludeStagedPolicy(uv3) {
		sprs := uv3.Key.(model.ResourceKey)
		log.WithField("key", sprs).Error("Filtering staged policies out")
		return
	}

	c.onUpdatePolicy(update)
}

// onUpdatePolicy is called when the syncer has an update for a Policy.
// This is used to register/unregister match updates from the InheritIndex helper for the
// policy selector so that we can track total endpoint counts for each policy.
func (c *labelHandler) onUpdatePolicy(update dispatcherv1v3.Update) {
	uv3 := update.UpdateV3
	uv1 := update.UpdateV1

	key := uv3.Key.(model.ResourceKey)
	if uv3.UpdateType == api.UpdateTypeKVDeleted {
		c.onDeletePolicy(key)
		return
	}

	// Create the selectors in advance, so we can handle errors in the selectors prior to making
	// any updates.
	var err error
	policyV1 := uv1.Value.(*model.Policy)
	parsedSel, err := selector.Parse(policyV1.Selector)
	if err != nil {
		// We have found a bad policy selector in our cache, so we'd better remove it. Send
		// in a delete update.
		log.WithError(err).Error("Bad policy selector found in config - removing policy from cache")
		c.onDeletePolicy(key)
		return
	}
	c.registerSelector(key, parsedSel)
}

// onDeletePolicy is called when the syncer has a delete for a Policy.
// This is used to register/unregister match updates from the InheritIndex helper for the
// policy selector so that we can track total endpoint counts for each policy.
func (c *labelHandler) onDeletePolicy(key model.ResourceKey) {
	// Unregister the main policy selector and the selector for each rule in that policy.
	c.unregisterSelector(key)
}

// registerSelector registers a selector with the InheritIndex helper.
func (c *labelHandler) registerSelector(selectorId any, selector *selector.Selector) {
	c.index.UpdateSelector(selectorId, selector)
}

// unregisterSelector unregisters a selector with the InheritIndex helper.
func (c *labelHandler) unregisterSelector(selectorId any) {
	c.index.DeleteSelector(selectorId)
}

// onMatchStarted is called from the InheritIndex helper when a selector-endpoint match has
// started.
func (c *labelHandler) onMatchStarted(selId, epId any) {
	switch s := selId.(type) {
	case policyQueryId:
		switch epId.(type) {
		case model.NetworkSetKey:
			// No op for network set queries - we don't return network sets matching
			// policy selectors.
		default:
			c.results = append(c.results, epId.(model.Key))
		}
	case ruleSelectorId:
		switch e := epId.(type) {
		case model.Key:
			for _, cb := range c.ruleCallbacks {
				cb(MatchStarted, string(s), e)
			}
		case policyQueryId:
			// No op for endpoint queries - we don't return rule matches.
		case ruleQueryId:
			// Return matching rule selectors
			c.ruleSelectorResults = append(c.ruleSelectorResults, string(s))
		default:
			log.WithFields(log.Fields{
				"selId": selId,
				"epId":  epId,
			}).Fatal("Unhandled endpoint type in onMatchStarted event")
		}
	case model.Key:
		switch e := epId.(type) {
		case model.Key:
			for _, cb := range c.policyCallbacks {
				cb(MatchStarted, s, e)
			}
		case policyQueryId:
			c.results = append(c.results, s)
		case ruleQueryId:
			// Ignore rule queries that match endpoints.
		default:
			log.WithFields(log.Fields{
				"selId": selId,
				"epId":  epId,
			}).Fatal("Unhandled endpoint type in onMatchStarted event")
		}
	default:
		log.WithFields(log.Fields{
			"selId": selId,
			"epId":  epId,
		}).Fatal("Unhandled selector type in onMatchStarted event")
	}
}

// onMatchStopped is called from the InheritIndex helper when a selector-endpoint match has
// stopped.
func (c *labelHandler) onMatchStopped(selId, epId any) {
	switch s := selId.(type) {
	case policyQueryId:
		// noop required - this occurs when the query is deleted.
	case ruleSelectorId:
		switch e := epId.(type) {
		case model.Key:
			for _, cb := range c.ruleCallbacks {
				cb(MatchStopped, string(s), e)
			}
		case policyQueryId:
			// No op for endpoint queries - we don't return rule matches.
		case ruleQueryId:
			// No op required - this occurs when a rule selector query is deleted.
		default:
			log.WithFields(log.Fields{
				"selId": selId,
				"epId":  epId,
			}).Fatal("Unhandled endpoint type in onMatchStarted event")
		}
	case model.Key:
		switch e := epId.(type) {
		case model.Key:
			for _, cb := range c.policyCallbacks {
				cb(MatchStopped, s, e)
			}
		case policyQueryId:
			// noop required - this occurs when the query is deleted.
		case ruleQueryId:
			// noop required - this occurs when the query is deleted.
		default:
			log.WithFields(log.Fields{
				"selId": selId,
				"epId":  epId,
			}).Fatal("Unhandled endpoint type in onMatchStopped event")
		}
	default:
		log.WithFields(log.Fields{
			"selId": selId,
			"epId":  epId,
		}).Fatal("Unhandled selector type in onMatchStopped event")
	}
}
