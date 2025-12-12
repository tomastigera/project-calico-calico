package xrefcache

import (
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// This file implements a NetworkPolicyRuleSelectorManager. This acts as a bridge between the real policy resources
// and the pseudo NetworkPolicuy RuleSelector types. The manager is responsible for handling

// Callbacks for match start/stop between a selector and a policy.
type NPRSMatchStarted func(policy, selector apiv3.ResourceID)
type NPRSMatchStopped func(policy, selector apiv3.ResourceID)

// NetworkPolicyRuleSelectorManager provides a shared interface for communication between the policy and the selector
// pseudo-resource caches. It also manages the creation and deletion of the pseudo resource types based on whether
// any policy needs a particular selector to be tracked.
type NetworkPolicyRuleSelectorManager interface {
	RegisterCallbacks(onMatchStarted NPRSMatchStarted, onMatchStopped NPRSMatchStopped)
	SetPolicyRuleSelectors(policy apiv3.ResourceID, selectors set.Typed[apiv3.ResourceID])
	DeletePolicy(policy apiv3.ResourceID)
}

// NewNetworkPolicyRuleSelectorManager creates a new NetworkPolicyRuleSelectorManager.
func NewNetworkPolicyRuleSelectorManager(onUpdate func(update syncer.Update)) NetworkPolicyRuleSelectorManager {
	return &networkPolicyRuleSelectorManager{
		onUpdate:           onUpdate,
		selectorsByPolicy:  make(map[apiv3.ResourceID]set.Typed[apiv3.ResourceID]),
		policiesBySelector: make(map[apiv3.ResourceID]set.Typed[apiv3.ResourceID]),
	}
}

// networkPolicyRuleSelectorManager implements the NetworkPolicyRuleSelectorManager interface.
type networkPolicyRuleSelectorManager struct {
	// The onUpdate method called to add the selector rule pseudo resource types.
	onUpdate func(syncer.Update)

	// Registered match stopped/started events.
	onMatchStarted []NPRSMatchStarted
	onMatchStopped []NPRSMatchStopped

	// Selectors by policy
	selectorsByPolicy map[apiv3.ResourceID]set.Typed[apiv3.ResourceID]

	// Policies by selector
	policiesBySelector map[apiv3.ResourceID]set.Typed[apiv3.ResourceID]
}

// RegisterCallbacks registers match start/stop callbacks with this manager.
func (m *networkPolicyRuleSelectorManager) RegisterCallbacks(onMatchStarted NPRSMatchStarted, onMatchStopped NPRSMatchStopped) {
	m.onMatchStarted = append(m.onMatchStarted, onMatchStarted)
	m.onMatchStopped = append(m.onMatchStopped, onMatchStopped)
}

// SetPolicyRuleSelectors sets the rule selectors that need to be tracked by a policy resource.
func (m *networkPolicyRuleSelectorManager) SetPolicyRuleSelectors(p apiv3.ResourceID, s set.Typed[apiv3.ResourceID]) {
	// If we have not seen this policy before then add it now
	currentSelectors, ok := m.selectorsByPolicy[p]
	if !ok {
		currentSelectors = set.Empty[apiv3.ResourceID]()
	}

	set.IterDifferences(currentSelectors, s,
		func(old apiv3.ResourceID) error {
			// Stop tracking old selectors for this policy.
			m.matchStopped(p, old)
			return nil
		},
		func(new apiv3.ResourceID) error {
			// Start tracking new selectors for this policy.
			m.matchStarted(p, new)
			return nil
		},
	)

	// Replace the set of selectors for this policy.
	m.selectorsByPolicy[p] = s
}

func (m *networkPolicyRuleSelectorManager) matchStarted(p, s apiv3.ResourceID) {
	log.Debugf("NetworkPolicyRuleSelector match started: %s / %s", p, s)
	pols, ok := m.policiesBySelector[s]
	if !ok {
		pols = set.New[apiv3.ResourceID]()
		m.policiesBySelector[s] = pols
	}
	pols.Add(p)

	if !ok {
		// This is a new selector, so create a new NetworkPolicy RuleSelector pseudo resource.
		log.Debugf("First policy for selector, adding pseudo-resource %s", s)
		m.onUpdate(syncer.Update{
			Type:       syncer.UpdateTypeSet,
			ResourceID: s,
		})
	}

	// Notify our listeners of a new match.
	for _, cb := range m.onMatchStarted {
		cb(p, s)
	}
}

func (m *networkPolicyRuleSelectorManager) matchStopped(p, s apiv3.ResourceID) {
	log.Debugf("NetworkPolicyRuleSelector match stopped: %s / %s", p, s)
	pols := m.policiesBySelector[s]
	pols.Discard(p)

	// Notify our listeners that the match has stopped.
	for _, cb := range m.onMatchStopped {
		cb(p, s)
	}

	if pols.Len() == 0 {
		// This was the last policy associated with this selector. Delete the RuleSelector pseudo resource.
		log.Debugf("Last policy for selector, deleting pseudo-resource %s", s)
		m.onUpdate(syncer.Update{
			Type:       syncer.UpdateTypeDeleted,
			ResourceID: s,
		})

		delete(m.policiesBySelector, s)
	}
}

// DeletePolicy is called to delete a policy from the manager. This will result in match stopped callbacks for any
// selectors it was previously tracking.
func (m *networkPolicyRuleSelectorManager) DeletePolicy(policy apiv3.ResourceID) {
	currentSelectors, ok := m.selectorsByPolicy[policy]
	if !ok {
		return
	}

	for selector := range currentSelectors.All() {
		m.matchStopped(policy, selector)
	}

	delete(m.selectorsByPolicy, policy)
}
