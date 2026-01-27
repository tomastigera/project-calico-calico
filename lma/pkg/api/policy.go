// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
package api

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

const (
	// Backward compatible - handle mixed entries of policy strings,
	// old format "index|tier|name|action" (count=4) and
	// new format "index|tier|name|aciton|ruleidindex" (count=5).
	oldPolicyPartsCount = 4
	newPolicyPartsCount = 5

	policyStrIndexIdx       = 0
	policyStrTierIdx        = 1
	policyStrNameIdx        = 2
	policyStrActionIdx      = 3
	policyStrRuleIdIndexIdx = 4
)

// PolicyHit represents a policy log in a flow log. This interface is used to make a the implementation read only, as the
// implementation is a representation of a log that is not changing. Certain Set actions have bee added, however they
// return a changed copy of the underlying policy hit to maintain the immutable properties.
type PolicyHit interface {
	// Action returns the action for this policy hit.
	Action() Action

	// Count returns the number of flow logs that this policy hit was applied to.
	Count() int64

	// FlowLogName returns the name as it would appear in the flow log. This is unique for a specific policy instance.
	// -  <tier>.<name>
	// -  <namespace>/<tier>.<name>
	// -  <namespace>/<tier>.staged:<name>
	// -  <namespace>/knp.default.<name>
	// -  <namespace>/staged:knp.default.<name>
	// -  <namespace>/staged:knp.default.<name>
	// -  __PROFILE__.kns.<namespace>
	FlowLogName() string

	// Index returns the index for this hit.
	Index() int

	// IsKubernetes returns whether or not this policy is a staged policy.
	IsKubernetes() bool

	// IsProfile returns whether or not this policy is a profile.
	IsProfile() bool

	// IsStaged returns whether or not this policy is a staged policy.
	IsStaged() bool

	// Name returns the raw name of the policy.
	Name() string

	// Kind() returns the kind of policy (NetworkPolicy, GlobalNetworkPolicy, etc).
	Kind() string

	// Namespace returns the policy namespace (if namespaced). An empty string is returned if the
	// policy is not namespaced.
	Namespace() string

	// SetIndex sets the index on a copy of the underlying PolicyHit and returns it.
	SetIndex(int) PolicyHit

	// Tier returns the tier name (or __PROFILE__ for profile match)
	Tier() string

	// ToFlowLogPolicyString returns a flow log policy string. Implementations of this must ensure that the value returned
	// from ToFlowLogPolicyString matches the input string passed to PolicyHitFromFlowLogPolicyString used to create
	// the PolicyHit (if it was used) exactly.
	ToFlowLogPolicyString() string

	// RuleIdIndex returns the rule id index pointer for this hit.
	RuleIdIndex() *int
}

// PolicyHitKey identifies a policy.
type policyHit struct {
	// The policy name.
	name string

	// The policy namespace (if namespaced).
	namespace string

	// The policy kind.
	kind string

	// The action for this policy hit.
	action Action

	// The document count.
	count int64

	// The index for this hit.
	index int

	// The tier name (or __PROFILE__ for profile match)
	tier string

	// The pointer to a rule id index for this hit.
	ruleIdIndex *int
}

// Kind returns the kind of policy (NetworkPolicy, GlobalNetworkPolicy, etc).
func (p policyHit) Kind() string {
	return p.kind
}

// Action returns the action for this policy hit.
func (p policyHit) Action() Action {
	return p.action
}

// Count returns the number of flow logs that this policy hit was applied to.
func (p policyHit) Count() int64 {
	return p.count
}

// FlowLogName returns the name part as it would appear in the flow log.
func (p policyHit) FlowLogName() string {
	// Use the same logic as calc.NewRuleID to generate the flow log policy name, ensuring consistency with
	// how flow logs are generated in Felix.
	rid := calc.NewRuleID(
		p.kind,
		p.tier,
		p.name,
		p.namespace,
		-1,                    // ruleIndex is not part of flow log name
		rules.RuleDirEgress,   // ruleDirection is not part of flow log name
		rules.RuleActionAllow, // ruleAction is not part of flow log name
	)

	// We only want the ID part of the flow log name, not the full RuleID.
	policyStr := rid.GetFlowLogPolicyName()
	splits := strings.Split(policyStr, "|")
	return splits[1]
}

// Index returns the index for this hit.
func (p policyHit) Index() int {
	return p.index
}

// IsKubernetes returns whether or not this policy is a staged policy.
func (p policyHit) IsKubernetes() bool {
	switch p.Kind() {
	case v3.KindStagedKubernetesNetworkPolicy,
		model.KindKubernetesNetworkPolicy:
		return true
	}
	return false
}

// IsProfile returns whether or not this policy is a profile.
func (p policyHit) IsProfile() bool {
	return p.Kind() == v3.KindProfile
}

// IsStaged returns whether or not this policy is a staged policy.
func (p policyHit) IsStaged() bool {
	switch p.Kind() {
	case v3.KindStagedKubernetesNetworkPolicy,
		v3.KindStagedNetworkPolicy,
		v3.KindStagedGlobalNetworkPolicy:
		return true
	}
	return false
}

// Name returns the raw name of the policy without any tier or knp prefixes.
func (p policyHit) Name() string {
	return p.name
}

// Namespace returns the policy namespace (if namespaced). An empty string is returned if the
// policy is not namespaced.
func (p policyHit) Namespace() string {
	return p.namespace
}

// SetIndex sets the index on a copy of the underlying PolicyHit and returns it.
func (p policyHit) SetIndex(index int) PolicyHit {
	p.index = index
	return &p
}

// Tier returns the tier name (or __PROFILE__ for profile match)
func (p policyHit) Tier() string {
	return p.tier
}

// RuleIdIndex returns the rule id index for this hit.
func (p policyHit) RuleIdIndex() *int {
	return p.ruleIdIndex
}

// ruleIdIndexString returns the rule id index as a string for this hit.
func (p policyHit) ruleIdIndexString() string {
	if p.ruleIdIndex != nil {
		return strconv.Itoa(*p.ruleIdIndex)
	}
	return "-"
}

// ToFlowLogPolicyString returns a flow log policy string. If PolicyHitFromFlowLogPolicyString was
// used to create the PolicyHit the return value of ToFlowLogPolicyString will exactly match the
// string given to PolicyHitFromFlowLogPolicyString.
// <index> | <tier> | <name> | <action> | <ruleID>
func (p policyHit) ToFlowLogPolicyString() string {
	return fmt.Sprintf(
		"%d|%s|%s|%s|%s", p.index, p.tier, p.FlowLogName(), p.action, p.ruleIdIndexString(),
	)
}

func (p policyHit) Fields() logrus.Fields {
	return logrus.Fields{
		"action":      p.action,
		"count":       p.count,
		"index":       p.index,
		"name":        p.name,
		"namespace":   p.namespace,
		"kind":        p.kind,
		"tier":        p.tier,
		"ruleIdIndex": p.ruleIdIndex,
	}
}

// NewPolicyHit creates and returns a new PolicyHit. This will mainly be used for PIP, where we
// "generate" policy hit logs for the user to see how their flows change with new policies.
func NewPolicyHit(
	action Action,
	count int64,
	index int,
	name, namespace, kind, tier string,
	ruleIdIndex *int,
) (PolicyHit, error) {
	if action == ActionInvalid {
		return nil, fmt.Errorf("a none empty Action must be provided")
	}
	if index < 0 {
		return nil, fmt.Errorf("index must be a positive integer")
	}
	if count < 0 {
		return nil, fmt.Errorf("count must be a positive integer")
	}
	if ruleIdIndex != nil && *ruleIdIndex != -1 && *ruleIdIndex < 0 {
		return nil, fmt.Errorf("rule id index must be a positive integer or -1")
	}

	isProfile := tier == "__PROFILE__" || tier == ""
	if isProfile && kind != v3.KindProfile {
		return nil, fmt.Errorf("tier '__PROFILE__' can only be used with kind 'Profile'")
	}

	if err := ValidateKind(kind); err != nil {
		return nil, err
	}

	p := &policyHit{
		kind:        kind,
		namespace:   namespace,
		name:        name,
		action:      action,
		count:       count,
		index:       index,
		tier:        tier,
		ruleIdIndex: ruleIdIndex,
	}

	return p, nil
}

// ValidateKind validates that the given kind is a valid policy kind. When new kinds are added,
// this function must be updated as well as shortKindToFullKind below.
func ValidateKind(kind string) error {
	switch kind {
	case model.KindKubernetesNetworkPolicy,
		v3.KindStagedKubernetesNetworkPolicy,
		v3.KindNetworkPolicy,
		v3.KindStagedNetworkPolicy,
		v3.KindGlobalNetworkPolicy,
		v3.KindStagedGlobalNetworkPolicy,
		v3.KindProfile:
		return nil
	}
	return fmt.Errorf("invalid policy kind '%s'", kind)
}

// PolicyHitFromFlowLogPolicyString creates a PolicyHit from a flow log policy string.
func PolicyHitFromFlowLogPolicyString(policyString string, count int64) (PolicyHit, error) {
	parts := strings.Split(policyString, "|")
	// Backward compatible to handle an old policy string, where the parts count is equal to
	// oldPolicyPartsCount==4.
	if len(parts) != newPolicyPartsCount && len(parts) != oldPolicyPartsCount {
		return nil,
			fmt.Errorf("invalid policy string '%s': pipe count must equal %d for a new or "+
				"%d for an old version of the policy string",
				policyString, newPolicyPartsCount, oldPolicyPartsCount)
	}

	p := &policyHit{
		count: count,
	}

	var err error
	p.index, err = strconv.Atoi(parts[policyStrIndexIdx])
	if err != nil {
		return nil, fmt.Errorf("invalid policy index: %w", err)
	}
	p.tier = parts[policyStrTierIdx]

	// The name part can be one of two formats:
	// - legacy format, which varies based on policy kind.
	// - modern format, which is always <kind>:[<namespace>/]<name>
	namePart := parts[policyStrNameIdx]
	if !isLegacyName(namePart) {
		p.kind, p.namespace, p.name, err = parseModernName(namePart)
		if err != nil {
			return nil, fmt.Errorf("invalid modern policy name: %w", err)
		}
	} else {
		p.kind, p.namespace, p.name = parseLegacyName(namePart, p.tier)
	}

	p.action = ActionFromString(parts[policyStrActionIdx])
	if p.action == ActionInvalid {
		return nil, fmt.Errorf("invalid action '%s'", parts[policyStrActionIdx])
	}

	// If the rule id index string is '-', set the hit RuleIdIndex to nil.
	if len(parts) == newPolicyPartsCount && parts[policyStrRuleIdIndexIdx] != "-" {
		p.ruleIdIndex = new(int)
		if *p.ruleIdIndex, err = strconv.Atoi(parts[policyStrRuleIdIndexIdx]); err != nil {
			return nil, fmt.Errorf("invalid policy rule id index: %w", err)
		}
	}

	return p, nil
}

func isLegacyName(namePart string) bool {
	// Legacy names do not contain a colon separating kind from name, although they may contain
	// colons as part of a 'staged:' prefix.
	if !strings.Contains(namePart, ":") {
		return true
	}

	// Next, check if the part before the colon is a known short kind.
	splits := strings.SplitN(namePart, ":", 2)
	if len(splits) != 2 {
		return true
	}
	kindShort := splits[0]
	return shortKindToFullKind(kindShort) == ""
}

func shortKindToFullKind(short string) string {
	switch short {
	case types.ShortKindKubernetesNetworkPolicy:
		return model.KindKubernetesNetworkPolicy
	case types.ShortKindStagedKubernetesNetworkPolicy:
		return v3.KindStagedKubernetesNetworkPolicy
	case types.ShortKindNetworkPolicy:
		return v3.KindNetworkPolicy
	case types.ShortKindStagedNetworkPolicy:
		return v3.KindStagedNetworkPolicy
	case types.ShortKindGlobalNetworkPolicy:
		return v3.KindGlobalNetworkPolicy
	case types.ShortKindStagedGlobalNetworkPolicy:
		return v3.KindStagedGlobalNetworkPolicy
	case types.ShortKindProfile:
		return v3.KindProfile
	case types.ShortKindKubernetesClusterNetworkPolicy:
		return model.KindKubernetesClusterNetworkPolicy
	case "kbanp":
		return model.KindKubernetesBaselineAdminNetworkPolicy
	case "kanp":
		return model.KindKubernetesAdminNetworkPolicy
	}
	return ""
}

func parseModernName(namePart string) (string, string, string, error) {
	var namespace string
	var name string
	var shortKind string

	// First, separate out the kind.
	splits := strings.SplitN(namePart, ":", 2)
	if len(splits) != 2 {
		return "", "", "", fmt.Errorf("invalid modern policy name '%s': missing kind prefix", namePart)
	}
	shortKind = splits[0]
	nameWithOptionalNamespace := splits[1]

	// Next, separate out the namespace if it exists.
	splits = strings.SplitN(nameWithOptionalNamespace, "/", 2)
	if len(splits) == 2 {
		namespace = splits[0]
		name = splits[1]
	} else {
		name = splits[0]
	}

	return shortKindToFullKind(shortKind), namespace, name, nil
}

// parseLegacyName parses the given full policy name (which includes tier, knp, or kns prefixes and may
// or may not contain the staged: pre / mid fix) and sets the appropriate policy hit fields
// (isKNP, isProfile...).
func parseLegacyName(namePart, tier string) (string, string, string) {
	var staged, knp, profile bool
	var namespace string
	var name string

	// First, separate out the namespace if it exists.
	splits := strings.SplitN(namePart, "/", 2)
	if len(splits) == 2 {
		namespace = splits[0]
		name = splits[1]
	} else {
		name = splits[0]
	}

	// legacyStagedPrefix is the prefix used in flow logs to indicate a staged policy.
	legacyStagedPrefix := "staged:"

	// First, check for the staged prefix, which may show up in a couple of different places.
	if strings.Contains(name, legacyStagedPrefix) {
		staged = true

		// Remove the staged prefix. Calico NPs are prefixed with "tier.staged:" whereas
		// KNPs are prefixed with "staged:", so split on the legacyStagedPrefix to handle both cases.
		splits := strings.Split(name, legacyStagedPrefix)
		name = splits[1]
	}

	if strings.HasPrefix(name, "knp.default.") {
		knp = true
		name = strings.TrimPrefix(name, "knp.default.")
	} else if strings.HasPrefix(name, "__PROFILE__.") {
		profile = true
		name = strings.TrimPrefix(name, "__PROFILE__.")
	} else if !strings.HasPrefix(name, tier+".") {
		// Add the tier prefix to the name - this used to be required.
		name = fmt.Sprintf("%s.%s", tier, name)
	}

	return v1.KindFromHints(knp, profile, staged, namespace), namespace, name
}

// SortablePolicyHits is a sortable slice of PolicyHits.
type SortablePolicyHits []PolicyHit

func (s SortablePolicyHits) Len() int { return len(s) }

func (s SortablePolicyHits) Less(i, j int) bool {
	if s[i].Index() != s[j].Index() {
		return s[i].Index() < s[j].Index()
	}
	if s[i].Namespace() != s[j].Namespace() {
		return s[i].Namespace() < s[j].Namespace()
	}
	if s[i].FlowLogName() != s[j].FlowLogName() {
		return s[i].FlowLogName() < s[j].FlowLogName()
	}
	if s[i].Action() != s[j].Action() {
		return s[i].Action() < s[j].Action()
	}
	if s[i].RuleIdIndex() == nil && s[j].RuleIdIndex() != nil {
		return true
	} else if s[i].RuleIdIndex() != nil && s[j].RuleIdIndex() == nil {
		return false
	} else if s[i].RuleIdIndex() != nil && s[j].RuleIdIndex() != nil &&
		*s[i].RuleIdIndex() != *s[j].RuleIdIndex() {
		return *s[i].RuleIdIndex() < *s[j].RuleIdIndex()
	}
	return s[i].IsStaged() && !s[j].IsStaged()
}

func (s SortablePolicyHits) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// SortAndRenumber sorts the PolicyHit slice and renumbers to be monotonically increasing.
func (s SortablePolicyHits) SortAndRenumber() {
	sort.Sort(s)
	for i := range s {
		s[i] = s[i].SetIndex(i)
	}
}

// PolicyHitsEqual compares two sets of PolicyHits to see if both order and values are identical.
func PolicyHitsEqual(p1, p2 []PolicyHit) bool {
	if len(p1) != len(p2) {
		return false
	}

	for i := range p1 {
		if !reflect.DeepEqual(p1[i], p2[i]) {
			return false
		}
	}
	return true
}

// ObfuscatedPolicyString creates the flow log policy string indicating an obfuscated policy.
func ObfuscatedPolicyString(matchIdx int, action Action) string {
	return fmt.Sprintf("%d|*|*|%s|*", matchIdx, action)
}
