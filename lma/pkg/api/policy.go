// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.
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

	policyStrIndexIdx     = 0
	policyStrTierIdx      = 1
	policyStrNameIdx      = 2
	policyStrActionIdx    = 3
	policyStrRuleIndexIdx = 4
)

// PolicyHit represents a policy hit in a flow log.
type PolicyHit interface {
	Action() Action
	Index() int
	Name() string
	Kind() string
	Namespace() string
	Tier() string
	RuleIndex() *int
}

type policyHit struct {
	name      string
	namespace string
	kind      string
	action    Action
	index     int
	tier      string
	ruleIndex *int
}

func (p policyHit) Kind() string      { return p.kind }
func (p policyHit) Action() Action    { return p.action }
func (p policyHit) Index() int        { return p.index }
func (p policyHit) Name() string      { return p.name }
func (p policyHit) Namespace() string { return p.namespace }
func (p policyHit) Tier() string      { return p.tier }
func (p policyHit) RuleIndex() *int   { return p.ruleIndex }

// WithIndex returns a copy of the PolicyHit with the given index.
func (p policyHit) WithIndex(index int) PolicyHit {
	p.index = index
	return &p
}

func (p policyHit) Fields() logrus.Fields {
	return logrus.Fields{
		"action":    p.action,
		"index":     p.index,
		"name":      p.name,
		"namespace": p.namespace,
		"kind":      p.kind,
		"tier":      p.tier,
		"ruleIndex": p.ruleIndex,
	}
}

// IsKubernetes returns whether the given kind is a Kubernetes network policy kind.
func IsKubernetes(kind string) bool {
	switch kind {
	case v3.KindStagedKubernetesNetworkPolicy,
		model.KindKubernetesNetworkPolicy:
		return true
	}
	return false
}

// IsProfile returns whether the given kind is a profile.
func IsProfile(kind string) bool {
	return kind == v3.KindProfile
}

// IsStaged returns whether the given kind is a staged policy kind.
func IsStaged(kind string) bool {
	switch kind {
	case v3.KindStagedKubernetesNetworkPolicy,
		v3.KindStagedNetworkPolicy,
		v3.KindStagedGlobalNetworkPolicy:
		return true
	}
	return false
}

// FlowLogName returns the name part as it would appear in the flow log for the given policy fields.
func FlowLogName(kind, tier, name, namespace string) string {
	rid := calc.NewRuleID(
		kind,
		tier,
		name,
		namespace,
		-1,                    // ruleIndex is not part of flow log name
		rules.RuleDirEgress,   // ruleDirection is not part of flow log name
		rules.RuleActionAllow, // ruleAction is not part of flow log name
	)

	policyStr := rid.GetFlowLogPolicyName()
	splits := strings.Split(policyStr, "|")
	return splits[1]
}

func ruleIndexString(ri *int) string {
	if ri != nil {
		return strconv.Itoa(*ri)
	}
	return "-"
}

// HitFlowLogName returns the flow log name for a PolicyHit. This is a convenience wrapper around
// FlowLogName that extracts the necessary fields from the PolicyHit.
func HitFlowLogName(p PolicyHit) string {
	return FlowLogName(p.Kind(), p.Tier(), p.Name(), p.Namespace())
}

// ToFlowLogPolicyString converts a PolicyHit to the pipe-delimited flow log policy string format.
func ToFlowLogPolicyString(p PolicyHit) string {
	return ToFlowLogPolicyStringWithIndex(p, p.Index())
}

// ToFlowLogPolicyStringWithIndex is like ToFlowLogPolicyString but uses the provided index instead
// of the PolicyHit's own index. This is used when renumbering policies (e.g., after RBAC filtering).
func ToFlowLogPolicyStringWithIndex(p PolicyHit, index int) string {
	return fmt.Sprintf(
		"%d|%s|%s|%s|%s",
		index,
		p.Tier(),
		HitFlowLogName(p),
		p.Action(),
		ruleIndexString(p.RuleIndex()),
	)
}

// NewPolicyHit creates and returns a new PolicyHit.
func NewPolicyHit(
	action Action,
	index int,
	name, namespace, kind, tier string,
	ruleIndex *int,
) (PolicyHit, error) {
	if action == ActionInvalid {
		return nil, fmt.Errorf("a none empty Action must be provided")
	}
	if index < 0 {
		return nil, fmt.Errorf("index must be a positive integer")
	}
	if ruleIndex != nil && *ruleIndex != -1 && *ruleIndex < 0 {
		return nil, fmt.Errorf("rule index must be a positive integer or -1")
	}

	isProfile := tier == "__PROFILE__" || tier == ""
	if isProfile && kind != v3.KindProfile {
		return nil, fmt.Errorf("tier '__PROFILE__' can only be used with kind 'Profile'")
	}

	if err := ValidateKind(kind); err != nil {
		return nil, err
	}

	p := &policyHit{
		kind:      kind,
		namespace: namespace,
		name:      name,
		action:    action,
		index:     index,
		tier:      tier,
		ruleIndex: ruleIndex,
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
func PolicyHitFromFlowLogPolicyString(policyString string) (PolicyHit, error) {
	parts := strings.Split(policyString, "|")
	// Backward compatible to handle an old policy string, where the parts count is equal to
	// oldPolicyPartsCount==4.
	if len(parts) != newPolicyPartsCount && len(parts) != oldPolicyPartsCount {
		return nil,
			fmt.Errorf("invalid policy string '%s': pipe count must equal %d for a new or "+
				"%d for an old version of the policy string",
				policyString, newPolicyPartsCount, oldPolicyPartsCount)
	}

	p := &policyHit{}

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

	// If the rule index string is '-', set the hit RuleIndex to nil.
	if len(parts) == newPolicyPartsCount && parts[policyStrRuleIndexIdx] != "-" {
		p.ruleIndex = new(int)
		if *p.ruleIndex, err = strconv.Atoi(parts[policyStrRuleIndexIdx]); err != nil {
			return nil, fmt.Errorf("invalid policy rule index: %w", err)
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

// SortablePolicyHit extends PolicyHit with a WithIndex method, allowing the index to be
// updated during sorting. Implementations of PolicyHit that need to participate in
// SortAndRenumber should implement this interface.
type SortablePolicyHit interface {
	PolicyHit
	WithIndex(int) PolicyHit
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
	iName := HitFlowLogName(s[i])
	jName := HitFlowLogName(s[j])
	if iName != jName {
		return iName < jName
	}
	if s[i].Action() != s[j].Action() {
		return s[i].Action() < s[j].Action()
	}
	if s[i].RuleIndex() == nil && s[j].RuleIndex() != nil {
		return true
	} else if s[i].RuleIndex() != nil && s[j].RuleIndex() == nil {
		return false
	} else if s[i].RuleIndex() != nil && s[j].RuleIndex() != nil &&
		*s[i].RuleIndex() != *s[j].RuleIndex() {
		return *s[i].RuleIndex() < *s[j].RuleIndex()
	}
	return IsStaged(s[i].Kind()) && !IsStaged(s[j].Kind())
}

func (s SortablePolicyHits) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// SortAndRenumber sorts the PolicyHit slice and renumbers to be monotonically increasing.
// PolicyHits that implement SortablePolicyHit will have their index updated.
func (s SortablePolicyHits) SortAndRenumber() {
	sort.Sort(s)
	for i := range s {
		if sph, ok := s[i].(SortablePolicyHit); ok {
			s[i] = sph.WithIndex(i)
		}
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
