// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.
package cache

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/networking/v1"

	"github.com/projectcalico/calico/felix/calc"
	libapi "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/dispatcherv1v3"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/labelhandler"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/utils"
)

type PoliciesCache interface {
	TotalGlobalNetworkPolicies() api.PolicySummary
	TotalNetworkPoliciesByNamespace() map[string]api.PolicySummary
	GetPolicy(model.Key) api.Policy
	GetTier(model.Key) api.Tier
	GetOrderedPolicies(set.Set[model.Key]) []api.Tier
	RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface)
	RegisterWithLabelHandler(handler labelhandler.Interface)
	GetPolicyKeySetByRuleSelector(string) set.Set[model.Key]
}

func NewPoliciesCache() PoliciesCache {
	return &policiesCache{
		globalNetworkPolicies:      newPolicyCache(),
		networkPoliciesByNamespace: make(map[string]*policyCache),
		tiers:                      make(map[string]*tierData),
		policySorter:               calc.NewPolicySorter(),
		ruleSelectors:              make(map[string]*ruleSelectorInfo),
	}
}

type policiesCache struct {
	globalNetworkPolicies      *policyCache
	networkPoliciesByNamespace map[string]*policyCache
	tiers                      map[string]*tierData
	policySorter               *calc.PolicySorter
	orderedTiers               []*tierData

	// Rule selectors are consolidated to reduce occupancy. We register with the label handler which
	// selectors we require for the rules.
	ruleRegistration labelhandler.RuleRegistrationInterface
	ruleSelectors    map[string]*ruleSelectorInfo
}

type policyCache struct {
	policies          map[model.Key]*policyData
	unmatchedPolicies set.Set[model.Key]
}

func newPolicyCache() *policyCache {
	return &policyCache{
		policies:          make(map[model.Key]*policyData),
		unmatchedPolicies: set.New[model.Key](),
	}
}

func (c *policiesCache) TotalGlobalNetworkPolicies() api.PolicySummary {
	return api.PolicySummary{
		Total:        len(c.globalNetworkPolicies.policies),
		NumUnmatched: c.globalNetworkPolicies.unmatchedPolicies.Len(),
	}
}

func (c *policiesCache) TotalNetworkPoliciesByNamespace() map[string]api.PolicySummary {
	nps := make(map[string]api.PolicySummary)
	for ns, cache := range c.networkPoliciesByNamespace {
		nps[ns] = api.PolicySummary{
			Total:        len(cache.policies),
			NumUnmatched: cache.unmatchedPolicies.Len(),
		}
	}
	return nps
}

func (c *policiesCache) GetPolicy(key model.Key) api.Policy {
	if policy := c.getPolicy(key); policy != nil {
		return c.combinePolicyDataWithRules(policy)
	}
	return nil
}

func (c *policiesCache) GetTier(key model.Key) api.Tier {
	c.orderPolicies()
	t := c.tiers[key.(model.ResourceKey).Name]
	if t == nil {
		return nil
	}
	return c.combineTierDataWithRules(t)
}

func (c *policiesCache) GetOrderedPolicies(keys set.Set[model.Key]) []api.Tier {
	c.orderPolicies()
	var tierDatas []*tierData
	if keys == nil {
		tierDatas = c.orderedTiers
	} else {
		tierDatas = make([]*tierData, 0)
		for _, t := range c.orderedTiers {
			td := &tierData{
				resource: t.resource,
				name:     t.name,
			}
			for _, p := range t.orderedPolicies {
				// Temporary fix for policy name inconsistency between label inheritance and policy cache.
				//
				// Problem: When retrieving policies via label inheritance, they include the tier prefix
				// (e.g., "default.policy1"), but the policy cache stores them with their original CRD name
				// (e.g., "policy1"). This causes lookups like keys.Contains(p.getKey()) to fail.
				// For staged policies, label inheritance returns "staged:default.policy1" whereas in
				// policy cache we have "staged:policy1".
				//
				// Solution:  For policies that don't contain a period, prepend "default." to match the format
				// used by the label inheritance mechanism. This works because:
				//   1. Calico policy names cannot contain periods except as tier separators.
				//   2. Policies without a period must be in the default tier.
				//   3. All other tiers explicitly include the tier name in the policy identifier.
				//   4. "Staged:" prefix comes before tier prefix.
				k := p.getKey().(model.ResourceKey)
				if !strings.Contains(k.Name, ".") {
					if strings.HasPrefix(k.Name, "staged:") {
						policyNameWithOutTags := strings.TrimPrefix(k.Name, "staged:")
						k.Name = fmt.Sprintf("staged:default.%s", policyNameWithOutTags)
					} else {
						k.Name = fmt.Sprintf("default.%s", k.Name)
					}
				}

				if keys.Contains(k) {
					td.orderedPolicies = append(td.orderedPolicies, p)
				}
			}
			if len(td.orderedPolicies) > 0 {
				tierDatas = append(tierDatas, td)
			}
		}
	}

	// Add the rule information to the tiers before returning.
	tiers := make([]api.Tier, len(tierDatas))
	for i, td := range tierDatas {
		tiers[i] = c.combineTierDataWithRules(td)
	}

	return tiers
}

func (c *policiesCache) GetPolicyKeySetByRuleSelector(selector string) set.Set[model.Key] {
	if rs := c.ruleSelectors[selector]; rs != nil {
		return rs.policies
	}
	return set.New[model.Key]()
}

func (c *policiesCache) RegisterWithDispatcher(dispatcher dispatcherv1v3.Interface) {
	dispatcher.RegisterHandler(apiv3.KindGlobalNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(apiv3.KindNetworkPolicy, c.onUpdate)
	dispatcher.RegisterHandler(apiv3.KindStagedGlobalNetworkPolicy, c.onStagedUpdate)
	dispatcher.RegisterHandler(apiv3.KindStagedNetworkPolicy, c.onStagedUpdate)
	dispatcher.RegisterHandler(apiv3.KindStagedKubernetesNetworkPolicy, c.onStagedUpdate)
	dispatcher.RegisterHandler(apiv3.KindTier, c.onUpdate)
}

func (c *policiesCache) RegisterWithLabelHandler(handler labelhandler.Interface) {
	handler.RegisterPolicyHandler(c.policyEndpointMatch)
	c.ruleRegistration = handler.RegisterRuleHandler(c.ruleEndpointMatch)
}

func (c *policiesCache) policyEndpointMatch(matchType labelhandler.MatchType, polKey model.Key, epKey model.Key) {
	erk := epKey.(model.ResourceKey)
	// Get the policy cache. Don't create if it doesn't exist as this means the policy has been deleted. Since
	// the policy cache is updated before the index handler is updated this is a valid scenario, and should be
	// treated as a no-op.
	pc := c.getPolicyCache(polKey, false)
	if pc == nil {
		// The policy has been deleted. Since the policy cache is updated before the index handler is updated this is
		// a valid scenario, and should be treated as a no-op.
		return
	}
	pd := pc.policies[polKey]
	if pd == nil {
		// The policy has been deleted. Since the policy cache is updated before the index handler is updated this is
		// a valid scenario, and should be treated as a no-op.
		return
	}

	switch erk.Kind {
	case apiv3.KindHostEndpoint:
		pd.endpoints.NumHostEndpoints += matchTypeToDelta[matchType]
	case libapi.KindWorkloadEndpoint:
		pd.endpoints.NumWorkloadEndpoints += matchTypeToDelta[matchType]
	default:
		log.WithField("key", erk).Error("Unexpected resource in event type, expecting a v3 endpoint type")
	}

	if pd.IsUnmatched() {
		pc.unmatchedPolicies.Add(polKey)
	} else {
		pc.unmatchedPolicies.Discard(polKey)
	}
}

func (c *policiesCache) ruleEndpointMatch(matchType labelhandler.MatchType, selector string, epKey model.Key) {
	erk := epKey.(model.ResourceKey)
	rsi := c.ruleSelectors[selector]
	// The current rule selector may not be registered if the rule was modified or deleted.  No worries
	// - just skip this match update.
	if rsi == nil {
		return
	}

	switch erk.Kind {
	case apiv3.KindHostEndpoint:
		rsi.endpoints.NumHostEndpoints += matchTypeToDelta[matchType]
	case libapi.KindWorkloadEndpoint:
		rsi.endpoints.NumWorkloadEndpoints += matchTypeToDelta[matchType]
	default:
		log.WithField("key", erk).Error("Unexpected resource in event type, expecting a v3 endpoint type")
	}
}

func (c *policiesCache) onStagedUpdate(update dispatcherv1v3.Update) {
	uv1 := update.UpdateV1
	uv3 := update.UpdateV3

	if utils.DoExcludeStagedPolicy(uv3) {
		sprs := uv3.Key.(model.ResourceKey)
		log.WithField("key", sprs).Error("Filtering staged policies out")
		return
	}

	utils.StagedToEnforcedConversion(uv1, uv3)
	c.onUpdate(update)
}

func (c *policiesCache) onUpdate(update dispatcherv1v3.Update) {
	uv1 := update.UpdateV1
	uv3 := update.UpdateV3

	// Manage our internal tier and policy cache first.
	switch v1k := uv1.Key.(type) {
	case model.TierKey:
		name := v1k.Name
		switch uv3.UpdateType {
		case bapi.UpdateTypeKVNew:
			c.tiers[name] = &tierData{
				name:     name,
				resource: uv3.Value.(api.Resource),
			}
		case bapi.UpdateTypeKVUpdated:
			c.tiers[name].resource = uv3.Value.(api.Resource)
		case bapi.UpdateTypeKVDeleted:
			delete(c.tiers, name)
		}
	case model.PolicyKey:
		// Get the policy cache, creating if necessary.
		pc := c.getPolicyCache(uv3.Key, true)
		if pc == nil {
			return
		}
		switch uv3.UpdateType {
		case bapi.UpdateTypeKVNew:
			pv1 := uv1.Value.(*model.Policy)
			pd := &policyData{
				resource: uv3.Value.(api.Resource),
				v1Policy: pv1,
			}
			pc.policies[uv3.Key] = pd
			pc.unmatchedPolicies.Add(uv3.Key)
			// Add rule selectors for this new policy
			c.addPolicyRuleSelectors(pv1, uv3.Key)
		case bapi.UpdateTypeKVUpdated:
			pv1 := uv1.Value.(*model.Policy)
			existing := pc.policies[uv3.Key]
			existing.resource = uv3.Value.(api.Resource)
			// Remove references to the policy from its current set of rule selectors.
			// We have to remove these references since they are possibly outdated with
			// any changes to the rule selectors. The policy references will be added
			// back to all applicable rule selectors in addPolicyRuleSelectors.
			c.deleteRuleSelectorPolicyReferences(existing.v1Policy, uv3.Key)
			// Update rule selectors for this policy. We add the new ones first and then unregister
			// the old ones - that prevents us potentially removing and adding back in a selector.
			c.addPolicyRuleSelectors(pv1, uv3.Key)
			c.deletePolicyRuleSelectors(existing.v1Policy)
			existing.v1Policy = pv1
		case bapi.UpdateTypeKVDeleted:
			// Staged policies with StagedActionDelete are ignored on add/update.
			// On Delete, searching might not find entry. Ignore in case.
			if existing, ok := pc.policies[uv3.Key]; ok {
				delete(pc.policies, uv3.Key)
				pc.unmatchedPolicies.Discard(uv3.Key)
				// Remove references to this policy from rule selectors
				c.deleteRuleSelectorPolicyReferences(existing.v1Policy, uv3.Key)
				// Remove the rule selectors for this policy.
				c.deletePolicyRuleSelectors(existing.v1Policy)
			}
		}

		if uv3.Key.(model.ResourceKey).Kind == apiv3.KindNetworkPolicy && len(pc.policies) == 0 {
			// Workload endpoints cache is empty for this namespace. Delete from the cache.
			delete(c.networkPoliciesByNamespace, uv3.Key.(model.ResourceKey).Namespace)
		}
	}

	// Update the policy sorter, invalidating our ordered tiers if the policy order needs
	// recalculating.
	if c.policySorter.OnUpdate(*uv1) {
		c.orderedTiers = nil
	}
}

// addPolicyRuleSelectors ensures we are tracking the rule selectors in the policy. This tracks
// based on the selector string and ensures we track identical selectors only once.
func (c *policiesCache) addPolicyRuleSelectors(p *model.Policy, polKey model.Key) {
	add := func(s string) {
		if s == "" {
			// Empty rule selectors are not tracked since we only care about endpoints and network sets that are
			// explicitly selected rather than included in the "everywhere" empty selector.
			return
		}
		rsi := c.ruleSelectors[s]
		if rsi == nil {
			rsi = &ruleSelectorInfo{
				policies: set.New[model.Key](),
			}
			c.ruleSelectors[s] = rsi
		}
		rsi.numRuleRefs++
		if rsi.numRuleRefs == 1 {
			_ = c.ruleRegistration.AddRuleSelector(s)
		}
		rsi.policies.Add(polKey)
	}

	for i := range p.InboundRules {
		r := &p.InboundRules[i]
		add(c.getSrcSelector(r))
		add(c.getDstSelector(r))
	}
	for i := range p.OutboundRules {
		r := &p.OutboundRules[i]
		add(c.getSrcSelector(r))
		add(c.getDstSelector(r))
	}
}

// deletePolicyRuleSelectors deletes the tracking of the rule selectors in the policy.
func (c *policiesCache) deletePolicyRuleSelectors(p *model.Policy) {
	del := func(s string) {
		if s == "" {
			// Empty rule selectors are not tracked since we only care about endpoints and network sets that are
			// explicitly selected rather than included in the "everywhere" empty selector.
			return
		}
		rsi := c.ruleSelectors[s]
		rsi.numRuleRefs--
		if rsi.numRuleRefs == 0 {
			delete(c.ruleSelectors, s)
			c.ruleRegistration.RemoveRuleSelector(s)
		}
	}

	for i := range p.InboundRules {
		r := &p.InboundRules[i]
		del(c.getSrcSelector(r))
		del(c.getDstSelector(r))
	}
	for i := range p.OutboundRules {
		r := &p.OutboundRules[i]
		del(c.getSrcSelector(r))
		del(c.getDstSelector(r))
	}
}

// deleteRuleSelectorPolicyReferences deletes the policy references that denote which policies
// contain a rule selector on the rule selector info.
func (c *policiesCache) deleteRuleSelectorPolicyReferences(p *model.Policy, polKey model.Key) {
	del := func(s string) {
		if s == "" {
			// Empty rule selectors are not tracked since we only care about endpoints and network sets that are
			// explicitly selected rather than included in the "everywhere" empty selector.
			return
		}
		rsi := c.ruleSelectors[s]
		rsi.policies.Discard(polKey)
	}

	for i := range p.InboundRules {
		r := &p.InboundRules[i]
		del(c.getSrcSelector(r))
		del(c.getDstSelector(r))
	}
	for i := range p.OutboundRules {
		r := &p.OutboundRules[i]
		del(c.getSrcSelector(r))
		del(c.getDstSelector(r))
	}
}

// combinePolicyDataWithRules combines the policyData with the cached rule data. The rule data
// is looked up from the effective selector string for each rule. An empty selector is not tracked
// and any associated endpoint counts should be zeroed.
func (c *policiesCache) combinePolicyDataWithRules(p *policyData) *policyDataWithRuleData {
	prd := &policyDataWithRuleData{
		policyData: p,
		ruleEndpoints: api.Rule{
			Ingress: make([]api.RuleDirection, len(p.v1Policy.InboundRules)),
			Egress:  make([]api.RuleDirection, len(p.v1Policy.OutboundRules)),
		},
	}

	setEndpoints := func(v1r *model.Rule, r *api.RuleDirection) {
		if s := c.getDstSelector(v1r); s != "" {
			r.Destination = c.ruleSelectors[s].endpoints
		} else {
			r.Destination = api.EndpointCounts{}
		}
		if s := c.getSrcSelector(v1r); s != "" {
			r.Source = c.ruleSelectors[s].endpoints
		} else {
			r.Source = api.EndpointCounts{}
		}
	}

	for i := range prd.ruleEndpoints.Ingress {
		setEndpoints(&p.v1Policy.InboundRules[i], &prd.ruleEndpoints.Ingress[i])
	}
	for i := range prd.ruleEndpoints.Egress {
		setEndpoints(&p.v1Policy.OutboundRules[i], &prd.ruleEndpoints.Egress[i])
	}

	return prd
}

// getSrcSelector returns the effective source selector by combining the positive and negative
// selectors.
func (c *policiesCache) getSrcSelector(r *model.Rule) string {
	return c.combineSelector(r.SrcSelector, r.NotSrcSelector)
}

// getSrcSelector returns the effective destination selector by combining the positive and negative
// selectors.
func (c *policiesCache) getDstSelector(r *model.Rule) string {
	return c.combineSelector(r.DstSelector, r.NotDstSelector)
}

// combineSelector combines the positive and negative selectors into a single selector string.
// This is slightly different from Felix which only combines the selectors provided the positive
// selector is not empty (since that means "anywhere"), but since we are only interested in
// endpoint counts, we can treat and empty positive selector as "all()" which means we can
// always combine the two selectors into a single selector.
func (c *policiesCache) combineSelector(sel, notSel string) string {
	if sel == "" {
		if notSel == "" {
			return ""
		}
		return "!(" + notSel + ")"
	}
	if notSel == "" {
		return sel
	}
	return "(" + sel + ") && !(" + notSel + ")"
}

// combineTierDataWithRules returns the tier data with the cached rule data.
func (c *policiesCache) combineTierDataWithRules(t *tierData) *tierDataWithRuleData {
	tdr := &tierDataWithRuleData{
		tierData:                t,
		orderedPoliciesWithData: make([]api.Policy, len(t.orderedPolicies)),
	}

	for i := range t.orderedPolicies {
		tdr.orderedPoliciesWithData[i] = c.combinePolicyDataWithRules(t.orderedPolicies[i])
	}

	return tdr
}

// orderPolicies orders the tierData and policyData within each Tier based on the order of
// application by Felix.
func (c *policiesCache) orderPolicies() {
	if c.orderedTiers != nil {
		return
	}
	tiers := c.policySorter.Sorted()
	c.orderedTiers = make([]*tierData, 0, len(tiers))
	for _, tier := range tiers {
		td := c.tiers[tier.Name]
		if td == nil {
			td = &tierData{name: tier.Name}
		}
		c.orderedTiers = append(c.orderedTiers, td)

		// Reset and reconstruct the ordered policies slice.
		td.orderedPolicies = nil
		for _, policy := range tier.OrderedPolicies {
			policyData := c.getPolicyFromV1Key(policy.Key)
			td.orderedPolicies = append(td.orderedPolicies, policyData)
		}
	}
}

func (c *policiesCache) getPolicyFromV1Key(key model.PolicyKey) *policyData {
	switch key.Kind {
	case apiv3.KindStagedGlobalNetworkPolicy:
		// We merge all staged policies into their enforced counterparts in the cache. Staged policies
		// receive a "staged:" prefix on their name to disambiguate them.
		// TODO: Refactor to use the "real" name and rely on key.Kind to disambiguate. See
		// StagedToEnforcedConversion in staged.go for the corresponding conversion.
		log.WithField("key", key).Debug("Looking for staged policy - merged into enforced policy")
		key.Name = "staged:" + key.Name
		fallthrough
	case apiv3.KindGlobalNetworkPolicy:
		v3k := model.ResourceKey{
			Kind: apiv3.KindGlobalNetworkPolicy,
			Name: key.Name,
		}
		log.WithField("v3key", v3k).Debug("Looking for global network policy")
		return c.globalNetworkPolicies.policies[v3k]
	case apiv3.KindStagedNetworkPolicy, apiv3.KindStagedKubernetesNetworkPolicy:
		// We merge all staged policies into their enforced counterparts in the cache. Staged policies
		// receive a "staged:" prefix on their name to disambiguate them.
		// TODO: Refactor to use the "real" name and rely on key.Kind to disambiguate. See
		// StagedToEnforcedConversion in staged.go for the corresponding conversion.
		log.WithField("key", key).Debug("Looking for staged policy - merged into enforced policy")
		key.Name = "staged:" + key.Name
		fallthrough
	case apiv3.KindNetworkPolicy:
		v3k := model.ResourceKey{
			Kind:      apiv3.KindNetworkPolicy,
			Namespace: key.Namespace,
			Name:      key.Name,
		}
		log.WithField("v3key", v3k).Debug("Looking for network policy")
		return c.networkPoliciesByNamespace[key.Namespace].policies[v3k]
	default:
		log.WithField("key", key).Error("Unexpected resource in event type, expecting a v3 policy type")
	}
	return nil
}

func (c *policiesCache) getPolicy(key model.Key) *policyData {
	// Get the endpoint cache to update. Disallow creation of the cache if it doesn't exist and just return a nil
	// result if it doesn't.
	pc := c.getPolicyCache(key, false)
	if pc == nil {
		return nil
	}
	return pc.policies[key]
}

func (c *policiesCache) getPolicyCache(polKey model.Key, create bool) *policyCache {
	if rKey, ok := polKey.(model.ResourceKey); ok {
		switch rKey.Kind {
		case apiv3.KindGlobalNetworkPolicy:
			return c.globalNetworkPolicies
		case apiv3.KindNetworkPolicy:
			networkPolicies := c.networkPoliciesByNamespace[rKey.Namespace]
			if networkPolicies == nil && create {
				networkPolicies = newPolicyCache()
				c.networkPoliciesByNamespace[rKey.Namespace] = networkPolicies
			}
			return networkPolicies
		}
	}
	log.WithField("key", polKey).Error("Unexpected resource in event type, expecting a v3 policy type")
	return nil
}

// policyData is used to hold policy data in the cache, and also implements the Policy interface
// for returning on queries. The v1 data model is maintained to enable us to track rule selector
// references.
type policyData struct {
	resource  api.Resource
	endpoints api.EndpointCounts
	v1Policy  *model.Policy
}

func (d *policyData) GetAnnotations() map[string]string {
	switch r := d.resource.(type) {
	case *apiv3.NetworkPolicy:
		return r.Annotations
	case *apiv3.GlobalNetworkPolicy:
		return r.Annotations
	}
	return map[string]string{}
}

func (d *policyData) GetEndpointCounts() api.EndpointCounts {
	return d.endpoints
}

func (d *policyData) GetResource() api.Resource {
	return d.resource
}

// GetTier returns the tier of the policy
func (d *policyData) GetTier() string {
	tier := ""
	switch r := d.resource.(type) {
	case *apiv3.NetworkPolicy:
		tier = r.Spec.Tier
	case *apiv3.GlobalNetworkPolicy:
		tier = r.Spec.Tier
	}

	if tier == "" {
		tier = names.DefaultTierName
	}

	return tier
}

func (d *policyData) GetOrder() *float64 {
	switch r := d.resource.(type) {
	case *apiv3.NetworkPolicy:
		return r.Spec.Order
	case *apiv3.GlobalNetworkPolicy:
		return r.Spec.Order
	case *apiv3.StagedNetworkPolicy:
		return r.Spec.Order
	case *apiv3.StagedGlobalNetworkPolicy:
		return r.Spec.Order
	default:
		log.Debugf("order is not defined for policy of type: %v", r.GetObjectKind())
	}
	return nil
}

func (d *policyData) GetSelector() *string {
	switch r := d.resource.(type) {
	case *apiv3.NetworkPolicy:
		return &r.Spec.Selector
	case *apiv3.GlobalNetworkPolicy:
		return &r.Spec.Selector
	case *apiv3.StagedNetworkPolicy:
		return &r.Spec.Selector
	case *apiv3.StagedGlobalNetworkPolicy:
		return &r.Spec.Selector
	default:
		log.Debugf("selector is not defined for policy of type: %v", r.GetObjectKind())
	}
	return nil
}

func (d *policyData) GetNamespaceSelector() *string {
	switch r := d.resource.(type) {
	case *apiv3.GlobalNetworkPolicy:
		return &r.Spec.NamespaceSelector
	case *apiv3.StagedGlobalNetworkPolicy:
		return &r.Spec.NamespaceSelector
	default:
		log.Debugf("namespaceSelector is not defined for policy of type: %v", r.GetObjectKind())
	}
	return nil
}

func (d *policyData) GetServiceAccountSelector() *string {
	switch r := d.resource.(type) {
	case *apiv3.NetworkPolicy:
		return &r.Spec.ServiceAccountSelector
	case *apiv3.GlobalNetworkPolicy:
		return &r.Spec.ServiceAccountSelector
	case *apiv3.StagedNetworkPolicy:
		return &r.Spec.ServiceAccountSelector
	case *apiv3.StagedGlobalNetworkPolicy:
		return &r.Spec.ServiceAccountSelector
	default:
		log.Debugf("serviceAcountSelector is not defined for policy of type: %v", r.GetObjectKind())
	}
	return nil
}

func (d *policyData) GetStagedAction() *apiv3.StagedAction {
	if d.v1Policy != nil {
		return d.v1Policy.StagedAction
	} else {
		return nil
	}
}

func (d *policyData) IsUnmatched() bool {
	return d.endpoints.NumWorkloadEndpoints == 0 && d.endpoints.NumHostEndpoints == 0
}

func (d *policyData) getKey() model.Key {
	return model.ResourceKey{
		Kind:      d.resource.GetObjectKind().GroupVersionKind().Kind,
		Name:      d.resource.GetObjectMeta().GetName(),
		Namespace: d.resource.GetObjectMeta().GetNamespace(),
	}
}

func (d *policyData) GetResourceType() api.Resource {
	cachedResource := d.resource
	name := cachedResource.GetObjectMeta().GetName()
	kind := cachedResource.GetObjectKind().GroupVersionKind().Kind

	isStaged := model.KindIsStaged(kind)
	isK8s := strings.Contains(name, "knp")
	isGlobal := kind == apiv3.KindGlobalNetworkPolicy

	switch {
	case isStaged && isK8s:
		return &apiv3.StagedKubernetesNetworkPolicy{
			TypeMeta: resources.TypeCalicoStagedKubernetesNetworkPolicies,
		}
	case !isStaged && isK8s:
		return &v1.NetworkPolicy{
			TypeMeta: resources.TypeK8sNetworkPolicies,
		}
	case isStaged && isGlobal:
		return &apiv3.StagedGlobalNetworkPolicy{
			TypeMeta: resources.TypeCalicoStagedGlobalNetworkPolicies,
			Spec: apiv3.StagedGlobalNetworkPolicySpec{
				Tier: d.GetTier(),
			},
		}
	case isStaged:
		return &apiv3.StagedNetworkPolicy{
			TypeMeta: resources.TypeCalicoStagedNetworkPolicies,
			Spec: apiv3.StagedNetworkPolicySpec{
				Tier: d.GetTier(),
			},
		}
	case isGlobal:
		return &apiv3.GlobalNetworkPolicy{
			TypeMeta: resources.TypeCalicoGlobalNetworkPolicies,
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier: d.GetTier(),
			},
		}
	default:
		return &apiv3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			Spec: apiv3.NetworkPolicySpec{
				Tier: d.GetTier(),
			},
		}
	}
}

func (d *policyData) IsKubernetesType() (bool, error) {
	// since GroupVersionKind is all converted to calico types, we need to check the name prefix
	// for identifying the kubernetes types.
	name := d.GetResource().GetObjectMeta().GetName()

	// remove the staged: tag from the name (if exists)
	if strings.Contains(name, "staged:") {
		name = strings.Split(name, "staged:")[1]
	}

	if strings.HasPrefix(name, "knp.default.") || strings.HasPrefix(name, "kanp.adminnetworkpolicy.") || strings.HasPrefix(name, "kbanp.baselineadminnetworkpolicy.") {
		return true, nil
	}

	// calico policy names cannot include a '.', thus the format should either be <tier>.<name> or <name>
	nameParts := strings.Split(name, ".")
	if len(nameParts) > 2 {
		return false, fmt.Errorf("policy name structure is unknown: %s", name)
	}

	return false, nil
}

// tierData is used to hold policy data in the cache, and also implements the Policy interface
// for returning on queries.
type tierData struct {
	name            string
	resource        api.Resource
	orderedPolicies []*policyData
}

func (d *tierData) GetName() string {
	return d.name
}

func (d *tierData) GetResource() api.Resource {
	return d.resource
}

type ruleSelectorInfo struct {
	numRuleRefs int
	endpoints   api.EndpointCounts
	policies    set.Set[model.Key]
}

// policyDataWithRuleData is a non-cached version of the policy data, but it includes
// the rule endpoint stats that are dynamically created.
type policyDataWithRuleData struct {
	*policyData
	ruleEndpoints api.Rule
}

func (d *policyDataWithRuleData) GetRuleEndpointCounts() api.Rule {
	return d.ruleEndpoints
}

type tierDataWithRuleData struct {
	*tierData
	orderedPoliciesWithData []api.Policy
}

func (d *tierDataWithRuleData) GetOrderedPolicies() []api.Policy {
	return d.orderedPoliciesWithData
}
