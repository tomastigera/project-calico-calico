package policycalc

import (
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/lma/pkg/api"
)

// CompiledPolicy contains the compiled policy matchers for either ingress _or_ egress policy rules.
type CompiledPolicy struct {
	// Name of the tier with separators in the flow log format.
	Tier string

	// Policy namespace.
	Namespace string

	// Policy Kind.
	Kind string

	// Calico v3 policy name. This is the name used in the flow log.
	Name string

	// Flow matchers for the main selector of the policy.
	MainSelectorMatchers []FlowMatcher

	// Endpoint matchers for the policy.
	Rules []CompiledRule

	// Whether this policy was modified.
	Modified bool

	// Whether this policy is being enforced or not. Generally for staged policies this would be false, however, if we
	// are previewing the enforcing of a staged policy then this will be set to true.
	Enforced bool

	// Whether this policy was deleted. Note that if deleted, Modified will also be true.
	Deleted bool
}

func (p *CompiledPolicy) Key() model.ResourceKey {
	return model.ResourceKey{
		Kind:      p.Kind,
		Name:      p.Name,
		Namespace: p.Namespace,
	}
}

// Applies determines whether the policy applies to the flow.
func (p *CompiledPolicy) Applies(flow *api.Flow, cache *flowCache) MatchType {
	mt := MatchTypeTrue
	for i := range p.MainSelectorMatchers {
		switch p.MainSelectorMatchers[i](flow, cache) {
		case MatchTypeFalse:
			return MatchTypeFalse
		case MatchTypeUncertain:
			mt = MatchTypeUncertain
		}
	}
	return mt
}

// Action determines the action of this policy on the flow. It is assumed Applies() has already been invoked to
// determine if this policy actually applies to the flow.
//   - It returns a set of possible actions for this policy - a combination of allow, deny, pass or no-match.
//   - It also uses the flow log to validate or provide certainty with the calculation, so the response may contain
//     additional bits that pertain to the flow log value.
func (c *CompiledPolicy) Action(flow *api.Flow, cache *flowCache) api.ActionFlag {
	var exact bool
	var flagsThisPolicy api.ActionFlag
loop:
	for i := range c.Rules {
		log.Debugf("Processing rule %d, action flags %d", i, c.Rules[i].ActionFlag)
		switch c.Rules[i].Match(flow, cache) {
		case MatchTypeTrue:
			// This rule matches exactly, so store off the action type for this rule and exit. No need to enumerate the
			// next policy, or rule since this was an exact match.
			log.Debug("Rule matches exactly")
			flagsThisPolicy |= c.Rules[i].ActionFlag
			exact = true
			break loop
		case MatchTypeUncertain:
			// If the match type is unknown, then at this point we bifurcate by assuming we both matched and did not
			// match - we track that we would use this rules action, but continue enumerating until we either get
			// conflicting possible actions (at which point we deem the impact to be indeterminate), or we end up with
			// same action through all possible match paths.
			log.Debug("Rule match is uncertain")
			flagsThisPolicy |= c.Rules[i].ActionFlag
		}
	}

	// If we got to the end of the rules without finding an exact rule add the no match flag.
	if !exact {
		log.Debug("Reached end of rules - include no match flag")
		flagsThisPolicy |= ActionFlagNoMatch
	}

	log.Debugf("Policy action flags calculated %d", flagsThisPolicy)
	return flagsThisPolicy
}

// compilePolicy compiles the Calico v3 policy resource into separate ingress and egress CompiledPolicy structs.
// If the policy does not contain ingress or egress matches then the corresponding result will be nil.
func compilePolicy(m *MatcherFactory, p Policy, impact Impact, previewingChange bool) (ingressPol, egressPol *CompiledPolicy) {
	log.Debugf("Compiling policy %s", p.ResourceID)

	// From the resource type, determine the namespace, selector and service account matchers and set of rules to use.
	//
	// The resource type here will either be a Calico NetworkPolicy or GlobalNetworkPolicy. Any Kubernetes
	// NetworkPolicies will have been converted to Calico NetworkPolicies prior to this point.
	var namespaceMatcher EndpointMatcher
	var selectorMatcher EndpointMatcher
	var serviceAccountMatcher EndpointMatcher
	var ingress, egress []v3.Rule
	var types []v3.PolicyType
	var tier string

	// The policy is enforced if either the policy is not a staged policy, or it is being previewed (since a staged
	// policy previewed is always enforced).
	enforced := !p.Staged || previewingChange

	switch res := p.CalicoV3Policy.(type) {
	case *v3.NetworkPolicy:
		namespaceMatcher = m.Namespace(res.Namespace)
		// borrow the ServiceAccounts matcher factory since it's functionality is a superset of what we need
		serviceAccountMatcher = m.ServiceAccounts(&v3.ServiceAccountMatch{Selector: res.Spec.ServiceAccountSelector})
		selectorMatcher = m.Selector(res.Spec.Selector)
		ingress, egress = res.Spec.Ingress, res.Spec.Egress
		types = res.Spec.Types
		tier = res.Spec.Tier
	case *v3.GlobalNetworkPolicy:
		namespaceMatcher = m.NamespaceSelector(res.Spec.NamespaceSelector)
		serviceAccountMatcher = m.ServiceAccounts(&v3.ServiceAccountMatch{Selector: res.Spec.ServiceAccountSelector})
		selectorMatcher = m.Selector(res.Spec.Selector)
		ingress, egress = res.Spec.Ingress, res.Spec.Egress
		types = res.Spec.Types
		tier = res.Spec.Tier
	default:
		log.WithField("res", res).Fatal("Unexpected policy resource type")
	}

	// Handle ingress policy matchers
	if policyTypesContains(types, v3.PolicyTypeIngress) {
		ingressPol = &CompiledPolicy{
			Namespace: p.CalicoV3Policy.GetObjectMeta().GetNamespace(),
			Name:      p.CalicoV3Policy.GetObjectMeta().GetName(),
			Kind:      p.Kind(),
			Tier:      tier,
			Rules:     compileRules(m, namespaceMatcher, ingress),
			Modified:  impact.Modified,
			Enforced:  enforced,
			Deleted:   impact.Deleted,
		}
		ingressPol.add(m.Dst(m.CalicoEndpointSelector()))
		ingressPol.add(m.Dst(namespaceMatcher))
		ingressPol.add(m.Dst(serviceAccountMatcher))
		ingressPol.add(m.Dst(selectorMatcher))
	}

	// Handle egress policy matchers
	if policyTypesContains(types, v3.PolicyTypeEgress) {
		egressPol = &CompiledPolicy{
			Namespace: p.CalicoV3Policy.GetObjectMeta().GetNamespace(),
			Name:      p.CalicoV3Policy.GetObjectMeta().GetName(),
			Kind:      p.Kind(),
			Tier:      tier,
			Rules:     compileRules(m, namespaceMatcher, egress),
			Modified:  impact.Modified,
			Enforced:  enforced,
			Deleted:   impact.Deleted,
		}
		egressPol.add(m.Src(m.CalicoEndpointSelector()))
		egressPol.add(m.Src(namespaceMatcher))
		egressPol.add(m.Src(serviceAccountMatcher))
		egressPol.add(m.Src(selectorMatcher))
	}

	return
}

// policyTypesContains checks if the supplied policy type is in the policy type slice
func policyTypesContains(s []v3.PolicyType, e v3.PolicyType) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// add adds the FlowMatcher to the set of matchers for the policy. It may be called with a nil matcher, in which case
// the policy is unchanged.
func (p *CompiledPolicy) add(fm FlowMatcher) {
	if fm == nil {
		// No matcher to add.
		return
	}
	p.MainSelectorMatchers = append(p.MainSelectorMatchers, fm)
}
