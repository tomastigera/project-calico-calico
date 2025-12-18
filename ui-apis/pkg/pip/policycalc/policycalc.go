package policycalc

import (
	"fmt"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/network-policy-api/apis/v1alpha1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/lma/pkg/api"
	pipcfg "github.com/projectcalico/calico/ui-apis/pkg/pip/config"
)

// ------
// This file contains all of the struct definitions that are used as input when instantiating a new policy calculator.
// ------

// The tiers containing the ordered set of Calico v3 policy resource types.
type Policy struct {
	CalicoV3Policy resources.Resource
	ResourceID     v3.ResourceID
	Staged         bool
}

func (p Policy) String() string {
	return fmt.Sprintf("%s -> %s; staged=%v", p.ResourceID, resources.GetResourceID(p.CalicoV3Policy), p.Staged)
}

func (p Policy) Kind() string {
	switch p.CalicoV3Policy.(type) {
	case *v3.NetworkPolicy:
		return v3.KindNetworkPolicy
	case *v3.GlobalNetworkPolicy:
		return v3.KindGlobalNetworkPolicy
	case *v3.StagedNetworkPolicy:
		return v3.KindStagedNetworkPolicy
	case *v3.StagedGlobalNetworkPolicy:
		return v3.KindStagedGlobalNetworkPolicy
	case *netv1.NetworkPolicy:
		return model.KindKubernetesNetworkPolicy
	case *v1alpha1.AdminNetworkPolicy:
		return model.KindKubernetesAdminNetworkPolicy
	case *v1alpha1.BaselineAdminNetworkPolicy:
		return model.KindKubernetesBaselineAdminNetworkPolicy
	default:
		log.Warnf("Unknown policy kind for resource: %T", p.CalicoV3Policy)
		return ""
	}
}

type (
	Tier  []Policy
	Tiers []Tier
)

// The consistent set of configuration used for calculating policy impact.
type ResourceData struct {
	Tiers           Tiers
	Namespaces      []*corev1.Namespace
	ServiceAccounts []*corev1.ServiceAccount
}

type Impact struct {
	// The resource was deleted.
	Deleted bool

	// The resource was modified. This is used to determine whether data from the flow logs can be used to augment
	// calculated data. If the resource was modified then we cannot use flow log data.
	// Note that for an enforced-staged resource, modified pertains to the staged resource type.
	Modified bool
}

// ImpactedResources is a set of impacts resources from a resource update preview. Note that the impact of previewing
// any staged policy has the effect of enforcing the policy as well.
type ImpactedResources map[v3.ResourceID]Impact

// Add adds a resource to the set of modified resources.
func (m ImpactedResources) Add(rid v3.ResourceID, impact Impact) {
	m[rid] = impact

	// For K8s NP, also add the equivalent Calico NP resource ID.
	// TODO(rlb): This is hacky. Need to rethink how we handle converted resources and the modified resources map.
	if rid.TypeMeta == resources.TypeK8sNetworkPolicies {
		rid = v3.ResourceID{
			TypeMeta:  resources.TypeCalicoNetworkPolicies,
			Namespace: rid.Namespace,
			Name:      "knp.default." + rid.Name,
		}
		m[rid] = impact
	}
}

// Impact returns impact for a particular resource.
func (m ImpactedResources) Impact(id v3.ResourceID) (Impact, bool) {
	impact, isImpacted := m[id]
	return impact, isImpacted
}

// IsModified returns if the resource is modified.
func (m ImpactedResources) IsModified(id v3.ResourceID) bool {
	return m[id].Modified
}

// IsDeleted returns if the resource is deleted.
func (m ImpactedResources) IsDeleted(id v3.ResourceID) bool {
	return m[id].Deleted
}

// PolicyCalculator is used to determine the calculated behavior from a configuration change for a given flow.
type PolicyCalculator interface {
	CalculateSource(source *api.Flow) (processed bool, before, after EndpointResponse)
	CalculateDest(dest *api.Flow, srcActionBefore, srcActionAfter api.ActionFlag) (processed bool, before, after EndpointResponse)
}

type EndpointResponse struct {
	// Whether to include the result in the final aggregated data set. For Calico->Calico endpoint flows we may need to
	// massage the data a little:
	// - For source-reported flows whose action changes from denied to allowed or unknown, we explicitly add the
	//   equivalent data at the destination, since the associated flow data should be missing from the original set.
	// - For destination-reported flows whose source action changes from allowed->denied, we remove the flow completely
	//   as it should not get reported.
	// This means the calculation response can have 0, 1 or 2 results to include in the aggregated data.
	Include bool

	// The calculated action flags at the endpoint for the supplied flow.  This can be a combination of ActionFlagAllow
	// and/or ActionFlagDeny with any of ActionFlagFlowLogMatchesCalculated, ActionFlagFlowLogRemovedUncertainty and
	// ActionFlagFlowLogConflictsWithCalculated.
	Action api.ActionFlag

	// The set of policies applied to this flow.
	Policies OrderedPolicyHits
}

type OrderedPolicyHits []api.PolicyHit

func (o OrderedPolicyHits) FlowLogPolicyStrings() []string {
	s := make([]string, 0, len(o))
	for i := range o {
		s = append(s, o[i].ToFlowLogPolicyString())
	}
	return s
}

// policyCalculator implements the PolicyCalculator interface.
type policyCalculator struct {
	Config    *pipcfg.Config
	Selectors *EndpointSelectorHandler
	Endpoints *EndpointCache
	Ingress   CompiledTierAndPolicyChangeSet
	Egress    CompiledTierAndPolicyChangeSet
}

// NewPolicyCalculator returns a new PolicyCalculator.
func NewPolicyCalculator(
	cfg *pipcfg.Config,
	endpoints *EndpointCache,
	resourceDataBefore *ResourceData,
	resourceDataAfter *ResourceData,
	impacted ImpactedResources,
) PolicyCalculator {
	// Create the selector handler. This is shared by both the before and after matcher factories - this is fine because
	// the labels on the endpoints are not being adjusted, and so a selector will return the same value in the before
	// and after configurations.
	selectors := NewEndpointSelectorHandler()

	// Calculate the before/after ingress/egress compiled tier and policy data.
	ingressBefore, egressBefore := calculateCompiledTiersAndImpactedPolicies(cfg, resourceDataBefore, impacted, selectors, false)
	ingressAfter, egressAfter := calculateCompiledTiersAndImpactedPolicies(cfg, resourceDataAfter, impacted, selectors, true)

	// Create the policyCalculator.
	return &policyCalculator{
		Config:    cfg,
		Selectors: selectors,
		Endpoints: endpoints,
		Ingress: CompiledTierAndPolicyChangeSet{
			Before: ingressBefore,
			After:  ingressAfter,
		},
		Egress: CompiledTierAndPolicyChangeSet{
			Before: egressBefore,
			After:  egressAfter,
		},
	}
}

// CalculateSource calculates the action before and after the configuration change for a specific source reported flow.
// This method may be called simultaneously from multiple go routines for different flows if required. If the source
// action changes from deny to allow then we also have to calculate the destination action since we will not have flow
// data to work from.
func (fp *policyCalculator) CalculateSource(flow *api.Flow) (modified bool, before, after EndpointResponse) {
	return fp.calculateBeforeAfterResponse(flow, &fp.Egress, true, 0, 0)
}

// Calculate calculates the action before and after the configuration change for a specific destination reported flow.
// This method may be called simultaneously from multiple go routines for different flows if required.
func (fp *policyCalculator) CalculateDest(flow *api.Flow, sourceActionBefore, sourceActionAfter api.ActionFlag) (modified bool, before, after EndpointResponse) {
	return fp.calculateBeforeAfterResponse(flow, &fp.Ingress, false, sourceActionBefore, sourceActionAfter)
}

// calculateBeforeAfterResponse calculates the action before and after the configuration change for a specific reported
// flow.
func (fp *policyCalculator) calculateBeforeAfterResponse(
	flow *api.Flow, changeset *CompiledTierAndPolicyChangeSet, isSrc bool, beforeSrcAction, afterSrcAction api.ActionFlag,
) (modified bool, before, after EndpointResponse) {
	var calculatedBefore EndpointResponse
	var usingCalculatedBefore bool

	// Initialize logger for this flow, and initialize selector caches.
	clog := log.WithFields(log.Fields{
		"reporter":        flow.Reporter,
		"sourceName":      flow.Source.Name,
		"sourceNamespace": flow.Source.Namespace,
		"destName":        flow.Destination.Name,
		"destNamespace":   flow.Destination.Namespace,
		"beforeSrcAction": beforeSrcAction,
		"afterSrcAction":  afterSrcAction,
	})

	// Initialize flow for the calculation.
	fp.initializeFlowForCalculations(flow)

	// Initialize the per-flow cache.
	cache := fp.newFlowCache(flow)

	// If the flow is not impacted return the unmodified response. Note that if ActionFlag is zero then this must be
	// an inserted flow due to a change of source action from deny to allow - we will have to recalculate in this
	// case even if the policy changes do not impact the ingress for the flow.
	// TODO: Should probably still run this through PIP to verify that the processor agrees.
	if flow.ActionFlag != 0 && !changeset.FlowSelectedByImpactedPolicies(flow, cache) {
		clog.Debug("Flow unaffected")
		if isSrc || beforeSrcAction&api.ActionFlagAllow != 0 {
			before = getUnchangedResponse(flow)
		}
		if isSrc || afterSrcAction&api.ActionFlagAllow != 0 {
			after = getUnchangedResponse(flow)
		}
		return beforeSrcAction != afterSrcAction, before, after
	}

	if isSrc || beforeSrcAction&api.ActionFlagAllow != 0 {
		// Calculate the before impact. We don't necessarily use the calculated value, but it pre-populates the cache for
		// the after response.
		// Note that we don't calculate the before impact if this is a destination reported flow and the flow was denied
		// at source.
		clog.Debug("Calculate before impact")
		calculatedBefore = changeset.Before.Calculate(flow, cache, true)

		if ActualFlowAction(calculatedBefore.Action) == ActualFlowAction(flow.ActionFlag) &&
			(len(flow.Policies) == 0 || PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(flow.Policies, calculatedBefore.Policies)) {
			// The original and calculated before actions are the same and the policies match. Use the calculated set
			// of policies to avoid duplications and to ensure ordering agrees with the current configuration.  This
			// also fills in the blanks when the policy data was not in the original flow data.
			clog.Debug("Calculated flow matches original after ignoring duplicate and staged policies")
			before = calculatedBefore
			usingCalculatedBefore = true
		} else if !fp.Config.CalculateOriginalAction {
			// We are not configured to calculate the original action, so revert back to use the data from the flow.
			clog.Debug("Use original flow data for before response")
			before = getUnchangedResponse(flow)

			// Sort the original set of flows so that we can compare to the "after" set to see if anything has actually
			// changed. We don't need to sort the calculated policies since these will already be sorted.
			sort.Sort(api.SortablePolicyHits(before.Policies))
		} else {
			clog.Debug("Calculated flow does not match original but configured to recalculate before flows")
			before = calculatedBefore
			usingCalculatedBefore = true
		}
	}

	if isSrc || afterSrcAction&api.ActionFlagAllow != 0 {
		// Calculate the after impact.
		clog.Debug("Calculate after impact")
		after = changeset.After.Calculate(flow, cache, false)
	}

	if log.IsLevelEnabled(log.DebugLevel) {
		if before.Include {
			clog.WithFields(log.Fields{
				"calculatedBeforeAction":   before.Action,
				"calculatedBeforePolicies": before.Policies,
			}).Debug("Including flow before")
		} else {
			clog.Debug("Not including flow before")
		}
		if after.Include {
			clog.WithFields(log.Fields{
				"calculatedAfterAction":   after.Action,
				"calculatedAfterPolicies": after.Policies,
			}).Debug("Including flow after")
		} else {
			clog.Debug("Not including flow after")
		}
	}

	modified = before.Include != after.Include ||
		ActualFlowAction(before.Action) != ActualFlowAction(after.Action) ||
		!PolicyHitsEqualIgnoringStaged(before.Policies, after.Policies)

	if modified && log.IsLevelEnabled(log.DebugLevel) {
		log.Debug("|> ====== IMPACTED FLOW START ======")
		log.Debugf("|> %s/%s -> %s/%s", flow.Source.Namespace, flow.Source.Name, flow.Destination.Namespace, flow.Destination.Name)
		log.Debugf("|> Reporter: %s", flow.Reporter)
		log.Debugf("|> Original source labels: %v", flow.Source.Labels)
		log.Debugf("|> Original destination labels: %v", flow.Destination.Labels)
		if before.Include {
			log.Debug("|> Before")
			log.Debugf("|>   Actions: %s", strings.Join(before.Action.ToActionStrings(), ", "))
			log.Debugf("|>   Policies: %s", strings.Join(before.Policies.FlowLogPolicyStrings(), ", "))
		}
		if !usingCalculatedBefore && calculatedBefore.Include {
			log.Debug("|> Calculated Before")
			log.Debugf("|>   Actions: %s", strings.Join(calculatedBefore.Action.ToActionStrings(), ", "))
			log.Debugf("|>   Policies: %s", strings.Join(calculatedBefore.Policies.FlowLogPolicyStrings(), ", "))
		}
		if after.Include {
			log.Debug("|> Calculated After")
			log.Debugf("|>   Actions: %s", strings.Join(after.Action.ToActionStrings(), ", "))
			log.Debugf("|>   Policies: %s", strings.Join(after.Policies.FlowLogPolicyStrings(), ", "))
		}
		log.Debug("|> ====== IMPACTED FLOW END ======")
	}

	return modified, before, after
}

func (fp *policyCalculator) initializeFlowForCalculations(flow *api.Flow) {
	// If either source or destination are calico endpoints initialize the selector cache and use the datastore cache to
	// augment the flow data (if some data is missing).
	if flow.Source.IsCalicoManagedEndpoint() {
		if ed := fp.Endpoints.Get(flow.Source.Namespace, flow.Source.Name); ed != nil {
			log.Debug("Found source endpoint in cache")

			if flow.Source.ServiceAccount == nil {
				log.Debugf("Augmenting source endpoint flow data with cached service account: %v", ed.ServiceAccount)
				flow.Source.ServiceAccount = ed.ServiceAccount
			}

			if flow.Source.NamedPorts == nil {
				log.Debugf("Augmenting source endpoint flow data with cached named ports: %v", ed.NamedPorts)
				flow.Source.NamedPorts = ed.NamedPorts
			}

			if flow.Source.Labels.Len() == 0 {
				log.Debugf("Augmenting source endpoint flow data with cached labels: %v", ed.Labels)
				flow.Source.Labels = ed.Labels
			}
		}
	}
	if flow.Destination.IsCalicoManagedEndpoint() {
		if ed := fp.Endpoints.Get(flow.Destination.Namespace, flow.Destination.Name); ed != nil {
			log.Debug("Found destination endpoint in cache")

			if flow.Destination.ServiceAccount == nil {
				log.Debugf("Augmenting destination endpoint flow data with cached service account: %v", ed.ServiceAccount)
				flow.Destination.ServiceAccount = ed.ServiceAccount
			}

			if flow.Destination.NamedPorts == nil {
				log.Debugf("Augmenting destination endpoint flow data with cached named ports: %v", ed.NamedPorts)
				flow.Destination.NamedPorts = ed.NamedPorts
			}

			if flow.Destination.Labels.Len() == 0 {
				log.Debugf("Augmenting destination endpoint flow data with cached labels: %v", ed.Labels)
				flow.Destination.Labels = ed.Labels
			}
		}
	}
}

func (fp *policyCalculator) newFlowCache(flow *api.Flow) *flowCache {
	flowCache := &flowCache{}

	// Initialize the caches if required.
	if !flow.Source.Labels.IsNil() {
		flowCache.source.selectors = fp.CreateSelectorCache()
	}
	if !flow.Destination.Labels.IsNil() {
		flowCache.destination.selectors = fp.CreateSelectorCache()
	}
	flowCache.policies = make(map[model.ResourceKey]api.ActionFlag)
	return flowCache
}

// CreateSelectorCache creates the match type slice used to cache selector calculations for a particular flow
// endpoint.
func (fp *policyCalculator) CreateSelectorCache() []MatchType {
	return fp.Selectors.CreateSelectorCache()
}

// getUnchangedSourceResponse returns a policy calculation Response based on the original source flow data.
func getUnchangedResponse(f *api.Flow) EndpointResponse {
	// Filter out staged policies from the original data.
	var filtered []api.PolicyHit
	for _, p := range f.Policies {
		if !p.IsStaged() {
			filtered = append(filtered, p)
		}
	}

	return EndpointResponse{
		Include:  true,
		Action:   f.ActionFlag,
		Policies: filtered,
	}
}

// CompiledTierAndPolicyChangeSet contains the before/after tier and policy data for a given flow direction (i.e.
// ingress or egress).
type CompiledTierAndPolicyChangeSet struct {
	// The compiled set of tiers and policies before the change.
	Before CompiledTiersAndImpactedPolicies

	// The compiled set of tiers and policies after the change.
	After CompiledTiersAndImpactedPolicies
}

// FlowSelectedByImpactedPolicies returns whether the flow is selected by any of the impacted policies before or after
// the change is applied.
func (c CompiledTierAndPolicyChangeSet) FlowSelectedByImpactedPolicies(flow *api.Flow, cache *flowCache) bool {
	return c.Before.FlowSelectedByImpactedPolicies(flow, cache) || c.After.FlowSelectedByImpactedPolicies(flow, cache)
}

// PolicyHitsEqualIgnoringOrderDuplicatesAndStaged compares two sets of PolicyHits to see if the set of matches is
// identical. This ignores the match index, staged policies and surplus policies in the dirty set. This means the match
// is somewhat fuzzy, but makes it simpler to compare before and after flows when the flow is long running and contains
// data from old connections.
func PolicyHitsEqualIgnoringOrderDuplicatesAndStaged(dirty, calculated []api.PolicyHit) bool {
	// Get the set of policy names and actions. This removes duplicates with different match indexes.
	dirtyActions := map[string]api.ActionFlag{}
	for _, p := range dirty {
		if p.IsStaged() {
			log.Debug("Skip staged in dirty set")
			continue
		}
		name := p.FlowLogName()
		action := ActualPolicyHitAction(p.Action().ToFlag())
		if af, ok := dirtyActions[name]; ok {
			if af != action {
				// Flow has multiple actions for the same policy. This can never match the calculated.
				log.WithField("name", name).Debug("Flow contains identical policy matches with different actions")
				return false
			}
		} else {
			dirtyActions[name] = action
		}
	}

	// Check the calculated hits against the dirty hits (ignoring staged policies).
	for _, p := range calculated {
		if p.IsStaged() {
			log.Debug("Skip staged in calculated set")
			continue
		}
		name := p.FlowLogName()
		action := ActualPolicyHitAction(p.Action().ToFlag())
		if af, ok := dirtyActions[name]; !ok {
			log.WithField("name", name).Debug("No matching policy")
			return false
		} else if af != action {
			log.WithFields(log.Fields{
				"policy":     name,
				"dirty":      af,
				"calculated": action,
			}).Debug("No matching action")
			return false
		}
	}

	return true
}

// PolicyHitsEqualIgnoringStaged compares two sets of PolicyHits to see if the set of matches is identical.
// This ignores staged policies, but otherwise the policies and their order should be identical.
func PolicyHitsEqualIgnoringStaged(before, after []api.PolicyHit) bool {
	next := func(idx int, p []api.PolicyHit) int {
		for ; idx < len(p); idx++ {
			if !p[idx].IsStaged() {
				return idx
			}
		}
		return -1
	}

	var beforeIdx, afterIdx int
	for {
		beforeIdx, afterIdx = next(beforeIdx, before), next(afterIdx, after)
		if beforeIdx == -1 || afterIdx == -1 {
			break
		}
		if ActualPolicyHitAction(before[beforeIdx].Action().ToFlag()) != ActualPolicyHitAction(after[afterIdx].Action().ToFlag()) ||
			before[beforeIdx].FlowLogName() != after[afterIdx].FlowLogName() {
			// Either the action or policy do not match. Return false.
			return false
		}

		// Increment to the next policy hit.
		beforeIdx++
		afterIdx++
	}

	// We exit the loop when we have reached the end of a policy hit slice. If we reached the end of both then the
	// match is successful.
	return beforeIdx == afterIdx
}
