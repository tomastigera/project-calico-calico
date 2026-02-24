// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package elastic

import (
	"sort"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/lma/pkg/rbac"
)

// FlowFilter interface is used by the composite aggregation flow enuemeration to perform additional filtering and
// processing of the flow.
type FlowFilter interface {
	IncludeLinseedFlow(flow *lapi.L3Flow) (include bool, err error)
	IncludeFlow(flow *CompositeAggregationBucket) (include bool, err error)
	ModifyFlow(flow *CompositeAggregationBucket) error
}

// NewFlowFilterIncludeAll returns a FlowFilter that filters in all flows and does not modify the flow.
func NewFlowFilterIncludeAll() FlowFilter {
	return &flowFilterIncludeAll{}
}

// NewFlowFilterUserRBAC returns a FlowFilter that filters out flows and obfuscates policies based on users RBAC.
func NewFlowFilterUserRBAC(r rbac.FlowHelper) FlowFilter {
	return &flowFilterUserRBAC{r}
}

// flowFilterIncludeAll implements the flow filter interface, including all flows and not modifying the flow.
type flowFilterIncludeAll struct{}

func (f *flowFilterIncludeAll) IncludeFlow(flow *CompositeAggregationBucket) (include bool, err error) {
	return true, nil
}

func (f *flowFilterIncludeAll) ModifyFlow(flow *CompositeAggregationBucket) error {
	return nil
}

func (f *flowFilterIncludeAll) IncludeLinseedFlow(flow *lapi.L3Flow) (include bool, err error) {
	return true, nil
}

// flowFilterUserRBAC implements the flow filter interface. It limits the returned flows to those containing endpoints
// that the user can list, and obfuscates policies based which ones the user can list.
type flowFilterUserRBAC struct {
	r rbac.FlowHelper
}

// Deprecated: Use IncludeLinseedFlow where possible.
func (f *flowFilterUserRBAC) IncludeFlow(flow *CompositeAggregationBucket) (include bool, err error) {
	// Check if user is able to list either endpoint.  If they cannot list either endpoint then exclude the flow.
	if canList, err := f.canListEndpoint(
		flow.CompositeAggregationKey, FlowCompositeSourcesIdxSourceType, FlowCompositeSourcesIdxSourceNamespace,
	); err != nil {
		return false, err
	} else if canList {
		return true, nil
	} else if canList, err = f.canListEndpoint(
		flow.CompositeAggregationKey, FlowCompositeSourcesIdxDestType, FlowCompositeSourcesIdxDestNamespace,
	); err != nil {
		return false, err
	} else if canList {
		return true, nil
	}
	return false, nil
}

func (f *flowFilterUserRBAC) IncludeLinseedFlow(flow *lapi.L3Flow) (include bool, err error) {
	// Check if user is able to list either endpoint.  If they cannot list either endpoint then exclude the flow.
	if canList, err := f.r.CanListEndpoint(api.EndpointType(flow.Key.Source.Type), EmptyToDash(flow.Key.Source.Namespace)); err != nil {
		return false, err
	} else if canList {
		return true, nil
	}
	if canList, err := f.r.CanListEndpoint(api.EndpointType(flow.Key.Destination.Type), EmptyToDash(flow.Key.Destination.Namespace)); err != nil {
		return false, err
	} else if canList {
		return true, nil
	}
	return false, nil
}

// ModifyFlow implements the FlowFilter interface.
func (f *flowFilterUserRBAC) ModifyFlow(flow *CompositeAggregationBucket) error {
	// Default behavior is to obfuscate the policies.
	return f.obfuscatePolicies(flow)
}

// ObfuscatePolicies implements the RBACHelper interface.
func (f *flowFilterUserRBAC) obfuscatePolicies(flow *CompositeAggregationBucket) error {
	var matchIdx int
	var obfuscatedPass api.PolicyHit

	// Extract the policies from the bucket.
	term := flow.AggregatedTerms[FlowAggregatedTermsNamePolicies]
	newBuckets := make(map[any]int64)
	policies := GetFlowPoliciesFromAggTerm(term)

	// Sort the policies so that we can obfuscate and group multiple obfuscated entries together.
	sort.Sort(api.SortablePolicyHits(policies))

	// Loop through the policies, updating as we go.
	for readIdx := range policies {
		policy := policies[readIdx]

		if canList, err := f.r.CanListPolicy(policy); err != nil {
			return err
		} else if canList {
			if obfuscatedPass != nil {
				// Store the obfuscated pass with the same doc count as the original pass.
				newBuckets[api.ObfuscatedPolicyString(matchIdx, api.ActionNextTier)] = obfuscatedPass.Count()
				matchIdx++
				obfuscatedPass = nil
			}

			// Store the unobfuscated policy, just need to update the match index.
			policy = policy.SetIndex(matchIdx)
			newBuckets[policy.ToFlowLogPolicyString()] = policy.Count()
			matchIdx++
		} else if policy.IsStaged() {
			// Skip staged policies that we do not have permissions to list.
			continue
		} else if policy.Action() == api.ActionNextTier {
			// This is a pass, we need to obfuscate, but don't do that just yet, we'll contract multiple obfuscated
			// entries into one.
			obfuscatedPass = policy
		} else {
			// Store the obfuscated action with the same doc count as the original action. If there was one or more
			// previous obfuscated passes then contract those into this obfuscated action.
			newBuckets[api.ObfuscatedPolicyString(matchIdx, policy.Action())] = policy.Count()
			matchIdx++
			obfuscatedPass = nil
		}
	}

	// Update the buckets.
	term.Buckets = newBuckets

	return nil
}

// canListEndpoint determines if an endpoint can be listed.
func (f *flowFilterUserRBAC) canListEndpoint(k CompositeAggregationKey, epTypeIdx, nsIdx int) (bool, error) {
	epType := GetFlowEndpointTypeFromCompAggKey(k, epTypeIdx)
	namespace := k[nsIdx].String()
	return f.r.CanListEndpoint(epType, namespace)
}
