package policycalc

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/lma/pkg/api"
	pipcfg "github.com/projectcalico/calico/ui-apis/pkg/pip/config"
)

// rule id index equals -1 for end-of-tier deny.
const ruleIdIndexEndOfTierDeny = -1

// calculateCompiledTiersAndImpactedPolicies compiles the Tiers and policies and returns ingress and egress sets of
// -  The compiled tiers (With policies)
// -  The set of policies that are impacted by a resource update.
func calculateCompiledTiersAndImpactedPolicies(
	cfg *pipcfg.Config,
	rd *ResourceData,
	impacted ImpactedResources,
	sel *EndpointSelectorHandler,
	changesApplied bool,
) (ingress, egress CompiledTiersAndImpactedPolicies) {
	// Create the namespace handler, and populate from the Namespaces and ServiceAccounts.
	log.Debugf("Creating namespace handler with %d namespaces and %d service accounts", len(rd.Namespaces), len(rd.ServiceAccounts))
	namespaces := NewNamespaceHandler(rd.Namespaces, rd.ServiceAccounts)

	// Create a new matcher factory which is used to create Matcher functions for the compiled policies.
	matcherFactory := NewMatcherFactory(cfg, namespaces, sel)

	// Iterate through tiers.
	for i, tier := range rd.Tiers {
		log.Debugf("Compiling tier (idx %d)", i)
		var ingressTier, egressTier CompiledTier

		// Iterate through the policies in a tier.
		for _, pol := range tier {
			// Determine the impact of this policy.
			impact, isImpacted := impacted.Impact(pol.ResourceID)

			// If this is set of data with changes applied, pass the impact associated with the policy when compiling
			// it.
			var actualImpact Impact
			if changesApplied {
				actualImpact = impact
			}

			// If this is an impacted policy, and the changes are being applied, then we always "enforce" the policy.
			previewingChange := changesApplied && isImpacted

			// Compile the policy to get the ingress and egress versions of the policy as appropriate.
			ingressPol, egressPol := compilePolicy(matcherFactory, pol, actualImpact, previewingChange)

			// Add the ingress and egress policies to their respective slices. If this is a impacted policy, also
			// track it - we'll use this as a shortcut to determine if a flow is possibly affected by the configuration
			// change or not. We do this for both the pre and post updated resources.
			if ingressPol != nil {
				ingressTier = append(ingressTier, ingressPol)
				if isImpacted {
					// If resource is impacted include this policy. We do this for original and changed resources.
					log.Debugf("This is an impacted ingress policy: deleted:%v; modified:%v",
						actualImpact.Deleted, actualImpact.Modified)
					ingress.ImpactedPolicies = append(ingress.ImpactedPolicies, ingressPol)
				}
			}
			if egressPol != nil {
				egressTier = append(egressTier, egressPol)
				if isImpacted {
					// If resource is impacted include this policy. We do this for original and changed resources.
					log.Debugf("This is an impacted egress policy: deleted:%v; modified:%v",
						actualImpact.Deleted, actualImpact.Modified)
					egress.ImpactedPolicies = append(egress.ImpactedPolicies, egressPol)
				}
			}
		}

		// Append the ingress and egress tiers if any policies were added to them.
		if ingressTier != nil {
			ingress.Tiers = append(ingress.Tiers, ingressTier)
		}
		if egressTier != nil {
			egress.Tiers = append(egress.Tiers, egressTier)
		}
	}

	return
}

// CompiledTiersAndImpactedPolicies contains a set of compiled tiers and impacted policies for a single flow direction
// (i.e. ingress or egress).
type CompiledTiersAndImpactedPolicies struct {
	// IngressTiers is the set of compiled tiers and policies, containing only ingress rules. Policies that do not
	// apply to ingress flows are filtered out, and tiers are omitted if all policies were filtered out.
	Tiers CompiledTiers

	// ImpactedEgressPolicies is the set of compiled policies containing egress rules that were impacted by the
	// resource update, either through resource modification, or previewing a staged policy.
	ImpactedPolicies []*CompiledPolicy
}

// FlowSelectedByModifiedEgressPolicies returns whether the flow is selected by any of the impacted policies.
func (c *CompiledTiersAndImpactedPolicies) FlowSelectedByImpactedPolicies(flow *api.Flow, cache *flowCache) bool {
	log.Debug("Checking impacted polices")
	for i := range c.ImpactedPolicies {
		log.Debugf("Checking impacted policy: %s", c.ImpactedPolicies[i].Key())
		if c.ImpactedPolicies[i].Applies(flow, cache) == MatchTypeTrue {
			return true
		}
	}
	return false
}

// Calculate determines the action and policy path for a specific flow on this compiled set of tiers and policies.
func (c *CompiledTiersAndImpactedPolicies) Calculate(flow *api.Flow, cache *flowCache, before bool) (r EndpointResponse) {
	// If the source endpoint is a Calico endpoint and this is reported by source then calculate egress. If the
	// action changes from deny in the original flow to either allow or unknown then we need to calculate for the
	// destination ingress too.
	if flow.Source.IsCalicoManagedEndpoint() && flow.Reporter == api.ReporterTypeSource {
		// Calculate egress.
		log.Debug("Calculating egress action")
		r = c.Tiers.Calculate(flow, &flow.Source, cache, before)
	} else if flow.Destination.IsCalicoManagedEndpoint() && flow.Reporter == api.ReporterTypeDestination {
		log.Debug("Calculating ingress action")
		r = c.Tiers.Calculate(flow, &flow.Destination, cache, before)
	}
	return
}

// CompiledTiers contains a set of compiled tiers and policies for either ingress or egress.
type CompiledTiers []CompiledTier

// Calculate determines the policy impact of the tiers for the supplied flow.
func (ts CompiledTiers) Calculate(flow *api.Flow, ep *api.FlowEndpointData, cache *flowCache, before bool) EndpointResponse {
	var af api.ActionFlag
	epr := EndpointResponse{Include: true}
	for i := range ts {
		// Calculate the set of action flags for the tier. The before/after calculation are handled separately so fan
		// off accordingly.
		if before {
			af |= ts[i].ActionBefore(flow, &epr, cache)
		} else {
			af |= ts[i].ActionAfter(flow, &epr, cache)
		}

		if Indeterminate(af) {
			// The flags now indicate the action is indeterminate, exit immediately. Store the action in the response
			// object.
			log.Debug("Indeterminate action from this tier - stop further processing")
			epr.Action = af
			return epr
		}

		if af&api.ActionFlagNextTier == 0 {
			// The next tier flag was not set, so we are now done. Since the action is not unknown, then we should
			// have a concrete allow or deny action at this point. Note that whilst the uncertain flag may be set
			// all of the possible paths have resulted in the same action. Store the action in the response object.
			log.Debug("Not required to enumerate next tier - must have final action")
			epr.Action = af
			return epr
		}

		// Clear the pass and tier match flags before we skip to the next tier.
		af &^= api.ActionFlagNextTier
	}

	// -- END OF TIERS --
	// This is Allow for Pods, and Deny for HEPs.
	log.Debug("Hit end of tiers")
	var k model.ResourceKey
	var actionFlag api.ActionFlag
	if ep.Type == api.EndpointTypeWep {
		// End of tiers allow is handled by the namespace profile. Add the policy name for this and set the allow flag.
		k = model.ResourceKey{
			Kind: "Profile",
			Name: "kns." + ep.Namespace,
		}
		actionFlag = api.ActionFlagAllow
	} else {
		// End of tiers deny is handled implicitly by Felix and has a very specific pseudo-profile name.
		k = model.ResourceKey{
			Kind: "Profile",
			Name: "__NO_MATCH__",
		}
		actionFlag = api.ActionFlagDeny
	}

	// If the calculated values are thus far corroborated by the flow logs then check to see if the end-of-tiers is
	// also corroborated.
	if af&ActionFlagsVerified != 0 {
		if flagsFromFlowLog, ok := getFlagsFromFlowLog(k, flow); ok {
			log.Debugf("End-of-tiers action flags found in flow log %d", flagsFromFlowLog)

			if flagsFromFlowLog&actionFlag != 0 {
				log.Debug("Calculated matches flow log")
				actionFlag |= ActionFlagFlowLogMatchesCalculated
			} else {
				log.Debug("Calculated conflicts with flow log")
				actionFlag |= ActionFlagFlowLogConflictsWithCalculated
			}
		}
	}

	addPolicyToResponse(&epr, "__PROFILE__", k, actionFlag, true, &af)

	// Store the action in the response object.
	epr.Action = af
	return epr
}

// CompiledTier contains a set of compiled policies for a specific tier, for either ingress _or_ egress.
type CompiledTier []*CompiledPolicy

// ActionBefore returns the calculated action for the tier for the supplied flow on the initial set of config.
//
// In this "before" processing, calculated flow hits are cross referenced against the flow log policy hits to provide
// additional certainty, and in the cases where the calculation was not possible to infer the result from the
// measured data.
func (tier CompiledTier) ActionBefore(flow *api.Flow, r *EndpointResponse, cache *flowCache) api.ActionFlag {
	// In the before branch we track unverifiedNoMatches no-matches. We process these after getting additional confirmation
	// (or not) from the flow logs.
	var unverifiedNoMatches []*CompiledPolicy
	var flowLogsInconsistentWithCalculation bool
	var lastEnforcedPolicy *CompiledPolicy
	var lastEnforcedActions api.ActionFlag
	var combinedPolicyActions api.ActionFlag
	for _, p := range tier {
		policyKey := p.Key()
		log.Debugf("Process policy: %+v", policyKey)

		// If the policy does not apply to this Endpoint then skip to the next policy.
		if p.Applies(flow, cache) != MatchTypeTrue {
			log.Debug("Policy does not apply - skipping")
			continue
		}
		// TODO(rlb): We may want to handle unknown selector matches if we decide to be a little more clever about our
		//           label aggregation.

		// Calculate the policy action. This will set at least one action flag.
		policyActions := p.Action(flow, cache)

		// This is the before run, so assumed the policy is not modified in relation to the flow logs data. Use the flow
		// log data to augment the calculated action.
		if flagsFromFlowLog, ok := getFlagsFromFlowLog(policyKey, flow); ok {
			log.Debugf("Policy action flags found in flow log %d", flagsFromFlowLog)

			// An end-of-tier deny flag actually means the policy was a no-match, so convert the flag to be no match
			// since that's what we need to cache (in the after processing it may no longer be an end-of-tier drop).
			if flagsFromFlowLog == api.ActionFlagEndOfTierDeny {
				log.Debug("Found end of tier drop matching policy - cache as no-match")
				flagsFromFlowLog = ActionFlagNoMatch
			} else if flagsFromFlowLog == api.ActionFlagDeny && policyActions&api.ActionFlagDeny == 0 && policyActions&ActionFlagNoMatch != 0 {
				// TODO(rlb): Fix in flow logs by returning an end of tier deny action value
				log.Debug("Found a deny action in flow logs, but not a valid action - treat as end of tier deny")
				flagsFromFlowLog = ActionFlagNoMatch
			}

			if flagsFromFlowLog&policyActions == 0 {
				// The action in the flow log does not agree with any of the calculated actions in the policy.
				log.Debugf("Policy action found in flow log conflicts with calculated: flagsFromFlowLog: %d; policyActions: %d",
					flagsFromFlowLog, policyActions)
				policyActions |= ActionFlagFlowLogConflictsWithCalculated
			} else if policyActions&ActionFlagsAllCalculatedPolicyActions == flagsFromFlowLog {
				log.Debugf("Policy action found in flow log exactly matches calculated")
				policyActions |= ActionFlagFlowLogMatchesCalculated
			} else {
				log.Debugf("Policy action found in flow log agrees with calculated - use to break uncertainty")
				policyActions = flagsFromFlowLog | ActionFlagFlowLogRemovedUncertainty
			}
		}

		// Cache the value so that we don't have to recalculate in the "after" processing.
		cache.policies[policyKey] = policyActions

		if p.Enforced {
			// Track the last enforced policy - we use this for end-of-tier drop processing.
			log.Debug("Policy is enforced - store policy and action flags")
			lastEnforcedPolicy = p
			lastEnforcedActions = policyActions
		}

		// If flow log data is self-consistent with the calculation then we can use the flow data to firm up
		// uncertain or no-matches.
		if flowLogsInconsistentWithCalculation {
			// Flow log data is inconsistent. Add the policy match immediately since there is no need to wait for
			// verification now.
			log.Debug("Flow log data is inconsistent with calculation")
			addPolicyToResponse(r, p.Tier, p.Key(), policyActions, p.Enforced, &combinedPolicyActions)
		} else if policyActions&(ActionFlagFlowLogMatchesCalculated|ActionFlagFlowLogRemovedUncertainty) != 0 {
			// The policy calculation was corroborated by the flow log data.
			log.Debug("Calculated action was corroborated by the flow log policies")

			// The unverified no matches can now be considered verified.
			for _, n := range unverifiedNoMatches {
				log.Debugf("Confirm no match for %+v", n.Key())
				prev := cache.policies[n.Key()]
				if prev == ActionFlagNoMatch {
					cache.policies[n.Key()] = ActionFlagNoMatch | ActionFlagFlowLogMatchesCalculated
				} else {
					cache.policies[n.Key()] = ActionFlagNoMatch | ActionFlagFlowLogRemovedUncertainty
				}
			}
			unverifiedNoMatches = nil

			// Add the policy to the response immediately. The action may be a no-match in which case nothing will get
			// added. if this the last enforced policy then processing outside the loop will add it as an end-of-tier
			// drop.
			addPolicyToResponse(r, p.Tier, p.Key(), policyActions, p.Enforced, &combinedPolicyActions)
		} else if policyActions&ActionFlagNoMatch != 0 {
			// This policy is an unverified no-match, track it - a future policy and corresponding flow log may
			// verify that this is really a no-match.
			log.Debug("Policy is no-match or uncertain no-match - track for later verification")
			unverifiedNoMatches = append(unverifiedNoMatches, p)
		} else {
			// This is an unverified match, which means flow log data and calculation are inconsistent.
			log.Debug("Policy is not a no-match, and has no corroborating flow log data")
			flowLogsInconsistentWithCalculation = true

			// Add the stored unverified no match policies to the response. Since addPolicyToResponse only adds
			// allow/deny/pass actions, any definite no-match will not add any policy entry.
			for _, n := range unverifiedNoMatches {
				log.Debugf("Add policy to response: %+v", n.Key())
				addPolicyToResponse(r, n.Tier, n.Key(), cache.policies[n.Key()], n.Enforced, &combinedPolicyActions)
			}
			unverifiedNoMatches = nil

			// And add this policy to the response.
			addPolicyToResponse(r, p.Tier, p.Key(), policyActions, p.Enforced, &combinedPolicyActions)
		}

		// If this is enforced and is not a no-match then exit.
		if p.Enforced && policyActions&ActionFlagNoMatch == 0 {
			log.Debugf("Policy is enforced and matches: %+v", policyKey)
			break
		}
	}

	if lastEnforcedPolicy == nil {
		// This flow didn't apply to any policy in this tier, so go to the next tier.  If there were any unverified
		// no matches then they must be for staged policies. We can firm up any unverified no matches.
		for _, n := range unverifiedNoMatches {
			log.Debugf("Confirm no match for %+v", n.Key())
			prev := cache.policies[n.Key()]
			if prev == ActionFlagNoMatch {
				cache.policies[n.Key()] = ActionFlagNoMatch | ActionFlagFlowLogMatchesCalculated
			} else {
				cache.policies[n.Key()] = ActionFlagNoMatch | ActionFlagFlowLogRemovedUncertainty
			}
		}

		log.Debug("Did not match tier - enumerate next tier")
		return api.ActionFlagNextTier
	}

	// At this point, we have a match that has not been corroborated by the flow logs. All we can do is include all of
	// the possible hits from this tier which may include multiple hits from the same policy and multiple policies. We
	// do not include staged policies nor do we include the last enforced policy which we handle explicitly.
	log.Debug("Final enforced policy action was not corroborated by the flow log policies")
	for _, n := range unverifiedNoMatches {
		// Add each possible action to the flow policy hits.
		noMatchPolicyActions := cache.policies[n.Key()]
		addPolicyToResponse(r, lastEnforcedPolicy.Tier, n.Key(), noMatchPolicyActions, n.Enforced, &combinedPolicyActions)
	}

	if lastEnforcedActions&ActionFlagNoMatch != 0 {
		// The last enforced policy included a no-match flag. This must be the last enforced policy in the tier because
		// we'd otherwise exit as soon as we get an exactly matched rule. We need to convert the no-match to an
		// end-of-tier drop. Assign the verification flags that we have from the cache for the no-match entry.
		log.Debug("Final policy included a no-match, include the end of tier action")
		verificationFlags := cache.policies[lastEnforcedPolicy.Key()] & ActionFlagsMeasured
		addPolicyToResponse(
			r,
			lastEnforcedPolicy.Tier,
			lastEnforcedPolicy.Key(),
			api.ActionFlagEndOfTierDeny|verificationFlags,
			true,
			&combinedPolicyActions,
		)
	}

	// Return the combined set of actions.
	return combinedPolicyActions
}

// ActionAfter returns the calculated action for the tier for the supplied flow.
// A previous tier/policy may have specified a possible match action which could not be confirmed due to lack of
// information. We supply the current action flags so that further enumeration can exit as soon as we either find
// an identical action with confirmed match, or a different action (confirmed or unconfirmed) that means we cannot
// determine the result with certainty.
func (tier CompiledTier) ActionAfter(flow *api.Flow, r *EndpointResponse, cache *flowCache) api.ActionFlag {
	var lastEnforcedPolicy *CompiledPolicy
	var lastEnforcedActions api.ActionFlag
	var combinedPolicyActions api.ActionFlag
	for _, p := range tier {
		log.Debugf("Process policy: %+v", p.Key())

		// If the policy does not apply to this Endpoint then skip to the next policy.
		if p.Applies(flow, cache) != MatchTypeTrue {
			log.Debug("Policy does not apply - skipping")
			continue
		}
		// TODO(rlb): We may want to handle unknown selector matches if we decide to be a little more clever about our
		//           label aggregation.

		// If the policy is not modified use the cached value if there is one, otherwise calculate.
		var actions api.ActionFlag
		if p.Modified {
			log.Debug("Policy is modified - calculate action")
			actions = p.Action(flow, cache)
		} else if cachedActions, ok := cache.policies[p.Key()]; ok {
			log.Debug("Use cached policy action")
			actions = cachedActions
		} else {
			log.Debug("No cached policy action - calculate")
			actions = p.Action(flow, cache)
		}

		// Add any policy matches.
		addPolicyToResponse(r, p.Tier, p.Key(), actions, p.Enforced, &combinedPolicyActions)

		// If this is enforced store the policy and actions, and if there was an exact match then exit.
		if p.Enforced {
			// Store the last enforced policy.
			lastEnforcedPolicy = p
			lastEnforcedActions = actions

			if actions&ActionFlagNoMatch == 0 {
				// Policy has an exactly matching rule so no need to enumerate further.
				log.Debug("Policy has an exactly matching rule")
				break
			}
		}
	}

	if lastEnforcedPolicy == nil {
		// This flow didn't apply to any policy in this tier, so go to the next tier.
		log.Debug("Did not match tier - enumerate next tier")
		return api.ActionFlagNextTier
	}

	if lastEnforcedActions&ActionFlagNoMatch != 0 {
		// The last enforced policy included a no-match flag. This must be the last enforced policy in the tier because
		// we'd otherwise exit as soon as we get an exactly matched rule. We need to convert the no-match to an
		// end-of-tier drop.
		log.Debug("Final policy included a no-match, include the end of tier action")
		var verificationFlags api.ActionFlag
		if !lastEnforcedPolicy.Modified {
			verificationFlags = cache.policies[lastEnforcedPolicy.Key()] & ActionFlagsMeasured
		}
		addPolicyToResponse(
			r,
			lastEnforcedPolicy.Tier,
			lastEnforcedPolicy.Key(),
			api.ActionFlagEndOfTierDeny|verificationFlags,
			true,
			&combinedPolicyActions,
		)
	}

	return combinedPolicyActions
}

// addPolicyToResponse adds a policy to the endpoint response. The action flags may indicate multiple possible
// outcomes when the calculation is uncertain. This may be a no-op if there are no concrete policy actions specified in
// the flags.
func addPolicyToResponse(r *EndpointResponse, tier string, k model.ResourceKey, flags api.ActionFlag, isEnforced bool, combinedFlags *api.ActionFlag) {
	if flags&ActionFlagsAllPolicyActions == 0 {
		return
	}
	log.Debugf("Add policy to flow: %s | %s | isEnforced=%v ", k.Name, flags.ToActionStrings(), isEnforced)
	if *combinedFlags == 0 {
		// This is the first policy. Set the measured bits first. This is used to provide some indication of the
		// accuracy of the calculation. The measurement flags are combined below for each consecutive policy hit.
		// Note that we track the measurement bits for both enforced and non-enforced policies since both provide
		// insight into whether the measured data agrees with the calculated.
		*combinedFlags |= (ActionFlagsMeasured & flags)
	}

	if isEnforced {
		// This flow is enforced, so update the concrete action flags for the flow.
		*combinedFlags |= (flags & ActionFlagsAllPolicyActions)
	}

	// Both enforced and non-enforced policy data provides input into the accuracy of the calculated result. Combine
	// the measurement flags which provide some indication of certainty.
	if *combinedFlags&ActionFlagFlowLogConflictsWithCalculated != 0 {
		// The flow action is flagged as conflicting with measured flow data - we don't update the flags any further.
	} else if flags&ActionFlagFlowLogConflictsWithCalculated != 0 {
		// This calculated policy conflicts with measured flow data - mark the flow as conflicting and removed the
		// verified flags if they were set.
		*combinedFlags = (*combinedFlags &^ ActionFlagsVerified) | ActionFlagFlowLogConflictsWithCalculated
	} else if flags&ActionFlagsVerified == 0 {
		// Action is not verified, so remove verification flags from combined action.
		*combinedFlags = (*combinedFlags &^ ActionFlagsVerified)
	} else if flags&ActionFlagFlowLogRemovedUncertainty != 0 && *combinedFlags&ActionFlagFlowLogMatchesCalculated != 0 {
		// Calculated policy removed uncertainty, but combined flags indicate matches calculated. Downgrade the
		// combined verified flag to indicatae removed uncertainty.
		*combinedFlags = (*combinedFlags &^ ActionFlagsVerified) | ActionFlagFlowLogRemovedUncertainty
	}

	// We set the staged indicator if the policy is not enforced. This means an enforced staged policy will not appear
	// as staged in the "after" policies - which is correct since we are previewing the effect of enforcing the staged
	// policy.
	staged := !isEnforced

	// Determine the match index. We increment it for each different policy - so uncertain matches for the same policy
	// will have the same match index.
	var matchIndex int
	if len(r.Policies) > 0 {
		lastPolicy := r.Policies[len(r.Policies)-1]
		matchIndex = lastPolicy.Index()
		if lastPolicy.Tier() != tier || lastPolicy.Namespace() != k.Namespace || lastPolicy.Name() != k.Name || lastPolicy.IsStaged() != staged {
			matchIndex++
		}
	}

	var ruleIdIndex *int
	for _, actionStr := range flags.ToActionStrings() {
		action := api.ActionFromString(actionStr)
		if action == api.ActionInvalid {
			log.Errorf("flag converted to invalid action")
			continue
		}
		// TODO(dimitrin): Remove the following action "eot-deny" redefinition to "deny". Remove the
		// ActionEndOfTierDeny from AllActions in lma. Define the rule id index while defining the
		// action.
		if action == api.ActionEndOfTierDeny {
			ruleIdIndex = new(int)
			*ruleIdIndex = -1
			action = api.ActionDeny
		}

		newPolicyHit, err := api.NewPolicyHit(action, 0, matchIndex, k.Name, k.Namespace, k.Kind, tier, ruleIdIndex)
		if err != nil {
			log.WithError(err).Errorf("failed to create new policy hit")
			continue
		}

		r.Policies = append(r.Policies, newPolicyHit)
	}
}

// TODO: CASEY: Fix matching here. This shouldn't be done based on the flow log name, but
// rather on the unique policy ID fields (kind, namespace, name).
//
// getFlagsFromFlowLog extracts the policy action flag from the flow log data.
func getFlagsFromFlowLog(k model.ResourceKey, flow *api.Flow) (api.ActionFlag, bool) {
	var policyAction api.Action
	fields := log.Fields{
		"policyKind":      k.Kind,
		"policyNamespace": k.Namespace,
		"policyName":      k.Name,
	}
	logCtx := log.WithFields(fields)
	for _, p := range flow.Policies {
		// We have a match if the kind, namespace and name all match.
		if p.Namespace() != k.Namespace {
			logCtx.WithFields(log.Fields{
				"flowNamespace": p.Namespace(),
				"policyNSpace":  k.Namespace,
			}).Debug("Policy namespace in flow log does not match compiled policy namespace")
			continue
		}
		if p.Kind() != k.Kind {
			logCtx.WithFields(log.Fields{
				"kind":       p.Kind(),
				"policyKind": k.Kind,
			}).Debug("Policy kind in flow log does not match compiled policy kind")
			continue
		}
		if p.Name() != k.Name {
			logCtx.WithFields(log.Fields{
				"flowName":   p.Name(),
				"policyName": k.Name,
			}).Debug("Policy name in flow log does not match compiled policy name")
			continue
		}

		// Match!
		thisActionFlag := p.Action()
		log.Debugf("Policy %s in flow log has action flags %s", p.Name(), thisActionFlag)
		if policyAction != api.ActionInvalid && policyAction != thisActionFlag {
			return 0, false
		}

		// When the policy action and the rule index id are 'deny' and -1 respectively, set the
		// policyAction to end-of-tier deny.
		if p.RuleIdIndex() != nil &&
			*p.RuleIdIndex() == ruleIdIndexEndOfTierDeny &&
			thisActionFlag == api.ActionDeny {
			policyAction = api.ActionEndOfTierDeny
		} else {
			policyAction = thisActionFlag
		}
	}

	policyActionFlag := api.ActionFlagFromString(string(policyAction))
	return policyActionFlag, policyActionFlag != 0
}
