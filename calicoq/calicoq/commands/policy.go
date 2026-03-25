// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

package commands

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
)

const APPLICABLE_ENDPOINTS = "applicable endpoints"

func EvalPolicySelectors(configFile, policyName string, hideSelectors, hideRuleMatches bool, outputFormat string) (err error) {
	bclient, _ := GetClient(configFile)
	ctx := context.Background()

	// policyName will be of the form <namespace>/<name>
	var name, ns string
	parts := strings.SplitN(policyName, "/", 2)
	if len(parts) == 2 {
		ns = parts[0]
		name = parts[1]
	} else {
		name = parts[0]
	}

	// Sanity check a name has been specified - this may be blank if someone specifies a
	// name such as "/" or "namespace/".
	if name == "" {
		fmt.Println("The policy-name must be specified.")
		log.WithField("<policy-name>", policyName).Error("The policy-name has not been specified")
		os.Exit(1)
	}

	// Query either the NP or the GNP depending on whether a namespace has also been supplied.
	var kvs []*model.KVPair
	if ns != "" {
		npkvs, err := bclient.List(ctx, model.ResourceListOptions{Name: name, Namespace: ns, Kind: apiv3.KindNetworkPolicy}, "")
		if err != nil {
			fmt.Println("Failed to list NetworkPolicy resources.")
			log.WithError(err).Error("Failed to get network policy")
			os.Exit(1)
		}
		kvs = npkvs.KVPairs
	} else {
		gnpkvs, err := bclient.List(ctx, model.ResourceListOptions{Name: name, Kind: apiv3.KindGlobalNetworkPolicy}, "")
		if err != nil {
			fmt.Println("Failed to list GlobalNetworkPolicy resources.")
			log.WithError(err).Error("Failed to get global network policy")
			os.Exit(1)
		}
		kvs = gnpkvs.KVPairs
	}

	var rcc *remoteClusterHandler
	for _, kv := range kvs {
		log.Debugf("Policy: %#v", kv)
		// Convert the V2 Policy object to a V1 Policy object
		// TODO: Get rid of the conversion method when felix is updated to use the v2 data model
		var policy *model.Policy
		switch kv.Value.(type) {
		case *apiv3.NetworkPolicy:
			policy = convertNetworkPolicyV2ToV1Value(kv.Value.(*apiv3.NetworkPolicy).Spec, kv.Value.(*apiv3.NetworkPolicy).Namespace)
		case *apiv3.GlobalNetworkPolicy:
			policy = convertGlobalPolicyV2ToV1Spec(kv.Value.(*apiv3.GlobalNetworkPolicy).Spec)
		}

		cbs := NewEvalCmd(configFile)
		cbs.showSelectors = !hideSelectors
		cbs.AddSelector(APPLICABLE_ENDPOINTS, policy.Selector)
		if !hideRuleMatches {
			cbs.AddPolicyRuleSelectors(policy, "")
		}

		noopFilter := func(update api.Update) (filterOut bool) {
			return false
		}
		cbs.Start(noopFilter)

		matches := map[string][]string{}
		for endpointID, selectors := range cbs.GetMatches() {
			matches[endpointName(endpointID)] = selectors
		}

		output := EvalPolicySelectorsPrintObjects(policyName, hideRuleMatches, kv, matches)

		switch outputFormat {
		case "yaml":
			EvalPolicySelectorsPrintYAML(output)
		case "json":
			EvalPolicySelectorsPrintJSON(output)
		case "ps":
			EvalPolicySelectorsPrint(output)
		}

		// We track the remoteClusterHandler and return errors associated with the remote clusters, for the
		// last policy that we process in this loop - it's assumed that the same set of errors would be
		// returned on each policy query, so just handling the last should be sufficient.
		rcc = cbs.rcc
	}

	// If there are any errors connecting to the remote clusters, report the errors and exit.
	// It might be nil if the for loop did't run (because kvs was empty).
	if rcc != nil {
		rcc.CheckForErrorAndExit()
	}

	return
}

func EvalPolicySelectorsPrintYAML(output OutputList) {
	err := printYAML([]OutputList{output})
	if err != nil {
		log.Errorf("Unexpected error printing to YAML: %s", err)
		fmt.Println("Unexpected error printing to YAML")
	}
}

func EvalPolicySelectorsPrintJSON(output OutputList) {
	err := printJSON([]OutputList{output})
	if err != nil {
		log.Errorf("Unexpected error printing to JSON: %s", err)
		fmt.Println("Unexpected error printing to JSON")
	}
}

func EvalPolicySelectorsPrintObjects(policyName string, hideRuleMatches bool, kv *model.KVPair, matches map[string][]string) OutputList {
	// matches is a mapping of Workload Endpoint names to a list of Felix selector strings.
	// The selector strings specify whether the endpoint matches a rule for the policy or if the policy applies to this endpoint.
	// wepNames represents all the Workload Endpoint name strings passed in from Felix.
	wepNames := []string{}
	for name := range matches {
		wepNames = append(wepNames, name)
	}
	sort.Strings(wepNames)

	// Display tier when non-default.
	var tier string
	switch kv.Value.(type) {
	case *apiv3.NetworkPolicy:
		tier = kv.Value.(*apiv3.NetworkPolicy).Spec.Tier
	case *apiv3.GlobalNetworkPolicy:
		tier = kv.Value.(*apiv3.GlobalNetworkPolicy).Spec.Tier
	}
	tierPrefix := ""
	if tier != "default" && tier != "" {
		tierPrefix = "Tier \"" + tier + "\" "
	}

	output := OutputList{
		Description: fmt.Sprintf("Endpoints that %sPolicy %s applies to and the endpoints that match the policy", tierPrefix, policyName),
		Tier:        tier,
		InputName:   policyName,
	}

	for _, wepName := range wepNames {
		// Create the Workload Endpoint object from the name
		epp := NewEndpointPrintFromNameString(wepName)
		if epp == nil {
			continue
		}

		// Need to add all the endpoints that this policy "applies to" to a set as well as the selector that qualified it.
		// Selector strings may be hidden by input options or by Felix options.
		for _, sel := range matches[wepName] {
			if epp.Cluster != "" {
				// Endpoints from a remote cluster can't apply on the local cluster, so skip them.
				break
			}
			// If this endpoint has a selector that specifies the policy "applies to" this endpoint, add it to the "applies to" set
			if strings.HasPrefix(sel, APPLICABLE_ENDPOINTS) {
				// sel is of the form "applicable endpoints; selector <selector>
				// If the selector is hidden, it will be of the form "applicable endpoints"
				// Add the selector to the endpoint if one exists.
				if strings.HasPrefix(sel, "applicable endpoints; selector") {
					selector := strings.SplitN(sel, " ", 4)[3]
					epp.Selector = selector[1 : len(selector)-1]
				}
				output.ApplyToEndpoints = append(output.ApplyToEndpoints, epp)
				break
			}
		}

		// Add the relevant rules to any matching endpoints
		if !hideRuleMatches {
			sort.Strings(matches[wepName])
			// Need to loop over the selectors again since now we are adding every valid rule to an endpoint
			for _, sel := range matches[wepName] {
				if !strings.HasPrefix(sel, APPLICABLE_ENDPOINTS) {
					epp.Rules = append(epp.Rules, NewRulePrintFromSelectorString(sel))
				}
			}
			output.MatchingEndpoints = append(output.MatchingEndpoints, epp)
		}
	}

	return output
}

func EvalPolicySelectorsPrint(output OutputList) {
	// Write all output to a buffer and then write that buffer to Stdout
	var buf bytes.Buffer

	// Display tier when non-default.
	tierPrefix := ""
	if output.Tier != "default" && output.Tier != "" {
		tierPrefix = "Tier \"" + output.Tier + "\" "
	}

	fmt.Fprintf(&buf, "%vPolicy \"%v\" applies to these endpoints:\n", tierPrefix, output.InputName)
	for _, epp := range output.ApplyToEndpoints {
		appliesToEndpointString := fmt.Sprintf("  Workload endpoint %v/%v/%v/%v\n", epp.Node, epp.Orchestrator, epp.Workload, epp.Name)
		if epp.Selector != "" {
			appliesToEndpointString = fmt.Sprintf("  Workload endpoint %v/%v/%v/%v; selector \"%v\"\n", epp.Node, epp.Orchestrator, epp.Workload, epp.Name, epp.Selector)
		}
		buf.WriteString(appliesToEndpointString)
	}

	if len(output.MatchingEndpoints) > 0 {
		fmt.Fprintf(&buf, "\nEndpoints matching %vPolicy \"%v\" rules:\n", tierPrefix, output.InputName)
		for _, epp := range output.MatchingEndpoints {
			cluster := ""
			if epp.Cluster != "" {
				cluster = epp.Cluster + "/"
			}
			endpointPrefix := fmt.Sprintf("  Workload endpoint %v%v/%v/%v/%v\n", cluster, epp.Node, epp.Orchestrator, epp.Workload, epp.Name)
			for _, rp := range epp.Rules {
				sel := fmt.Sprintf("%v rule %v %v match", rp.Direction, rp.Order, rp.SelectorType)
				if rp.Selector != "" {
					sel = fmt.Sprintf("%v rule %v %v match; selector \"%v\"", rp.Direction, rp.Order, rp.SelectorType, rp.Selector)
				}
				fmt.Fprintf(&buf, "%v    %v\n", endpointPrefix, sel)
				endpointPrefix = ""
			}
		}
	}

	// Write the buffer to Stdout
	if _, err := buf.WriteTo(os.Stdout); err != nil {
		log.Errorf("Failed to write to Stdout: %v", err)
	}
}

// These are slightly modified copies (they do not return an error) of
// the conversion methods in libcalico-go. Copying it here so that we
// do not have more work later to keep libcalico-go-private in sync
// with libcalico-go.
// TODO: Delete this when the Felix syncer uses the v3 model and the
// referencing logic is changed.
func convertGlobalPolicyV2ToV1Spec(spec apiv3.GlobalNetworkPolicySpec) *model.Policy {
	v1value := &model.Policy{
		Order:          spec.Order,
		InboundRules:   updateprocessors.RulesAPIV3ToBackend(spec.Ingress, "", false),
		OutboundRules:  updateprocessors.RulesAPIV3ToBackend(spec.Egress, "", false),
		Selector:       spec.Selector,
		Types:          policyTypesAPIV3ToBackend(spec.Types),
		DoNotTrack:     spec.DoNotTrack,
		PreDNAT:        spec.PreDNAT,
		ApplyOnForward: spec.ApplyOnForward,
	}

	return v1value
}

func convertNetworkPolicyV2ToV1Value(spec apiv3.NetworkPolicySpec, ns string) *model.Policy {
	// If this policy is namespaced, then add a namespace selector.
	selector := spec.Selector
	if ns != "" {
		nsSelector := fmt.Sprintf("%s == '%s'", apiv3.LabelNamespace, ns)
		if selector == "" {
			selector = nsSelector
		} else {
			selector = fmt.Sprintf("(%s) && %s", selector, nsSelector)
		}
	}

	v1value := &model.Policy{
		Order:          spec.Order,
		InboundRules:   updateprocessors.RulesAPIV3ToBackend(spec.Ingress, ns, false),
		OutboundRules:  updateprocessors.RulesAPIV3ToBackend(spec.Egress, ns, false),
		Selector:       selector,
		Types:          policyTypesAPIV3ToBackend(spec.Types),
		ApplyOnForward: true,
	}

	return v1value
}

// Copy of the function in libcalico-go.
// TODO: Remove this when the Felix syncer uses the v3 model and the
// referencing logic is changed
func policyTypesAPIV3ToBackend(ptypes []apiv3.PolicyType) []string {
	var v1ptypes []string
	for _, ptype := range ptypes {
		v1ptypes = append(v1ptypes, strings.ToLower(string(ptype)))
	}
	return v1ptypes
}
