// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.

package commands

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/dispatcher"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/felixsyncer"
)

// MATT: How to make includeRules actually work?
// Will need to be able to call eval selector and get the output programmatically (not printed).
// Do that for each rule in each policy (globally, not just selected).
// Actually I want to be able to do eval selector with many selectors and few EPs.
// Basically I want to be able to control the EP filter used by eval selector.
func DescribeEndpointOrHost(configFile, endpointSubstring, hostname string, hideSelectors bool, hideRuleMatches bool, outputFormat string) (err error) {
	disp := dispatcher.NewDispatcher()
	cbs := &describeCmd{
		hideSelectors:     hideSelectors,
		includeRules:      !hideRuleMatches,
		endpointSubstring: endpointSubstring,
		hostname:          hostname,
		outputFormat:      outputFormat,
		dispatcher:        disp,
		done:              make(chan bool),
		epIDToPolIDs:      make(map[any]map[model.PolicyKey]bool),
		epIDToProfileIDs:  make(map[any][]string),
		polIDToPolicy:     make(map[model.PolicyKey]*model.Policy),
		policySorter:      calc.NewPolicySorter(),
		evalCmd:           nil,
		rcc:               NewRemoteClusterHandler(),
	}
	nrs := &noopRuleScanner{}
	arc := calc.NewActiveRulesCalculator()
	arc.PolicyMatchListeners = append(arc.PolicyMatchListeners, cbs)
	arc.RuleScanner = nrs
	cbs.activeRulesCalculator = arc

	// MATT This approach won't be suitable for not-yet-configured endpoints.
	//      To support them, we'd need to be able to build a fake endpoint kv
	//      for them from the yaml for that endpoint.
	filterUpdate := func(update api.Update) (filterOut bool) {
		if update.Value == nil {
			// MATT: Why is this so much lower priority than checkValid?
			log.Infof("Skipping bad update: %v", update.Key)
			return true
		}
		switch key := update.Key.(type) {
		case model.HostEndpointKey:
			if hostname != "" && key.Hostname != hostname {
				return true
			}
			if !strings.Contains(endpointName(key), endpointSubstring) {
				return true
			}
			ep := update.Value.(*model.HostEndpoint)
			cbs.epIDToProfileIDs[key] = ep.ProfileIDs
		case model.WorkloadEndpointKey:
			if hostname != "" && key.Hostname != hostname {
				return true
			}
			if !strings.Contains(endpointName(key), endpointSubstring) {
				return true
			}
			ep := update.Value.(*model.WorkloadEndpoint)
			cbs.epIDToProfileIDs[key] = ep.ProfileIDs
		}
		// Insert an empty map so we'll list this endpoint even if
		// no policies match it.
		log.Infof("Found active endpoint %#v", update.Key)
		cbs.epIDToPolIDs[update.Key] = make(map[model.PolicyKey]bool)
		arc.OnUpdate(update)
		return false
	}

	// MATT TODO: Compare this to the Felix ValidationFilter.  How is this deficient?
	checkValid := func(update api.Update) (filterOut bool) {
		if update.Value == nil {
			fmt.Printf("WARNING: failed to parse value of key %v; "+
				"ignoring.\n\n", update)
			return true
		}
		return false
	}

	// MATT: It's very opaque why some of these need to be checked,
	//       and some can just be passed straight to the arc/sorter.
	// LOL I'm an idiot.
	disp.Register(model.WorkloadEndpointKey{}, checkValid)
	disp.Register(model.HostEndpointKey{}, checkValid)
	disp.Register(model.PolicyKey{}, checkValid)
	disp.Register(model.TierKey{}, checkValid)
	disp.Register(model.ProfileRulesKey{}, checkValid)

	if cbs.includeRules {
		// MATT: Would be nice to have a single dispatcher: wouldn't need to worry about
		// the two not working on the same data and giving weird results.
		cbs.evalCmd = NewEvalCmd(configFile)
		cbs.evalCmd.showSelectors = !hideSelectors
		polRules := func(update api.Update) (filterOut bool) {
			// Go through the rules, and generate a selector for each.
			cbs.evalCmd.AddPolicyRuleSelectors(
				update.Value.(*model.Policy),
				"Policy \""+keyToName(update.Key.(model.PolicyKey))+"\" ",
			)
			return false
		}
		disp.Register(model.PolicyKey{}, polRules)
		// TODO: Do a profile version?
	}

	disp.Register(model.WorkloadEndpointKey{}, filterUpdate)
	disp.Register(model.HostEndpointKey{}, filterUpdate)
	disp.Register(model.PolicyKey{}, cbs.onPolicyUpdate)
	disp.Register(model.PolicyKey{}, arc.OnUpdate)
	disp.Register(model.PolicyKey{}, cbs.policySorter.OnUpdate)
	disp.Register(model.TierKey{}, cbs.policySorter.OnUpdate)
	disp.Register(model.ResourceKey{}, arc.OnUpdate)
	disp.Register(model.RemoteClusterStatusKey{}, cbs.rcc.OnUpdate)

	bclient, cfg := GetClient(configFile)
	syncer := felixsyncer.New(bclient, cfg.Spec, cbs, false, true)
	syncer.Start()

	// The describeCmd will notify us once it's in sync and has finished outputting.
	<-cbs.done

	// If there are any errors connecting to the remote clusters, report the errors and exit.
	cbs.rcc.CheckForErrorAndExit()

	return
}

type noopRuleScanner struct{}

func (rs *noopRuleScanner) OnPolicyActive(model.PolicyKey, *model.Policy) {
}

func (rs *noopRuleScanner) OnPolicyInactive(model.PolicyKey) {
}

func (rs *noopRuleScanner) OnProfileActive(model.ProfileRulesKey, *model.ProfileRules) {
}

func (rs *noopRuleScanner) OnProfileInactive(model.ProfileRulesKey) {
}

func (rs *noopRuleScanner) OnTierActive(model.TierKey, *model.Tier) {
}

func (rs *noopRuleScanner) OnTierInactive(model.TierKey) {
}

type describeCmd struct {
	// Config.
	hideSelectors     bool
	includeRules      bool
	endpointSubstring string
	hostname          string
	outputFormat      string

	// ActiveRulesCalculator matches policies/profiles against local
	// endpoints and notifies the ActiveSelectorCalculator when
	// their rules become active/inactive.
	activeRulesCalculator *calc.ActiveRulesCalculator
	dispatcher            *dispatcher.Dispatcher
	epIDToPolIDs          map[any]map[model.PolicyKey]bool
	epIDToProfileIDs      map[any][]string
	polIDToPolicy         map[model.PolicyKey]*model.Policy
	policySorter          *calc.PolicySorter

	evalCmd *EvalCmd

	// Remote cluster handler is used to output errors associated with failures to connect to a configured
	// remote cluster.
	rcc *remoteClusterHandler

	done chan bool
}

func (cbs *describeCmd) OnConfigLoaded(globalConfig map[string]string,
	hostConfig map[string]string,
) {
	// Ignore for now
}

type endpointDatum struct {
	epID   any
	polIDs map[model.PolicyKey]bool
}

func (epd endpointDatum) EndpointName() string {
	var epName string
	switch epID := epd.epID.(type) {
	case model.WorkloadEndpointKey:
		epName = fmt.Sprintf("Workload endpoint %v/%v/%v", epID.OrchestratorID, convertWorkloadID(epID.WorkloadID), epID.EndpointID)
	case model.HostEndpointKey:
		epName = fmt.Sprintf("Host endpoint %v", epID.EndpointID)
	}
	return epName
}

type ByName []endpointDatum

func (a ByName) Len() int      { return len(a) }
func (a ByName) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByName) Less(i, j int) bool {
	return a[i].EndpointName() < a[j].EndpointName()
}

func (cbs *describeCmd) OnStatusUpdated(status api.SyncStatus) {
	if status == api.InSync {
		var matches map[any][]string
		if cbs.includeRules {
			endpointMatch := func(update api.Update) (filterOut bool) {
				if update.Value == nil {
					// MATT: Why is this so much lower priority than checkValid?
					log.Infof("Skipping bad update: %v", update.Key)
					return true
				}
				switch key := update.Key.(type) {
				case model.HostEndpointKey:
					if cbs.hostname != "" && key.Hostname != cbs.hostname {
						return true
					}
					if !strings.Contains(endpointName(key), cbs.endpointSubstring) {
						return true
					}
				case model.WorkloadEndpointKey:
					if cbs.hostname != "" && key.Hostname != cbs.hostname {
						return true
					}
					if !strings.Contains(endpointName(key), cbs.endpointSubstring) {
						return true
					}
				}
				return false
			}
			cbs.evalCmd.Start(endpointMatch)
			matches = cbs.evalCmd.GetMatches()
		}

		output := cbs.printObjects(matches)

		switch cbs.outputFormat {
		case "json":
			cbs.printJSON(output)
		case "yaml":
			cbs.printYAML(output)
		case "ps":
			cbs.print(output)
		}

		cbs.done <- true
	}
}

func (cbs *describeCmd) print(output OutputList) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%v:\n", output.Description)
	for _, ep := range output.Endpoints {
		fmt.Fprintf(&buf, "\n%v\n", ep.PrintNameWithoutNode())
		fmt.Fprintln(&buf, "  Policies:")
		for _, pol := range ep.Policies {
			if pol.TierOrder == "missing" {
				fmt.Fprintf(&buf, "    WARNING: tier %#v metadata missing; packets will skip tier\n", pol.TierName)
			}

			tierText := ""
			if pol.TierName != "default" {
				tierText = fmt.Sprintf("Tier %#v (order %v) ", pol.TierName, pol.TierOrder)
			}

			if cbs.hideSelectors {
				fmt.Fprintf(&buf, "    %sPolicy %#v (order %v)%v\n", tierText, pol.Name, pol.Order, pol.UntrackedSuffix)
			} else {
				fmt.Fprintf(&buf, "    %sPolicy %#v (order %v; selector \"%v\")%v\n", tierText, pol.Name, pol.Order, pol.Selector, pol.UntrackedSuffix)
			}
		}

		if len(ep.Profiles) > 0 {
			buf.WriteString("  Profiles:\n")
			for _, prof := range ep.Profiles {
				fmt.Fprintf(&buf, "    Profile \"%v\"\n", prof.Name)
			}
		}

		if len(ep.Rules) > 0 {
			buf.WriteString("  Rule matches:\n")
			for _, rule := range ep.Rules {
				ruleString := fmt.Sprintf("    Policy \"%v\" %v rule %v %v match\n", rule.PolicyName, rule.Direction, rule.Order, rule.SelectorType)
				if rule.Selector != "" {
					ruleString = fmt.Sprintf("    Policy \"%v\" %v rule %v %v match; selector \"%v\"\n", rule.PolicyName, rule.Direction, rule.Order, rule.SelectorType, rule.Selector)
				}
				buf.WriteString(ruleString)
			}
		}
	}

	_, err := buf.WriteTo(os.Stdout)
	if err != nil {
		log.Errorf("Failed to write to Stdout: %v", err)
	}
}

func (cbs *describeCmd) printObjects(matches map[any][]string) OutputList {
	output := OutputList{}

	if cbs.hostname != "" {
		output.Description = fmt.Sprintf("Policies and profiles for each endpoint on host \"%v\"", cbs.hostname)
	} else {
		output.Description = fmt.Sprintf("Policies and profiles for endpoints matching \"%v\"", cbs.endpointSubstring)
	}

	tiers := cbs.policySorter.Sorted() // MATT: map[model.PolicyKey]*model.Policy
	epData := make([]endpointDatum, 0)

	for epID, polIDs := range cbs.epIDToPolIDs {
		epData = append(epData, endpointDatum{epID, polIDs})
	}

	sort.Sort(ByName(epData))

	for _, epDatum := range epData {
		ep := NewEndpointPrintFromEndpointDatum(epDatum)
		epID := epDatum.epID
		polIDs := epDatum.polIDs
		log.Infof("Looking at endpoint %v with policies %v", epID, polIDs)
		for _, untracked := range []bool{true, false} {
			for _, tier := range tiers {
				log.Infof("Looking at tier %v", tier)
				suffix := ""
				if untracked {
					suffix = " [untracked]"
				}

				for _, pol := range tier.OrderedPolicies { // pol is a PolKV
					log.Infof("Looking at policy %v", pol.Key)
					if pol.Value.DoNotTrack() != untracked {
						continue
					}
					if polIDs[pol.Key] {
						tierOrder := "default"
						if tier.Order != nil {
							tierOrder = fmt.Sprint(*tier.Order)
						}

						if tier.Name != "default" {
							if !tier.Valid {
								fmt.Printf("    WARNING: tier %#v metadata missing; packets will skip tier\n", tier.Name)
								tierOrder = "missing"
							}
						}

						polOrder := "default"
						if !math.IsInf(pol.Value.Order, 1) {
							polOrder = fmt.Sprint(pol.Value.Order)
						}

						policyPrint := PolicyPrint{
							Name:            keyToName(pol.Key),
							Order:           polOrder,
							TierName:        tier.Name,
							TierOrder:       tierOrder,
							UntrackedSuffix: suffix,
						}

						if !cbs.hideSelectors {
							policy, ok := cbs.polIDToPolicy[pol.Key]
							if ok {
								policyPrint.Selector = policy.Selector
							} else {
								policyPrint.Selector = "<missing>"
							}
						}

						ep.Policies = append(ep.Policies, policyPrint)
					}
				}
			}
		}

		profIDs := cbs.epIDToProfileIDs[epID]
		if len(profIDs) > 0 {
			for _, profID := range cbs.epIDToProfileIDs[epID] {
				ep.Profiles = append(ep.Profiles, ProfilePrint{profID})
			}
		}

		if cbs.includeRules {
			if policies, ok := matches[epID]; ok {
				sort.Strings(policies)
				for _, policy := range policies {
					ep.Rules = append(ep.Rules, NewRulePrintFromMatchString(policy))
				}
			}
		}

		// Add the filled out endpoint to the output list
		output.Endpoints = append(output.Endpoints, ep)
	}

	return output
}

func (cbs *describeCmd) printYAML(output OutputList) {
	err := printYAML([]OutputList{output})
	if err != nil {
		log.Errorf("Unexpected error printing to YAML: %s", err)
		fmt.Println("Unexpected error printing to YAML")
	}
}

func (cbs *describeCmd) printJSON(output OutputList) {
	err := printJSON([]OutputList{output})
	if err != nil {
		log.Errorf("Unexpected error printing to JSON: %s", err)
		fmt.Println("Unexpected error printing to JSON")
	}
}

func (cbs *describeCmd) OnUpdates(updates []api.Update) {
	log.Info("Update: ", updates)
	for _, update := range updates {
		// MATT: Removed some handling of empty key: don't understand how it can happen.
		cbs.dispatcher.OnUpdate(update)
	}
}

func (cbs *describeCmd) onPolicyUpdate(update api.Update) (filterOut bool) {
	polKey := update.Key.(model.PolicyKey)
	if update.Value == nil {
		delete(cbs.polIDToPolicy, polKey)
	} else {
		cbs.polIDToPolicy[polKey] = update.Value.(*model.Policy)
	}
	return false
}

func (cbs *describeCmd) OnPolicyMatch(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	log.Infof("%s now matches %+v", policyKey.String(), endpointKey)
	cbs.epIDToPolIDs[endpointKey][policyKey] = true
}

func (cbs *describeCmd) OnPolicyMatchStopped(policyKey model.PolicyKey, endpointKey model.EndpointKey) {
	// Matt: Maybe we should remove something here, but it's an edge case
}

func (cbs *describeCmd) OnComputedSelectorMatch(_ string, _ model.EndpointKey) {
	// We don't currently analyze egress selectors.
}

func (cbs *describeCmd) OnComputedSelectorMatchStopped(_ string, _ model.EndpointKey) {
	// We don't currently analyze egress selectors.
}

var _ calc.PolicyMatchListener = (*describeCmd)(nil)

type TierInfo struct {
	Name     string
	Valid    bool
	Order    *float32
	Policies []*model.Policy
}
