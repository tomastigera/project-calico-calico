// Copyright (c) 2017 Tigera, Inc. All rights reserved.

package commands

import (
	"fmt"
	"strconv"
	"strings"

	// TODO (mattl): Check glide for these and if they need to be private
	"encoding/json"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

func printYAML(outputs []OutputList) error {
	if output, err := yaml.Marshal(outputs); err != nil {
		return err
	} else {
		fmt.Println(string(output))
	}
	return nil
}

func printJSON(outputs []OutputList) error {
	if output, err := json.MarshalIndent(outputs, "", "  "); err != nil {
		return err
	} else {
		fmt.Println(string(output))
	}
	return nil
}

type OutputList struct {
	Description       string           `json:"description"`
	Endpoints         []*EndpointPrint `json:"endpoints,omitempty"`
	ApplyToEndpoints  []*EndpointPrint `json:"policy_applies_to_endpoints,omitempty"`
	MatchingEndpoints []*EndpointPrint `json:"endpoints_match_policy,omitempty"`
	Tier              string           `json:"-"`
	InputName         string           `json:"-"`
}

type EndpointPrint struct {
	Node         string         `json:"node,omitempty"`
	Orchestrator string         `json:"orchestrator,omitempty"`
	Workload     string         `json:"workload,omitempty"`
	Name         string         `json:"name,omitempty"`
	Policies     []PolicyPrint  `json:"policies,omitempty"`
	Profiles     []ProfilePrint `json:"profiles,omitempty"`
	Rules        []RulePrint    `json:"rule_matches,omitempty"`
	Selector     string         `json:"selector,omitempty"`
	Cluster      string         `json:"remote_cluster,omitempty"`
}

func NewEndpointPrintFromEndpointDatum(epd endpointDatum) *EndpointPrint {
	return NewEndpointPrintFromKey(epd.epID)
}

func NewEndpointPrintFromKey(key interface{}) *EndpointPrint {
	epp := &EndpointPrint{}
	switch epID := key.(type) {
	case model.WorkloadEndpointKey:
		epp.Node = epID.Hostname
		epp.Orchestrator = epID.OrchestratorID
		epp.Workload = epID.WorkloadID
		epp.Name = epID.EndpointID
	case model.HostEndpointKey:
		epp.Node = epID.Hostname
		epp.Name = epID.EndpointID
	}
	return epp
}

func NewEndpointPrintFromNameString(name string) *EndpointPrint {
	// name is of the form "Workload endpoint <node>/<orchestrator>/<workload>/<name>
	// sel is of the form "applicable endpoints; selector <selector>
	epp := &EndpointPrint{}
	endpointStrings := strings.Split(name, " ")
	if len(endpointStrings) != 3 || endpointStrings[0] != "Workload" || endpointStrings[1] != "endpoint" {
		log.Errorf("Workload endpoint name is not in the \"Workload endpoint <node>/<orchestrator>/<workload>/<name>\" format: %s", name)
		return nil
	}

	endpointIdents := strings.Split(endpointStrings[2], "/")
	if len(endpointIdents) != 4 && len(endpointIdents) != 5 {
		log.Errorf("Workload endpoint name does not have its identifiers <node>/<orchestrator>/<workload>/<name> separated by \"/\": %s", name)
		return nil
	}

	if len(endpointIdents) == 5 {
		// If there's a cluster/ at the front, then "pop" it off the endpointIdents slice.
		epp.Cluster, endpointIdents = endpointIdents[0], endpointIdents[1:]
	}

	epp.Node = endpointIdents[0]
	epp.Orchestrator = endpointIdents[1]
	epp.Workload = endpointIdents[2]
	epp.Name = endpointIdents[3]

	return epp
}

func (epp *EndpointPrint) PrintName() string {
	// Workload Endpoints will have all these fields specified
	if epp.IsWorkloadEndpoint() {
		return fmt.Sprintf("Workload endpoint %v/%v/%v/%v", epp.Node, epp.Orchestrator, convertWorkloadID(epp.Workload), epp.Name)
	}

	// If it is not a Workload Endpoint, it is a Host Endpoint
	return fmt.Sprintf("Host endpoint %v/%v", epp.Node, epp.Name)
}

func (epp *EndpointPrint) PrintNameWithoutNode() string {
	// Workload Endpoints will have all these fields specified
	if epp.IsWorkloadEndpoint() {
		return fmt.Sprintf("Workload endpoint %v/%v/%v", epp.Orchestrator, convertWorkloadID(epp.Workload), epp.Name)
	}

	// If it is not a Workload Endpoint, it is a Host Endpoint
	return fmt.Sprintf("Host endpoint %v", epp.Name)
}

func (epp *EndpointPrint) IsWorkloadEndpoint() bool {
	return epp.Node != "" && epp.Orchestrator != "" && epp.Workload != "" && epp.Name != ""
}

type PolicyPrint struct {
	Name            string `json:"name,omitempty"`
	Order           string `json:"order,omitempty"`
	Selector        string `json:"selector,omitempty"`
	TierName        string `json:"tier_name,omitempty"`
	TierOrder       string `json:"tier_order,omitempty"`
	UntrackedSuffix string `json:"-"`
}

type ProfilePrint struct {
	Name string `json:"name"`
}

type RulePrint struct {
	PolicyName   string `json:"policy_name,omitempty"`
	TierName     string `json:"tier_name,omitempty"`
	Direction    string `json:"direction"`
	SelectorType string `json:"selector_type"`
	Order        int    `json:"order"`
	Selector     string `json:"selector,omitempty"`
}

func NewRulePrintFromMatchString(match string) RulePrint {
	// Takes in a policy string formatted by EvalCmd.GetMatches for policies of the format:
	// Policy "<policy name>" <inbound/outbound> rule <rule number> <source/destination> match; selector "<selector>"
	rp := RulePrint{}

	// Split by spaces to extract the information
	info := strings.SplitN(match, " ", 9)

	// TODO (mattl): Figure out what the right error handling would be here
	// TODO (mattl): Refactor this and its callers eventually to use the PolicyKey objects to get Tier names
	if len(info) == 7 {
		if info[0] != "Policy" || info[3] != "rule" || info[6] != "match" {
			log.Errorf("Internal error - please report to support: Match string is not in the format: Policy \"policy name>\" <inbound/outbound> rule <rule number> <source/destination> match: %s", match)
			return rp
		}
	} else if len(info) != 9 || info[0] != "Policy" || info[3] != "rule" || info[6] != "match;" || info[7] != "selector" {
		log.Errorf("Internal error - please report to support: Match string is not in the format: Policy \"policy name>\" <inbound/outbound> rule <rule number> <source/destination> match; selector \"<selector>\": %s", match)
		return rp
	}

	var err error
	rp.PolicyName = info[1][1 : len(info[1])-1]
	rp.Direction = info[2]
	rp.SelectorType = info[5]
	if len(info) == 9 {
		rp.Selector = info[8][1 : len(info[8])-1]
	}
	rp.Order, err = strconv.Atoi(info[4])
	if err != nil {
		log.Errorf("Unable to create Policy Rule from match string: %s", err)
	}

	return rp
}

func NewRulePrintFromSelectorString(selector string) RulePrint {
	// Takes in a policy string formatted by EvalCmd.GetMatches of the format:
	// <direction> rule <rule number> <selector type> match; selector "<selector>"
	rp := RulePrint{}

	// Split by spaces to extract the information
	info := strings.SplitN(selector, " ", 7)

	// TODO (mattl): Figure out what the right error handling would be here
	if len(info) == 5 {
		if strings.HasPrefix(selector, APPLICABLE_ENDPOINTS) || info[1] != "rule" || info[4] != "match" {
			log.Errorf("Internal error - please report to support: Selector string not in the format <direction> rule <rule number> <selector type> match: %s", selector)
			return rp
		}
	} else if strings.HasPrefix(selector, APPLICABLE_ENDPOINTS) || len(info) != 7 || info[1] != "rule" || info[4] != "match;" || info[5] != "selector" {
		log.Errorf("Internal error - please report to support: Selector string not in the format <direction> rule <rule number> <selector type> match; selector \"<selector>\": %s", selector)
		return rp
	}

	var err error
	rp.Direction = info[0]
	rp.SelectorType = info[3]
	if len(info) == 7 {
		rp.Selector = info[6][1 : len(info[6])-1]
	}
	rp.Order, err = strconv.Atoi(info[2])
	if err != nil {
		log.Errorf("Unable to create Policy Rule from match string: %s", err)
	}

	return rp
}

func endpointName(key interface{}) string {
	var epName string
	switch epID := key.(type) {
	case model.WorkloadEndpointKey:
		epName = fmt.Sprintf("Workload endpoint %v/%v/%v/%v", epID.Hostname, epID.OrchestratorID, convertWorkloadID(epID.WorkloadID), epID.EndpointID)
	case model.HostEndpointKey:
		epName = fmt.Sprintf("Host endpoint %v/%v", epID.Hostname, epID.EndpointID)
	}
	return epName
}

// keyToName takes a model.PolicyKey and returns an appropriate string name.
// TODO: Remove this and refactor to pass around PolicyKey objects directly.
func keyToName(k model.PolicyKey) string {
	if k.Namespace != "" {
		return fmt.Sprintf("%s/%s", k.Namespace, k.Name)
	}
	return k.Name
}

// TODO: Figure out if we need to change how WorkloadEndpoints are displayed and remove this if
// we are going to move away from using "/" to separate the key values for a WorkloadEndpoint.
func convertWorkloadID(raw string) string {
	// Need to change the WorkloadID from form <namespace>/<name> to <namespace>.<name>
	return strings.Replace(raw, "/", ".", 1)
}
