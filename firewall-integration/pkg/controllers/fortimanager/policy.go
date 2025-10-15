// Copyright 2020-2021 Tigera Inc. All rights reserved.
package fortimanager

import (
	"errors"
	"fmt"
	"strconv"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	fortilib "github.com/projectcalico/calico/firewall-integration/pkg/fortimanager"
)

const (
	FwFortiManagerLabel = "tigera.io/address-group"
	ProtocolTCP         = "TCP"
	ProtocolUDP         = "UDP"
)

// FortiManager Firewall rule `action` field returns 0 = Deny and 1 = Allow.
// Covert this to V3 action objects.
var actions = []apiv3.Action{apiv3.Deny, apiv3.Allow}

func createRule(fwRule fortilib.FortiFWPolicy, ingress bool, selector, protocol string, ports []numorstring.Port) apiv3.Rule {
	var policyRule apiv3.Rule

	proto := numorstring.ProtocolFromString(protocol)
	policyRule.Protocol = &proto
	policyRule.Action = actions[fwRule.Action]
	if len(ports) > 0 {
		policyRule.Destination = apiv3.EntityRule{
			Ports: ports,
		}
	}
	if ingress {
		policyRule.Source.Selector = selector
	} else {
		policyRule.Destination.Selector = selector
	}
	return policyRule
}

func createNwPolicyRules(fwRule fortilib.FortiFWPolicy, ingress bool, selector string) []apiv3.Rule {

	log.Debugf("Calculating rule for policy rules for FWpolicy %+v ingress %v selector %v", fwRule, ingress, selector)
	var rules []apiv3.Rule
	// Find the TCP ports for Entity rule
	var portsTCP []numorstring.Port
	for _, svc := range fwRule.Service {
		if port, found := fortilib.FortiServicesTCP[svc]; found {
			if p, err := numorstring.PortFromString(port); err == nil {
				portsTCP = append(portsTCP, p)
			}
		}
	}
	if len(portsTCP) != 0 {
		policyRule := createRule(fwRule, ingress, selector, ProtocolTCP, portsTCP)
		rules = append(rules, policyRule)
	}

	// Find the UDP ports for Entity rule
	var portsUDP []numorstring.Port
	for _, svc := range fwRule.Service {
		if port, found := fortilib.FortiServicesUDP[svc]; found {
			if p, err := numorstring.PortFromString(port); err == nil {
				portsUDP = append(portsUDP, p)
			}
		}
	}
	if len(portsUDP) != 0 {
		policyRule := createRule(fwRule, ingress, selector, ProtocolUDP, portsUDP)
		rules = append(rules, policyRule)
	}

	// Find the supported ICMP versions for Entity rule
	icmpMap := make(map[string]bool)
	for _, svc := range fwRule.Service {
		if proto, found := fortilib.FortiServicesICMP[svc]; found {
			icmpMap[proto] = true
		}
	}

	for proto := range icmpMap {
		policyRule := createRule(fwRule, ingress, selector, proto, nil)
		rules = append(rules, policyRule)
	}

	log.Debugf("Calculated rules for policy rules for FWpolicy %+v ingress %v selector %v rules %v", fwRule, ingress, selector, rules)
	return rules
}

func CheckFWRuleParams(fwRule fortilib.FortiFWPolicy) error {

	// If Firewall rule don't have name, fail to convert GNP's
	if fwRule.Name == "" {
		log.Errorf("FortiManager's firewall rule should have name, rule: %#v", fwRule)
		return errors.New("missing rule Name in FortiManager's FW rule")
	}

	if len(fwRule.SrcAddr) == 0 || len(fwRule.DstAddr) == 0 || len(fwRule.Service) == 0 {
		if len(fwRule.SrcAddr) == 0 {
			log.Errorf("FortiManager's firewall rule should have valid label in Src Address, rule: %#v", fwRule)
			return errors.New("missing Src Addresses in FortiManager FW rule")
		}

		if len(fwRule.DstAddr) == 0 {
			log.Errorf("FortiManager's firewall rule should have valid label in Dst Address, rule: %#v", fwRule)
			return errors.New("missing Dst Addresses in FortiManager FW rule")
		}

		if len(fwRule.Service) == 0 {
			log.Errorf("FortiManager's firewall rule should have valid services, rule: %#v", fwRule)
			return errors.New("missing Service in FortiManager FW rule")
		}
	}
	return nil
}

func ConvertFWRuleToGNPs(tier, pkgName string, fwRule fortilib.FortiFWPolicy) ([]apiv3.GlobalNetworkPolicy, error) {

	log.Debugf("Converting policy %+v from package %v", fwRule, pkgName)
	// Check valid params are passed in Firewall rule.
	if err := CheckFWRuleParams(fwRule); err != nil {
		return nil, err
	}

	policyNameIng := fmt.Sprintf("%s.%s-%s", tier, fwRule.Name, "ingress")
	policyNameEgr := fmt.Sprintf("%s.%s-%s", tier, fwRule.Name, "egress")

	var selectorNameIngress string
	for idx, selectorName := range fwRule.DstAddr {
		if idx != 0 {
			selectorNameIngress += fmt.Sprintf(" && %s == %s", FwFortiManagerLabel, strconv.Quote(selectorName))
		} else {
			selectorNameIngress += fmt.Sprintf("%s == %s", FwFortiManagerLabel, strconv.Quote(selectorName))
		}
	}

	var selectorNameEgress string
	for idx, selectorName := range fwRule.SrcAddr {
		if idx != 0 {
			selectorNameEgress += fmt.Sprintf(" && %s == %s", FwFortiManagerLabel, strconv.Quote(selectorName))
		} else {
			selectorNameEgress += fmt.Sprintf("%s == %s", FwFortiManagerLabel, strconv.Quote(selectorName))
		}
	}

	annotationGNP := map[string]string{"FortiManagerPackageName": pkgName, "FWRuleName": fwRule.Name, "Comments": fwRule.Comments}
	var gnps []apiv3.GlobalNetworkPolicy
	gnpIng := apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyNameIng, Annotations: annotationGNP},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     tier,
			Selector: selectorNameIngress,
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress},
			Ingress:  createNwPolicyRules(fwRule, true, selectorNameEgress),
		},
	}
	gnps = append(gnps, gnpIng)

	policyNameIngDeny := fmt.Sprintf("%s.%s-%s-%s", tier, fwRule.Name, "ing", "deny")
	gnpIngDeny := apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyNameIngDeny, Annotations: annotationGNP},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     tier,
			Selector: selectorNameIngress,
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
		},
	}
	gnps = append(gnps, gnpIngDeny)

	gnpEgr := apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyNameEgr, Annotations: annotationGNP},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:     tier,
			Selector: selectorNameEgress,
			Types:    []apiv3.PolicyType{apiv3.PolicyTypeEgress},
			Egress:   createNwPolicyRules(fwRule, false, selectorNameIngress),
		},
	}
	gnps = append(gnps, gnpEgr)

	if selectorNameIngress != selectorNameEgress {
		policyNameEgrDeny := fmt.Sprintf("%s.%s-%s-%s", tier, fwRule.Name, "egr", "deny")
		gnpEgrDeny := apiv3.GlobalNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyNameEgrDeny, Annotations: annotationGNP},
			Spec: apiv3.GlobalNetworkPolicySpec{
				Tier:     tier,
				Selector: selectorNameEgress,
				Types:    []apiv3.PolicyType{apiv3.PolicyTypeIngress, apiv3.PolicyTypeEgress},
			},
		}
		gnps = append(gnps, gnpEgrDeny)
	}

	return gnps, nil
}
