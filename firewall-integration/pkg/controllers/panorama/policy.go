// Copyright 2019, 2021 Tigera Inc. All rights reserved.

package panorama

import (
	"fmt"
	"strings"

	panw "github.com/PaloAltoNetworks/pango"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/firewall-integration/pkg/util"
)

type zonePol struct {
	Ingress []apiv3.Rule
	Egress  []apiv3.Rule
}

// Get a map representing all possible zones merged together from Firewall and TSEE.
//
// returns a map with zone as key and TSEE policy as value.

func getZoneRuleMap(cs datastore.ClientSet, rules *Rules) ([]string, map[string]zonePol, error) {
	zoneRuleMap := make(map[string]zonePol)
	zones := make([]string, 0)
	fwZones := getZonesFromFirewall(rules)
	for _, z := range fwZones {
		if _, ok := zoneRuleMap[z]; !ok {
			zones = append(zones, z)
		}
		zoneRuleMap[z] = zonePol{}
	}

	k8sZones, err := util.GetAllZonesFromK8s(cs)
	if err != nil {
		log.WithError(err).Error("error getting zones from AAPI server.")
		return nil, nil, err
	}

	if len(k8sZones) == 0 {
		log.Warn("no pods running with label 'zone' set.")
	}

	for _, z := range k8sZones {
		if _, ok := zoneRuleMap[z]; !ok {
			zones = append(zones, z)
		}
		zoneRuleMap[z] = zonePol{}
	}

	return zones, zoneRuleMap, nil
}

func getZonesFromFirewall(rules *Rules) []string {
	zones := make([]string, 0)

	for i := range rules.PreRules {
		zones = append(zones, rules.PreRules[i].SrcZones...)
		zones = append(zones, rules.PreRules[i].DstZones...)
	}

	for i := range rules.PostRules {
		zones = append(zones, rules.PostRules[i].SrcZones...)
		zones = append(zones, rules.PostRules[i].DstZones...)
	}

	return zones
}

// Compile firewall policies into per-zone policies.
//
// The idea here is to define per-zone ingress/egress rules, native to TSEE
// network policies.

func CompilePolicies(pan *panw.Panorama, cs datastore.ClientSet, rules *Rules, testDg string) ([]string, map[string]zonePol, error) {
	orderedZones, zoneMap, err := getZoneRuleMap(cs, rules)
	if err != nil {
		log.WithError(err).Error("error getting zone information")
		return orderedZones, zoneMap, err
	}
	log.Infof("Available zones: %v", zoneMap)

	for idx := range rules.PreRules {
		for _, sz := range rules.PreRules[idx].SrcZones {
			rules := createRules(rules.PreRules[idx], rules.PreRules[idx].DstZones, false)
			zp := zoneMap[sz]
			zp.Egress = append(zp.Egress, rules...)
			zoneMap[sz] = zp
		}

		for _, dz := range rules.PreRules[idx].DstZones {
			rules := createRules(rules.PreRules[idx], rules.PreRules[idx].SrcZones, true)
			zp := zoneMap[dz]
			zp.Ingress = append(zp.Ingress, rules...)
			zoneMap[dz] = zp
		}
	}

	for idx := range rules.PostRules {
		for _, sz := range rules.PostRules[idx].SrcZones {
			rules := createRules(rules.PostRules[idx], rules.PostRules[idx].DstZones, false)
			zp := zoneMap[sz]
			zp.Egress = append(zp.Egress, rules...)
			zoneMap[sz] = zp
		}

		for _, dz := range rules.PostRules[idx].DstZones {
			rules := createRules(rules.PostRules[idx], rules.PostRules[idx].SrcZones, true)
			zp := zoneMap[dz]
			zp.Ingress = append(zp.Ingress, rules...)
			zoneMap[dz] = zp
		}
	}
	log.Infof("Compiled zoneMap: %v", zoneMap)

	// Adjust based on predefined inter-zone traffic rule.
	preDefMap, err := util.GetPredefinedDefaultSecurityRules(pan, testDg)
	if err != nil {
		log.WithError(err).Errorf("error getting predefined rules.")
		return nil, nil, err
	}
	log.Infof("preDefMap: %v", preDefMap)

	if preDefMap[IntraZoneDefault] == Allow {
		fixZoneMapForPredefinedRules(zoneMap, preDefMap)
	}

	return orderedZones, zoneMap, nil
}

func fixZoneMapForPredefinedRules(zoneMap map[string]zonePol, preDefMap map[string]string) {
	for z := range zoneMap {
		selector := fmt.Sprintf("zone == '%s'", z)
		rule := apiv3.Rule{
			Action: actions[preDefMap[IntraZoneDefault]],
		}
		irule := rule
		irule.Source.Selector = selector
		erule := rule
		erule.Destination.Selector = selector

		zp := zoneMap[z]
		zp.Ingress = append(zp.Ingress, irule)
		zp.Egress = append(zp.Egress, erule)
		zoneMap[z] = zp
	}
}

func createRules(rule Rule, zones []string, ingress bool) []apiv3.Rule {
	var polRules []apiv3.Rule

	for _, svc := range rule.Services {
		var polRule apiv3.Rule

		polRule.Action = actions[rule.Action]
		if svc.Protocol != "" {
			proto := numorstring.ProtocolFromString(svc.Protocol)
			polRule.Protocol = &proto
		}

		srcPorts := []numorstring.Port{}
		for _, p := range svc.SrcPorts {
			srcPort, _ := numorstring.PortFromString(p)
			if srcPort.MinPort < 1 || srcPort.MaxPort < 1 {
				continue
			}
			srcPorts = append(srcPorts, srcPort)
		}
		if len(srcPorts) != 0 {
			polRule.Source = apiv3.EntityRule{
				Ports: srcPorts,
			}
		}

		dstPorts := []numorstring.Port{}
		for _, p := range svc.DstPorts {
			dstPort, _ := numorstring.PortFromString(p)
			if dstPort.MinPort < 1 || dstPort.MaxPort < 1 {
				continue
			}
			dstPorts = append(dstPorts, dstPort)
		}
		if len(dstPorts) != 0 {
			polRule.Destination = apiv3.EntityRule{
				Ports: dstPorts,
			}
		}

		var selector string
		if len(zones) == 1 {
			selector = fmt.Sprintf("zone == '%s'", zones[0])
		} else {
			toSelectorExpr := strings.Join(zones, "\", \"")
			selector = fmt.Sprintf("zone in { '%s' }", toSelectorExpr)
		}

		if ingress {
			polRule.Source.Selector = selector
		} else {
			polRule.Destination.Selector = selector
		}

		polRules = append(polRules, polRule)
	}

	return polRules
}
