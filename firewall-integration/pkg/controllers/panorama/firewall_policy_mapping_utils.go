// Copyright (c) 2022 Tigera, Inc. All rights reserved.
package panorama

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PaloAltoNetworks/pango/objs/addr"
	"github.com/PaloAltoNetworks/pango/objs/srvc"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	panclient "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/backend/client"
	panutils "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/utils"
)

const (
	AddressNameAnnotationPrefix      = "address"
	AddressGroupNameAnnotationPrefix = "address-group"
	ZoneNameAnnotationPrefix         = "zone"

	RuleAnnotationKey        = FirewallPrefix + "rule"
	SourceAnnotationKey      = FirewallPrefix + "source"
	DestinationAnnotationKey = FirewallPrefix + "destination"
	RankAnnotationKey        = FirewallPrefix + "rank"
)

type UpdateRules struct {
	name    string
	egress  []v3.Rule
	ingress []v3.Rule
}

// newGlobalNetworkPolicy returns a pointer to a GlobalNetworkPolicy.
func newGlobalNetworkPolicy(zoneName, gnpName, tier string, order *float64) *v3.GlobalNetworkPolicy {
	log.Infof("Create a new Panorama global network policy: %s", zoneName)

	return &v3.GlobalNetworkPolicy{
		TypeMeta:   metav1.TypeMeta{Kind: "GlobalNetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{Name: gnpName},
		Spec: v3.GlobalNetworkPolicySpec{
			Tier:           tier,
			PreDNAT:        false,
			Order:          order,
			Egress:         []v3.Rule{},
			Ingress:        []v3.Rule{},
			Selector:       fmt.Sprintf("%s%s == '%s'", FirewallPrefix, PanoramaZoneKeyName, zoneName),
			DoNotTrack:     false,
			ApplyOnForward: false,
			Types:          []v3.PolicyType{},
		},
	}
}

// createBasicGlobalNetworkPolicy returns a firewall policy integration GlobalNetworkPolicy.
func createBasicGlobalNetworkPolicy(zoneName, gnpName, tier string, order *float64) *v3.GlobalNetworkPolicy {
	gnp := newGlobalNetworkPolicy(zoneName, gnpName, tier, order)
	// Define firewall integration annotations.
	gnp.Annotations = map[string]string{
		fmt.Sprintf("%s%s", FirewallPrefix, "type"):        ParoramaType,
		fmt.Sprintf("%s%s", FirewallPrefix, "object-type"): "Zone",
	}

	return gnp
}

// generateGlobalNetworkPolicyName prepends a prefix to indicate the GNP is a Panorama
// policy. The name is converted to a RFC1123 compliant string, with a generated hash postfix
// appended to the end, if a conversion is necessary to be compliant.
// The policy generated will contain the tier name as a prefix by default, so no need to add it
// here.
func generateGlobalNetworkPolicyName(tier, name string) (string, error) {
	gnpName, err := panutils.GetRFC1123PolicyName(tier, fmt.Sprintf("%s-%s-%s", PanoramaPolicyNamePrefix, PanoramaZoneKeyName, name))
	if err != nil {
		return "", err
	}
	log.Debugf("Generated GlobalNetworkSet name: %s", gnpName)

	return gnpName, nil
}

// getRuleAnnotations defines the v3 rule annotations, provided a Panorama rule name, a source and
// destination name of the objects that are mapped within the Panorama rule. The index identifies
// the Panorama rule rank.
func getRuleAnnotations(rule, src, dst string, index int) map[string]string {
	annotations := make(map[string]string)
	annotations[RuleAnnotationKey] = rule
	annotations[SourceAnnotationKey] = src
	annotations[DestinationAnnotationKey] = dst
	annotations[RankAnnotationKey] = strconv.Itoa(index)

	return annotations
}

func getZoneAnnotationName(name string) string {
	return fmt.Sprintf("%s.%s", ZoneNameAnnotationPrefix, name)
}

func getAddressAnnotationName(name string) string {
	return fmt.Sprintf("%s.%s", AddressNameAnnotationPrefix, name)
}

func getAddressGroupAnnotationName(name string) string {
	return fmt.Sprintf("%s.%s", AddressGroupNameAnnotationPrefix, name)
}

// getGlobalNetworkPolicyTypes defines the pilicy types to ingress, egress, indicating the existence of
// rules in the policy.
func getGlobalNetworkPolicyTypes(ingress, egress bool) []v3.PolicyType {
	if ingress && egress {
		return []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress}
	} else if ingress && !egress {
		return []v3.PolicyType{v3.PolicyTypeIngress}
	} else if !ingress && egress {
		return []v3.PolicyType{v3.PolicyTypeEgress}
	}

	return []v3.PolicyType{}
}

// createUpdateV3Rules creates a set of policies for each zone mapping within the Panorama rule.
// Each source to destination mapping in a Panorama rule defines an ingress and egress set of v3
// Calico rules. A policy that is defined for the source of Panorama rule will define egress, and
// a policy that is defined for a destination will define ingress v3 Calico rules.
func createUpdateV3Rules(rule panclient.RulePanorama) map[string]*UpdateRules {
	updateRules := make(map[string]*UpdateRules)

	// For each destination zone, create ingress rules that
	// - selects the source zone, and allows traffic to ports/protocols in Panorama service"
	// - allows traffic from address mapped to CIDRs, or domains
	// - allows traffic from address groups mapped to networksets which in turn are used as label selectors
	for _, dstZone := range rule.DestinationZones {
		dstZoneName := getZoneAnnotationName(dstZone)
		// Create a new update rule if it hasn't already been created.
		if _, exists := updateRules[dstZone]; !exists {
			updateRules[dstZone] = &UpdateRules{name: dstZone}
		}
		// Create ingress rules for zones.
		for _, srcZone := range rule.SourceZones {
			// Avoid adding an ingress rule from a source to the same destination.
			srcZoneName := getZoneAnnotationName(srcZone)
			annotations := getRuleAnnotations(rule.Name, srcZoneName, dstZoneName, rule.Index)
			// Base case, no service defined, will return a single rule. Otherwise, a new rule will be
			// defined for each service present in the Panorama rule.
			v3Rules := createIngressV3Rules(PanoramaZoneKeyName, srcZone, rule.Action, annotations, rule.Services)
			updateRules[dstZone].ingress = append(updateRules[dstZone].ingress, v3Rules...)
		}
		// Create ingress rules for address groups
		for _, srcAddrGrp := range rule.SourceAddressGroups {
			srcAddrGrpNameWithPrefix := getAddressGroupAnnotationName(srcAddrGrp)
			annotations := getRuleAnnotations(rule.Name, srcAddrGrpNameWithPrefix, dstZoneName, rule.Index)
			// Base case, no service defined, will return a single rule. Otherwise, a new rule will be
			// defined for each service present in the Panorama rule.
			v3Rules := createIngressV3Rules(PanoramaAddressGroupKeyName, srcAddrGrp, rule.Action, annotations, rule.Services)
			updateRules[dstZone].ingress = append(updateRules[dstZone].ingress, v3Rules...)
		}
		// Create ingress rules for addresses
		for _, srcAddr := range rule.SourceAddresses {
			srcAddrName := getAddressAnnotationName(srcAddr.Name)
			annotations := getRuleAnnotations(rule.Name, srcAddrName, dstZoneName, rule.Index)
			// Base case, no service defined, will return a single rule. Otherwise, a new rule will be
			// defined for each service present in the Panorama rule.
			v3Rules := createIngressV3RulesForAddresses(srcAddr, rule.Action, annotations, rule.Services)
			updateRules[dstZone].ingress = append(updateRules[dstZone].ingress, v3Rules...)
		}
	}

	// For each destination zone, create egress rules that
	// - selects the destination zone, and allows traffic to ports/protocols in Panorama service"
	// - allows traffic from address mapped to CIDRs
	// - allows traffic from address groups mapped to networksets which in turn are used as label selectors
	for _, srcZone := range rule.SourceZones {
		srcZoneName := getZoneAnnotationName(srcZone)
		// Create a new update rule if it hasn't already been created.
		if _, ok := updateRules[srcZone]; !ok {
			updateRules[srcZone] = &UpdateRules{name: srcZone}
		}
		// Create egress rules for zones.
		for _, dstZone := range rule.DestinationZones {
			dstZoneName := getZoneAnnotationName(dstZone)
			annotations := getRuleAnnotations(rule.Name, srcZoneName, dstZoneName, rule.Index)
			// Base case, no service defined, will return a single rule. Otherwise, a new rule will be
			// defined for each service present in the Panorama rule.
			v3Rules := createEgressV3Rules(PanoramaZoneKeyName, dstZone, rule.Action, annotations, rule.Services)
			updateRules[srcZone].egress = append(updateRules[srcZone].egress, v3Rules...)
		}
		// Create egress rules for address groups.
		for _, dstAddrGrp := range rule.DestinationAddressGroups {
			dstAddrGrpNameWithPrefix := getAddressGroupAnnotationName(dstAddrGrp)
			annotations := getRuleAnnotations(rule.Name, srcZoneName, dstAddrGrpNameWithPrefix, rule.Index)
			// Base case, no service defined, will return a single rule. Otherwise, a new rule will be
			// defined for each service present in the Panorama rule.
			v3Rules := createEgressV3Rules(PanoramaAddressGroupKeyName, dstAddrGrp, rule.Action, annotations, rule.Services)
			updateRules[srcZone].egress = append(updateRules[srcZone].egress, v3Rules...)
		}
		// Create egress rules for addresses.
		for _, dstAddr := range rule.DestinationAddresses {
			dstAddrName := getAddressAnnotationName(dstAddr.Name)
			annotations := getRuleAnnotations(rule.Name, srcZoneName, dstAddrName, rule.Index)
			// Base case, no service defined, will return a single rule. Otherwise, a new rule will be
			// defined for each service present in the Panorama rule.
			v3Rules := createEgressV3RulesForAddresses(dstAddr, rule.Action, annotations, rule.Services)
			updateRules[srcZone].egress = append(updateRules[srcZone].egress, v3Rules...)
		}
	}

	return updateRules
}

// createIngressV3Rules creates a list of new ingress rules for each service defined within the same
// device group (or 'shared'). A single rule is returned if no service is defined.
func createIngressV3Rules(panType, name, action string, annotations map[string]string, services []srvc.Entry) []v3.Rule {
	// An ingress rule is defined by the source entity selector.
	if len(name) == 0 {
		log.Trace("The rule will not be created for an empty name.")
		return nil
	}

	rules := []v3.Rule{}
	v3Action := panoramaActionToCalico(action)
	var srcEntity v3.EntityRule
	// Panorama returns 'any' if no value has been added to the destination object.
	if name != "any" {
		srcEntity = v3.EntityRule{
			Selector: fmt.Sprintf("%s%s == '%s'", FirewallPrefix, panType, name),
		}
	}
	if len(services) == 0 {
		// A single rule will be returned if no services have been defined in the Panorama rule.
		rules = append(rules, v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: annotations,
			},
			Action: v3Action,
			Source: srcEntity,
		})
	} else {
		// Iterate through the list of services and create a new Calico rule for each one.
		for _, service := range services {
			protocol := numorstring.ProtocolFromString(service.Protocol)
			// Add just the ports as the selector has already been defined for the source entity.
			srcEntity.Ports = panoramaPortsToCalico(service.SourcePort, protocol)

			dstPorts := panoramaPortsToCalico(service.DestinationPort, protocol)
			dstEntity := v3.EntityRule{
				Ports: dstPorts,
			}
			rules = append(rules, v3.Rule{
				Metadata: &v3.RuleMetadata{
					Annotations: annotations,
				},
				Action:      v3Action,
				Protocol:    &protocol,
				Source:      srcEntity,
				Destination: dstEntity,
			})
		}
	}

	return rules
}

// createIngressV3RulesForAddresses creates a new ingress rules given an action and a list of
// services. If the services are empty, then will return a single rule defined by its action,
// address and annotations.
func createIngressV3RulesForAddresses(srcAddress addr.Entry, action string, annotations map[string]string, services []srvc.Entry) []v3.Rule {
	rules := []v3.Rule{}

	v3Action := panoramaActionToCalico(action)

	// Define only the source entity for an ingress rule. Supported types are IPNetmask, and FQDN.
	var srcEntityRule v3.EntityRule
	switch srcAddress.Type {
	case panutils.IpNetmask:
		srcEntityRule = v3.EntityRule{
			Nets: []string{srcAddress.Value},
		}
	case panutils.Fqdn:
		srcEntityRule = v3.EntityRule{
			Domains: []string{srcAddress.Value},
		}
	default:
		log.Debugf("The controller supports IPNetmask, and FQDN, cannot handle address type %s",
			srcAddress.Type)

		return nil
	}

	if len(services) == 0 {
		rules = append(rules, v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: annotations,
			},
			Action: v3Action,
			Source: srcEntityRule,
		})
	} else {
		for _, service := range services {
			// Add a new rule for every service.
			protocol := numorstring.ProtocolFromString(service.Protocol)
			srcEntityRule.Ports = panoramaPortsToCalico(service.SourcePort, protocol)
			dstPorts := panoramaPortsToCalico(service.DestinationPort, protocol)
			rules = append(rules, v3.Rule{
				Metadata: &v3.RuleMetadata{
					Annotations: annotations,
				},
				Action:   v3Action,
				Protocol: &protocol,
				Source:   srcEntityRule,
				Destination: v3.EntityRule{
					Ports: dstPorts,
				},
			})
		}
	}

	return rules
}

// createIngressV3Rules creates a list of new egress rules for each service defined within the same
// device group (or 'shared'). A single rule is returned if no service is defined.
func createEgressV3Rules(panType, name, action string, annotations map[string]string, services []srvc.Entry) []v3.Rule {
	// An egress rule is defined by the source entity selector.
	if len(name) == 0 {
		log.Trace("The rule will not be created for an empty name.")
		return nil
	}

	rules := []v3.Rule{}
	v3Action := panoramaActionToCalico(action)
	var dstEntity v3.EntityRule
	// Panorama returns 'any' if no value has been added to the destination object.
	if name != "any" {
		dstEntity = v3.EntityRule{
			Selector: fmt.Sprintf("%s%s == '%s'", FirewallPrefix, panType, name),
		}
	}
	if len(services) == 0 {
		// A single rule will be returned if no services have been defined in the Panorama rule.
		rules = append(rules, v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: annotations,
			},
			Action:      v3Action,
			Destination: dstEntity,
		})
	} else {
		// Iterate through the list of services and create a new Calico rule for each one.
		for _, service := range services {
			protocol := numorstring.ProtocolFromString(service.Protocol)
			srcPorts := panoramaPortsToCalico(service.SourcePort, protocol)
			srcEntity := v3.EntityRule{
				Ports: srcPorts,
			}
			// Add just the ports to the already defined destination entity.
			dstEntity.Ports = panoramaPortsToCalico(service.DestinationPort, protocol)
			rules = append(rules, v3.Rule{
				Metadata: &v3.RuleMetadata{
					Annotations: annotations,
				},
				Action:      v3Action,
				Protocol:    &protocol,
				Source:      srcEntity,
				Destination: dstEntity,
			})
		}
	}

	return rules
}

// createEgressV3RulesForAddresses creates a new egress rules given an action and a list of
// services. If the services are empty, then will return a single rule defined by its action,
// address and annotations.
func createEgressV3RulesForAddresses(dstAddress addr.Entry, action string, annotations map[string]string, services []srvc.Entry) []v3.Rule {
	rules := []v3.Rule{}

	v3Action := panoramaActionToCalico(action)

	// Define only the destination entity for an egress rule. Supported types are IPNetmask, and FQDN.
	var dstEntityRule v3.EntityRule
	switch dstAddress.Type {
	case panutils.IpNetmask:
		dstEntityRule = v3.EntityRule{
			Nets: []string{dstAddress.Value},
		}
	case panutils.Fqdn:
		dstEntityRule = v3.EntityRule{
			Domains: []string{dstAddress.Value},
		}
	default:
		log.Debugf("The controller supports IPNetmask, and FQDN, cannot handle address type %s",
			dstAddress.Type)

		return nil
	}

	if len(services) == 0 {
		rules = append(rules, v3.Rule{
			Metadata: &v3.RuleMetadata{
				Annotations: annotations,
			},
			Action:      v3Action,
			Destination: dstEntityRule,
		})
	} else {
		for _, service := range services {
			// Add a new rule for every service.
			protocol := numorstring.ProtocolFromString(service.Protocol)
			srcPorts := panoramaPortsToCalico(service.SourcePort, protocol)
			dstEntityRule.Ports = panoramaPortsToCalico(service.DestinationPort, protocol)
			rules = append(rules, v3.Rule{
				Metadata: &v3.RuleMetadata{
					Annotations: annotations,
				},
				Action:   v3Action,
				Protocol: &protocol,
				Source: v3.EntityRule{
					Ports: srcPorts,
				},
				Destination: dstEntityRule,
			})
		}
	}

	return rules
}

// deleteV3Rule deletes a key from the list of rules. The key is compared to the value of the "name"
// metadata annotation. The first occurrance is deleted and function returns.
// O(n) average to remove an element from a slice.
func deleteV3Rule(rules []v3.Rule, key string) []v3.Rule {
	log.Debugf("Delete the key: %s", key)

	newRules := []v3.Rule{}
	// Delete the rule with the same name from the list of rules.
	for i := 0; i < len(rules); i++ {
		if key != rules[i].Metadata.Annotations[RuleAnnotationKey] {
			newRules = append(newRules, rules[i])
		}
	}

	return newRules
}

// insertV3Rule inserts a rule into a list by its rank. Returns logs an error and returns if the
// rank cannot be converted to an integer for comparison.
// O(n) average to insert an element from a slice.
func insertV3Rule(rules []v3.Rule, rule v3.Rule) ([]v3.Rule, error) {
	insertRank, err := strconv.Atoi(rule.Metadata.Annotations[RankAnnotationKey])
	if err != nil {
		log.WithError(err).Errorf("Cannot convert rule %s rank to integer", rule.Metadata.Annotations[fmt.Sprintf("%s%s", FirewallPrefix, "name")])
		return rules, fmt.Errorf(
			"failed to insert mapping from source: %s to destination: %s, in rule: %s: %s",
			rule.Metadata.Annotations[SourceAnnotationKey], rule.Metadata.Annotations[DestinationAnnotationKey],
			rule.Metadata.Annotations[RuleAnnotationKey], err.Error())
	}
	for i := 0; i < len(rules); i++ {
		rank, err := strconv.Atoi(rules[i].Metadata.Annotations[RankAnnotationKey])
		if err != nil {
			log.WithError(err).Errorf("Cannot convert rule %s rank to integer", rules[i].Metadata.Annotations[RankAnnotationKey])
			return rules, fmt.Errorf(
				"failed to convert rank while comparing against rule with source: %s, destination: %s, in rule: %s: %s",
				rules[i].Metadata.Annotations[SourceAnnotationKey], rules[i].Metadata.Annotations[DestinationAnnotationKey],
				rules[i].Metadata.Annotations[RuleAnnotationKey], err.Error())
		}
		// inserting into slice will shift other values to the right.
		if insertRank <= rank {
			rules = append(rules[:i+1], rules[i:]...)
			rules[i] = rule

			return rules, nil
		}
	}
	// Append rule to the end of list, if the policy's rules list is empty.
	rules = append(rules, rule)

	return rules, nil
}

// panoramaActionToCalico converts a Panorama to a Calico action. All actions other than "allow" are
// mapped to v3.Deny.
func panoramaActionToCalico(action string) v3.Action {
	var v3Action v3.Action
	// All actions that are not "allow" will be mapped to "deny".
	if v3.Action(action) == "allow" {
		v3Action = v3.Action(v3.Allow)
	} else {
		v3Action = v3.Action(v3.Deny)
	}

	return v3Action
}

// panoramaPortsToCalico splits the input string into a numorstring.Port array. SCTP protocol is not
// supported and will return an empty list. Will log an error if numorstring cannot resolve the
// ports string and will not add any ports to the entity rule. Will log and not add any ports to the
// entity rule if one of the ports resolves to an invalid ports number.
func panoramaPortsToCalico(port string, protocol numorstring.Protocol) []numorstring.Port {
	ports := []numorstring.Port{}

	if len(port) == 0 {
		return ports
	}

	if protocol.StrVal == "sctp" {
		// no support for SCTP ports in networkpolicy rule.
		log.Debug("Network policy does not support sctp. The ports are not added to the rule.")
		return ports
	}
	// Remove all spaces.
	portNoSpaces := strings.ReplaceAll(port, " ", "")
	// Split the comma separated ports into arrays.
	portsArray := strings.Split(portNoSpaces, ",")
	// Define the rule's source ports.
	for _, portStr := range portsArray {
		// Split the port range, separated by a "-" character.
		portRange := strings.Split(portStr, "-")

		var port numorstring.Port
		var err error
		if len(portRange) == 1 {
			port, err = numorstring.PortFromString(portStr)
			if err != nil {
				log.Errorf("cannot convert port %s, with error: %s", portStr, err.Error())
				continue
			}
		} else if len(portRange) == 2 {
			portMin, err := strconv.Atoi(portRange[0])
			if err != nil {
				log.WithError(err).Errorf("failed to convert port range min: %s to an integer", portRange[0])
			}
			portMax, err := strconv.Atoi(portRange[1])
			if err != nil {
				log.WithError(err).Errorf("failed to convert port range max: %s to an integer", portRange[1])
			}
			port, err = numorstring.PortFromRange(uint16(portMin), uint16(portMax))
			if err != nil {
				log.WithError(err).Errorf("cannot convert port range min: %d and max: %d", portMin, portMax)
				continue
			}
		} else {
			log.Errorf("cannot handle port value: %s", portStr)
			continue
		}

		if port.MinPort < 1 || port.MaxPort < 1 {
			log.Debugf("Cannot add the port to source ports. Min or Max port resolves to an invalid port"+
				" number, MinPort: %d, MaxPort: %d", port.MinPort, port.MaxPort)
			continue
		}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		log.Debug("No ports added to entity rule.")
	}

	return ports
}
