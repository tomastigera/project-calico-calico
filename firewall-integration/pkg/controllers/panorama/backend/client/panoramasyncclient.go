// Copyright 2022 Tigera Inc. All rights reserved.
package panoramasyncclient

import (
	"fmt"

	panw "github.com/PaloAltoNetworks/pango"
	"github.com/PaloAltoNetworks/pango/objs/addr"
	"github.com/PaloAltoNetworks/pango/objs/srvc"
	"github.com/PaloAltoNetworks/pango/poli/security"
	log "github.com/sirupsen/logrus"

	panutils "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/utils"
	"github.com/projectcalico/calico/firewall-integration/pkg/util"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// Panorama client Ids.
	PanoramaAddressClientId = "panoramaAddressClient"
	PanoramaRuleClientId    = "panoramaRuleClient"
	PanoramaServiceClientId = "panoramaServiceClient"

	// Panorama object kinds.
	PanoramaAddressKind = "PanoramaAddressKind"
	PanoramaRuleKind    = "PanoramaRuleKind"
	PanoramaServiceKind = "PanoramaServiceKind"

	PanoramaRuleEntryAny = "any"
)

type RulePanorama struct {
	Name     string
	Index    int
	Action   string
	Type     string
	Tags     []string     // ordered
	Services []srvc.Entry // unordered

	SourceZones         []string     // unordered
	SourceAddresses     []addr.Entry // unordered
	SourceAddressGroups []string     // unordered

	DestinationZones         []string     // unordered
	DestinationAddresses     []addr.Entry // unordered
	DestinationAddressGroups []string     // unordered
}

func newRulePanorama(
	rule security.Entry,
	index int,
	services []srvc.Entry,
	srcAddrs []addr.Entry,
	srcAddrGrps []string,
	srcZones []string,
	dstAddrs []addr.Entry,
	dstAddrGrps []string,
	dstZones []string,
) *RulePanorama {
	return &RulePanorama{
		Name:                     rule.Name,
		Action:                   rule.Action,
		Type:                     rule.Type,
		Index:                    index,
		Tags:                     rule.Tags,
		Services:                 services,
		SourceZones:              srcZones,
		SourceAddresses:          srcAddrs,
		SourceAddressGroups:      srcAddrGrps,
		DestinationZones:         dstZones,
		DestinationAddresses:     dstAddrs,
		DestinationAddressGroups: dstAddrGrps,
	}
}

// Panorama Firewall Policy Client.
type PanoramaFirewallPolicyClient interface {
	List() (*model.KVPairList, error)
}

type PanoramaAddressClient struct {
	// Panorama client.
	Client *panw.Panorama
	// Panorama Address device group.
	DeviceGroup string
	// Panorama Address client type name.
	ClientType string
}

// List returns a list of addresses of a specified device group. An error is returned if the call
// to Panorama client returns an error. The list of address entries are converted to the generic
// interface type.
func (pac *PanoramaAddressClient) List() (*model.KVPairList, error) {
	log.Debugf("List Panorama Addresses for device group: %s", pac.DeviceGroup)

	// Get all addresses from the Panorama datasource.
	addrs, err := pac.Client.Objects.Address.GetAll(pac.DeviceGroup)
	if err != nil {
		log.Error("failed to retrieve Panorama address entries")
		return nil, err
	}

	// Build a KVPair for each address and set it as its value. KVPairs will ultimately be processed
	// by the syncer interface.
	kvPairs := make([]*model.KVPair, 0, len(addrs))
	for _, addr := range addrs {
		kvPair := model.KVPair{
			Key: model.PanoramaObjectKey{
				Name: addr.Name,
				Kind: PanoramaRuleKind,
			},
			Value: &addr,
		}
		kvPairs = append(kvPairs, &kvPair)
	}
	kvPairList := model.KVPairList{
		KVPairs:  kvPairs,
		Revision: "",
	}

	return &kvPairList, nil
}

type PanoramaRuleClient struct {
	// Panorama client.
	Client panutils.PanoramaClient
	// Panorama Rule device group.
	DeviceGroup string
	// Panorama Rule client type name.
	ClientType string
	// Filter selector parsed from the a logical statement of Panorama tags.
	Selector *selector.Selector
}

// List returns a filtered list of the pre, post and default Panorama rules in a given device group.
// The filter matches against the Panorama rule's tags. The order of rules returned, is pre, post,
// then default type. An error is returned if the call to Panorama client returns an error. The list
// of Panorama rule entries are converted to the generic interface type. A a valid device group,
// other than "shared" must be provided to retrieve a valid response, as the Panorama API call to
//
//	GetAll rules for the "shared" device group returns an error.
func (c *PanoramaRuleClient) List() (*model.KVPairList, error) {
	log.Debugf("List Panorama Rules for device group: %s", c.DeviceGroup)

	// Get all pre rules from the Panorama datasource.
	preRulesUnfiltered, err := c.Client.GetPreRulePolicies(c.DeviceGroup)
	if err != nil {
		log.Error("failed to retrieve Panorama pre-rule entries")

		return nil, err
	}
	// Filter the pre rules.
	preRules, err := filterRules(c.Selector, preRulesUnfiltered)
	if err != nil {
		log.Error("failed to filter Panorama pre-rule entries")

		return nil, err
	}
	// Get all post rules from the Panorama datasource.
	postRulesUnfiltered, err := c.Client.GetPostRulePolicies(c.DeviceGroup)
	if err != nil {
		log.Error("failed to retrieve Panorama post-rule entries")

		return nil, err
	}
	// Filter the post rules.
	postRules, err := filterRules(c.Selector, postRulesUnfiltered)
	if err != nil {
		log.Error("failed to filter Panorama post-rule entries")

		return nil, err
	}
	// Get all default rules from the Panorama datasource.
	defaultRulesUnfiltered, err := c.getPredefinedDefaultRules()
	if err != nil {
		log.Error("failed to filter Panorama post-rule entries")

		return nil, err
	}
	// Filter the default rules.
	defaultRules, err := filterRules(c.Selector, defaultRulesUnfiltered)
	if err != nil {
		log.Error("failed to filter Panorama default-rule entries")

		return nil, err
	}

	panRules := make([]RulePanorama, 0, len(preRules)+len(postRules)+len(defaultRules))
	ruleIndex := 0
	// Retrieve the pre rule's services and addresses, and define each new Rule.
	for _, rule := range preRules {
		// The list of addresses in a Panorama rules contains both address and address group objects.
		// Address groups have to be extracted from the list of address names.
		srcAddresses := c.getAddresses(rule.SourceAddresses)
		srcAddressGroupNames := c.getAddressGroupNames(rule.SourceAddresses)
		dstAddresses := c.getAddresses(rule.DestinationAddresses)
		dstAddressGroupNames := c.getAddressGroupNames(rule.DestinationAddresses)

		services := c.getServices(rule.Services)
		// If the entry for a zone is 'any', then the zones list will be empty in the PanoramaRule.
		srcZones := []string{}
		if len(rule.SourceZones) >= 1 && rule.SourceZones[0] != PanoramaRuleEntryAny {
			srcZones = append(srcZones, rule.SourceZones...)
		}
		dstZones := []string{}
		if len(rule.DestinationZones) >= 1 && rule.DestinationZones[0] != PanoramaRuleEntryAny {
			dstZones = append(dstZones, rule.DestinationZones...)
		}

		// Define a new Panorama Rule.
		panRule := newRulePanorama(rule, ruleIndex, services,
			srcAddresses, srcAddressGroupNames, srcZones,
			dstAddresses, dstAddressGroupNames, dstZones)
		// Append the Panorama Rule to the list.
		panRules = append(panRules, *panRule)
		ruleIndex++
	}
	// Retrieve the post rule's services and addresses, and define each new Rule.
	for _, rule := range postRules {
		// The list of addresses in a Panorama rules contains both address and address group objects.
		// Address groups have to be extracted from the list of address names.
		srcAddresses := c.getAddresses(rule.SourceAddresses)
		srcAddressGroupNames := c.getAddressGroupNames(rule.SourceAddresses)
		dstAddresses := c.getAddresses(rule.DestinationAddresses)
		dstAddressGroupNames := c.getAddressGroupNames(rule.DestinationAddresses)

		services := c.getServices(rule.Services)
		// If the entry for a zone is 'any', then the zones list will be empty in the PanoramaRule.
		srcZones := []string{}
		if len(rule.SourceZones) >= 1 && rule.SourceZones[0] != PanoramaRuleEntryAny {
			srcZones = append(srcZones, rule.SourceZones...)
		}
		dstZones := []string{}
		if len(rule.DestinationZones) >= 1 && rule.DestinationZones[0] != PanoramaRuleEntryAny {
			dstZones = append(dstZones, rule.DestinationZones...)
		}

		// Define a new Panorama Rule.
		panRule := newRulePanorama(rule, ruleIndex, services,
			srcAddresses, srcAddressGroupNames, srcZones,
			dstAddresses, dstAddressGroupNames, dstZones)
		// Append the Panorama Rule to the list.
		panRules = append(panRules, *panRule)
		ruleIndex++
	}

	// Build a KVPair for each rule and set it as its value. KVPairs will ultimately be processed
	// by the syncer interface.
	kvPairs := make([]*model.KVPair, 0, len(panRules))
	for _, rule := range panRules {
		kvPair := model.KVPair{
			Key: model.PanoramaObjectKey{
				Name: rule.Name,
				Kind: PanoramaRuleKind,
			},
			Value: rule,
		}
		kvPairs = append(kvPairs, &kvPair)
	}
	kvPairList := model.KVPairList{
		KVPairs:  kvPairs,
		Revision: "",
	}

	return &kvPairList, nil
}

// filterRules returns the filtered list rules matching tags against a given selector.
// If the  is empty, then no filter is applied and the entirety of the input rules are
// returned in the responce.
func filterRules(sel *selector.Selector, rules []security.Entry) ([]security.Entry, error) {
	log.Debugf("Filter rules for match selector: %s", sel.String())

	// Iterate through the list of rules, and filter out rules that don't match the tag expression.
	filteredRules := []security.Entry{}
	for _, rule := range rules {
		labels := make(map[string]string)
		for _, tag := range rule.Tags {
			// Convert to a valid selector format.
			labels[panutils.GetRFC1123Name(tag)] = ""
		}
		if sel.Evaluate(labels) {
			// Add each matching rule to the filtered output.
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules, nil
}

// getAddresses returns the list of address entries corresponding to input names. In Panorama, a
// rule is defined by objects that reside in both the "shared" and its own device group, thus both
// are queried. Given a specific device group, GetAll returns just the list of addresses defined in
// the input device group. Similarly, a query on the "shared" device group returns only addresses
// explicitly defined in the "shared" device group. The function filters out addresses of that are
// not of type FQDN, or IPNetmask.
func (c *PanoramaRuleClient) getAddresses(names []string) []addr.Entry {
	// Note: The name 'any' is reserved, thus an address cannot be named 'any'.
	// Panoramam error: "address -> any constraints failed : 'any' is not allowed"
	if len(names) == 1 && names[0] == PanoramaRuleEntryAny {
		log.Tracef("Panorama addresses field is \"any\", returning an empty list.")
		return []addr.Entry{}
	}

	// Get all address group entries from both the user defined device groups and shared.
	deviceGroupAddressEntries, err := c.Client.GetAddressEntries(c.DeviceGroup)
	if err != nil {
		log.WithError(err).Debugf("failed to retrieve address groups list from device group: %s",
			c.DeviceGroup)
	}
	sharedAddressEntries, err := c.Client.GetAddressEntries("shared")
	if err != nil {
		log.WithError(err).Debugf("failed to retrieve address groups list from device group: %s",
			c.DeviceGroup)
	}
	addressMap := make(map[string]addr.Entry)
	for _, address := range deviceGroupAddressEntries {
		addressMap[address.Name] = address
	}
	for _, address := range sharedAddressEntries {
		addressMap[address.Name] = address
	}

	// Cross reference the address entries against the list of input names to compiles the list of
	// address entries.
	addresses := []addr.Entry{}
	for _, name := range names {
		if item, exists := addressMap[name]; exists {
			addresses = append(addresses, item)
		}
	}

	return addresses
}

// getAddressGroupNames returns the list of address entries corresponding to input names. In
// Panorama, a rule is defined by objects that reside in both the "shared" and its own device group,
// thus both are queried. Given a specific device group, GetList returns just the list of addresses
// groups defined in the input device group. Similarly, a query on the "shared" device group returns
// only addresses groups explicitly defined in the "shared" device group. Errors are logged as debug
// logs.
func (c *PanoramaRuleClient) getAddressGroupNames(names []string) []string {
	// Note: The name 'any' is reserved, thus an address group cannot be named 'any'.
	// Panoramam error: "address group -> any constraints failed : 'any' is not allowed"
	if len(names) == 1 && names[0] == PanoramaRuleEntryAny {
		log.Tracef("Panorama addresses field is \"any\", returning an empty list.")
		return []string{}
	}

	// Get all address group entries from both the user defined device groups and shared.
	deviceGroupAddressGroups, err := c.Client.GetAddressGroups(c.DeviceGroup)
	if err != nil {
		log.WithError(err).Debugf("failed to retrieve address groups list from device group: %s",
			c.DeviceGroup)
	}
	sharedAddressGroups, err := c.Client.GetAddressGroups("shared")
	if err != nil {
		log.WithError(err).Debugf("failed to retrieve address groups list from device group: %s",
			c.DeviceGroup)
	}
	addressGroupSet := set.FromArray(append(deviceGroupAddressGroups, sharedAddressGroups...))
	// Cross reference the address groups to the list of input names.
	addressGroups := []string{}
	for _, name := range names {
		if addressGroupSet.Contains(name) {
			addressGroups = append(addressGroups, name)
		}
	}

	return addressGroups
}

// getServices returns a list of Panorama service objects. In Panorama, a rule is defined by objects
// that reside in both the "shared" and its own device group, thus both are queried. Given a
// specific device group, GetAll returns just the list of services defined in the input device
// group. Similarly, a query on the "shared" device group returns only services explicitly defined
// in the "shared" device group. Errors are logged as debug logs.
func (c *PanoramaRuleClient) getServices(names []string) []srvc.Entry {
	// Note: The name 'any' is reserved, thus a service cannot be named 'any'.
	// Panoramam error: "service -> any constraints failed : 'any' is not allowed"
	if len(names) == 1 && names[0] == PanoramaRuleEntryAny {
		log.Tracef("Panorama addresses field is \"any\", returning an empty list.")
		return []srvc.Entry{}
	}

	deviceGroupServiceEntries, err := c.Client.GetServiceEntries(c.DeviceGroup)
	if err != nil {
		log.WithError(err).Debugf("failed to retrieve the services from device group: %s",
			c.DeviceGroup)
	}
	sharedServiceEntries, err := c.Client.GetServiceEntries("shared")
	if err != nil {
		log.WithError(err).Debugf("failed to retrieve the services from device group: %s",
			c.DeviceGroup)
	}
	serviceMap := make(map[string]srvc.Entry)
	for _, service := range deviceGroupServiceEntries {
		serviceMap[service.Name] = service
	}
	for _, service := range sharedServiceEntries {
		serviceMap[service.Name] = service
	}

	services := []srvc.Entry{}
	for _, name := range names {
		if item, exists := serviceMap[name]; exists {
			services = append(services, item)
		}
	}

	return services
}

func (c *PanoramaRuleClient) getPredefinedDefaultRules() ([]security.Entry, error) {
	rules := []security.Entry{}
	var response util.PredefinedSecurityRulesResponse
	// Get "shared" post rulebase default rules.
	if _, err := c.Client.Get("/config/shared/post-rulebase/default-security-rules", &response); err != nil {
		log.Infof("No shared pre-defined security rules.")
	} else {
		log.Infof("shared overridden default rules(response): %v", response)
		for _, r := range response.Rules {
			rule := security.Entry{Name: r.Name, Action: r.Action}
			rules = append(rules, rule)
		}
	}
	// Get device group's post rulebase default rules.
	xp := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/default-security-rules", c.DeviceGroup)
	if _, err := c.Client.Get(xp, &response); err != nil {
		log.Infof("No device-group pre-defined security rules.")
		// No error needed, move to the next step.
	} else {
		log.Infof("device-group predefined rules(response): %v", response)
		for _, r := range response.Rules {
			rule := security.Entry{Name: r.Name, Action: r.Action}
			rules = append(rules, rule)
		}
	}
	// Get predefined rulebase default rules.
	if _, err := c.Client.Get("/config/predefined/default-security-rules", &response); err != nil {
		log.WithError(err).Error("error reading pre-defined default rules.")
		return rules, err
	} else {
		log.Infof("pre-defined default rules(response): %v", response)
		for _, r := range response.Rules {
			rule := security.Entry{Name: r.Name, Action: r.Action}
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

type PanoramaServiceClient struct {
	// Panorama client.
	Client panutils.PanoramaApiClient
	// Panorama Service device group.
	DeviceGroup string
	// Panorama Service client type name.
	ClientType string
}

func (psc *PanoramaServiceClient) List() (*model.KVPairList, error) {
	log.Debugf("List Panorama Services for device group: %s", psc.DeviceGroup)

	// Get all services from the Panorama datasource.
	srvs, err := psc.Client.GetServiceEntries(psc.DeviceGroup)
	if err != nil {
		log.Error("failed to retrieve Panorama service entries")
		return nil, err
	}

	// Build a KVPair for each service and set it as its value. KVPairs will ultimately be processed
	// by the syncer interface.
	kvPairs := make([]*model.KVPair, 0, len(srvs))
	for _, srv := range srvs {
		kvPair := model.KVPair{
			Key: model.PanoramaObjectKey{
				Name: srv.Name,
				Kind: "PanoramaServiceKind",
			},
			Value: &srv,
		}
		kvPairs = append(kvPairs, &kvPair)
	}

	kvPairList := model.KVPairList{
		KVPairs:  kvPairs,
		Revision: "",
	}

	return &kvPairList, nil
}
