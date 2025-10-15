// Copyright 2019-2021 Tigera Inc. All rights reserved.

package panorama

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	panw "github.com/PaloAltoNetworks/pango"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/firewall-integration/pkg/cache"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	"github.com/projectcalico/calico/firewall-integration/pkg/util"
)

const (
	Shared               = "shared"
	PreRuleBase          = "pre-rulebase"
	PostRuleBase         = "post-rulebase"
	PreDefined           = "predefined"
	IntraZoneDefault     = "intrazone-default"
	InterZoneDefault     = "interzone-default"
	NetworkPolicyPrefix  = "fw"
	Allow                = "allow"
	HasZone              = "has(zone)"
	PassToNextTierPolicy = "pass-to-next-tier"
	SystemTierLabel      = "projectcalico.org/system-tier"
)

var (
	lastTimeStamp int64
	securityRules Rules
)

type Service struct {
	Protocol string
	SrcPorts []string
	DstPorts []string
}

type Rule struct {
	Name     string
	SrcZones []string
	DstZones []string
	SrcCIDR  string
	DstCIDR  string
	Services []Service
	Action   string
}

type Rules struct {
	PreRules  []Rule
	PostRules []Rule
}

var actions = map[string]apiv3.Action{
	"allow": apiv3.Allow,
	"deny":  apiv3.Deny,
	"log":   apiv3.Log,
	"pass":  apiv3.Pass,
}

func (pc *PanoramaController) fwIntegrate() {
	// Get FW policies.
	ts, err := util.GetLatestConfigTimestamp(pc.panwClient)
	if err != nil {
		log.Fatalf("Error getting LatestConfig Timestamp: %s", err)
		return
	}

	if ts > lastTimeStamp {
		securityRules = Rules{}
		err = getSecurityRules(pc.panwClient, pc.cfg, &securityRules)
		if err != nil {
			log.Fatalf("Error reading FW Rules: %s", err)
			return
		}
		log.Infof("Rules: %v", securityRules)
		lastTimeStamp = ts
	} else {
		log.Info("No new configuration available, apply the last compiled policies.")
	}

	orderedZones, zoneMap, err := CompilePolicies(pc.panwClient, pc.calicoClient, &securityRules, pc.cfg.FwDeviceGroup)
	if err != nil {
		log.Fatalf("Error compiling policies: %v", err)
	}
	log.Infof("orderedZones: %v", orderedZones)

	err = createUpdateTierForPanorama(pc.calicoClient, pc.cfg)
	if err != nil {
		log.Fatalf("Error creating Tier resource")
	}

	// Cache global network policies.
	pc.gnpCache.SyncDatastoreBackoff()

	fwNetPols := make(map[string]bool)
	order := float64(0)
	for _, zoneName := range orderedZones {
		zoneMapVal := zoneMap[zoneName]
		log.Infof("zoneMap[%s]: %v", zoneName, zoneMapVal)
		if err := createUpdateNetworkPolicy(pc.cfg, pc.calicoClient, zoneName, zoneMapVal, order, fwNetPols, pc.gnpCache); err != nil {
			log.Error("error creating policy")
		}
		order = order + 1
	}
	log.Infof("Network policies from Firewall: %v", fwNetPols)

	if pc.cfg.TSPassToNextTier {
		polName, err := addPassToNextTier(pc.cfg, pc.calicoClient, order)
		if err != nil {
			log.WithError(err).Errorf("error adding default zone label policy")
			return
		}
		fwNetPols[polName] = true
	}

	// Get diff of fwNetPols and available globalnetworkpolicies.
	netPolsAvailable, err := util.GetAllPoliciesFromFwTier(pc.calicoClient, pc.cfg.TSTierPrefix)
	if err != nil {
		log.WithError(err).Errorf("Error getting GNPs")
		return
	}
	log.Infof("network policies available: %v", netPolsAvailable)

	netPolsToDelete := make([]string, 0)
	for _, polName := range netPolsAvailable {
		if !fwNetPols[polName] {
			netPolsToDelete = append(netPolsToDelete, polName)
		}
	}
	log.Infof("network policies to be deleted: %v", netPolsToDelete)
	for _, polName := range netPolsToDelete {
		err := pc.calicoClient.GlobalNetworkPolicies().Delete(context.Background(), polName, metav1.DeleteOptions{})
		if err != nil {
			log.WithError(err).Errorf("error deleting GNP, %s", polName)
		}
	}
}

// createUpdateTierForPanorama checks if a tier already exists. If not, create else update.
func createUpdateTierForPanorama(cl datastore.ClientSet, cfg *config.Config) error {
	expectedTierName := cfg.TSTierPrefix
	order, _ := strconv.ParseFloat(cfg.TSTierOrder, 64)
	// const labels applied to all Tiers interacted by fw
	tierLabels := map[string]string{
		SystemTierLabel: strconv.FormatBool(true),
	}

	// Lookup to see if this object already exists in the datastore.
	t, err := cl.Tiers().Get(context.Background(), expectedTierName, metav1.GetOptions{})

	log.Debugf("Create/Update Tiers in Calico datastore")

	if err != nil {
		// Doesn't exist - create it.
		tier := apiv3.Tier{}
		tier.Name = cfg.TSTierPrefix
		tier.Labels = tierLabels
		tier.Spec.Order = &order

		_, err := cl.Tiers().Create(context.Background(), &tier, metav1.CreateOptions{})
		if err != nil {
			log.WithError(err).Warning("Failed to create tier")
			return err
		}
		log.Debugf("Successfully created tier")
		return nil
	}

	// The policy already exists, update it and write it back to the datastore.
	t.Spec.Order = &order
	t.Labels = tierLabels
	_, err = cl.Tiers().Update(context.Background(), t, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Warning("Failed to update tier")
		return err
	}

	log.Debugf("Successfully updated Tier")
	return nil
}

// Check if a tier already exists. If not, create else update.
func createUpdateNetworkPolicy(cfg *config.Config, cl datastore.ClientSet, zoneName string, zonePol zonePol, order float64, netPols map[string]bool, gnpc *cache.GnpCache) error {
	// Poupulate GlobalNetworkPolicy definition.
	gnp := apiv3.GlobalNetworkPolicy{}
	gnp.Name = fmt.Sprintf("%s.%s-zone-%s", cfg.TSTierPrefix, cfg.TSNetworkPrefix, strings.Replace(strings.ToLower(zoneName), " ", "-", len(zoneName)-1))
	gnp.Spec.Tier = cfg.TSTierPrefix
	gnp.Spec.PreDNAT = false
	gnp.Spec.Order = &order
	gnp.Spec.Ingress = zonePol.Ingress
	gnp.Spec.Egress = zonePol.Egress
	gnp.Spec.Selector = fmt.Sprintf("zone == '%s'", zoneName)
	gnp.Spec.DoNotTrack = false
	gnp.Spec.ApplyOnForward = false
	gnp.Spec.Types = []apiv3.PolicyType{apiv3.PolicyTypeEgress, apiv3.PolicyTypeIngress}

	// Check cache for if the global network policy is indeed updated.
	if gnpc.PolicyNotChanged(gnp.Name, gnp) {
		log.Info("GNP unchanged, skipping create/update...")
		netPols[gnp.Name] = true
		return nil
	}

	// Create/Update GlobalNetworkPolicy resources.
	log.Debugf("Create/Update GlobalNetworkPolicy in Calico datastore")
	// Lookup to see if this object already exists in the datastore.
	g, err := cl.GlobalNetworkPolicies().Get(context.Background(), gnp.Name, metav1.GetOptions{})
	if err != nil {
		_, err := cl.GlobalNetworkPolicies().Create(context.Background(), &gnp, metav1.CreateOptions{})
		if err != nil {
			log.WithError(err).Warning("Failed to create global network policies")
			return err
		}
		log.Debugf("Successfully created global network policies")
		netPols[gnp.Name] = true
		return nil
	}

	// The policy already exists, update it and write it back to the datastore.
	g.Spec = gnp.Spec
	_, err = cl.GlobalNetworkPolicies().Update(context.Background(), g, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Warning("Failed to update GNP")
		return err
	}
	log.Debugf("Successfully updated GlobalNetworkPolicy")

	netPols[gnp.Name] = true
	return nil
}

func addPassToNextTier(cfg *config.Config, cl datastore.ClientSet, order float64) (string, error) {
	policyName := fmt.Sprintf("%s.%s-%s", cfg.TSTierPrefix, cfg.TSNetworkPrefix, PassToNextTierPolicy)
	rule := apiv3.EntityRule{Selector: "has(zone)"}

	gnp := apiv3.GlobalNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policyName},
		Spec: apiv3.GlobalNetworkPolicySpec{
			Tier:           cfg.TSTierPrefix,
			PreDNAT:        false,
			Order:          &order,
			Selector:       HasZone,
			DoNotTrack:     false,
			ApplyOnForward: false,
			Types:          []apiv3.PolicyType{apiv3.PolicyTypeEgress, apiv3.PolicyTypeIngress},
			Ingress:        []apiv3.Rule{apiv3.Rule{Source: rule, Action: actions["pass"]}},
			Egress:         []apiv3.Rule{apiv3.Rule{Destination: rule, Action: actions["pass"]}},
		},
	}

	// Lookup to see if this object already exists in the datastore.
	g, err := cl.GlobalNetworkPolicies().Get(context.Background(), gnp.Name, metav1.GetOptions{})
	if err != nil {
		_, err := cl.GlobalNetworkPolicies().Create(context.Background(), &gnp, metav1.CreateOptions{})
		if err != nil {
			log.WithError(err).Errorf("Failed to create GNP: %s: ", gnp.Name)
			return policyName, err
		}
		log.Infof("Created GNP: %s", gnp.Name)
		return policyName, nil
	}

	// The policy already exists, update it and write it back to the datastore.
	g.Spec = gnp.Spec
	_, err = cl.GlobalNetworkPolicies().Update(context.Background(), g, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Warning("Failed to update GNP")
		return policyName, err
	}
	log.Infof("Updated GNP: %s", gnp.Name)

	return policyName, nil
}

func getSecurityRules(pc *panw.Panorama, cfg *config.Config, sr *Rules) error {
	if err := getSecurityRulesByDG(pc, Shared, sr); err != nil {
		return err
	}

	if err := getSecurityRulesByDG(pc, cfg.FwDeviceGroup, sr); err != nil {
		return err
	}

	return nil
}

func getSecurityRulesByDG(c *panw.Panorama, dg string, sr *Rules) error {
	pre, err := getRuleByType(c, dg, PreRuleBase)
	if err != nil {
		log.Error("error reading Pre rules")
	}
	post, err := getRuleByType(c, dg, PostRuleBase)
	if err != nil {
		log.Error("error reading Post rules")
	}

	sr.PreRules = append(sr.PreRules, pre...)
	sr.PostRules = append(sr.PostRules, post...)

	return nil
}

func getRuleByType(c *panw.Panorama, dg string, rt string) ([]Rule, error) {
	var rules []Rule

	policies, err := c.Policies.Security.GetList(dg, rt)
	if err != nil {
		log.Errorf("Failed to get policies from client: %s", err)
		return rules, err
	}

	for _, pol := range policies {
		var rule Rule
		polDetails, err := c.Policies.Security.Show(dg, rt, pol)
		if err != nil {
			log.Error(err)
			continue
		}
		log.Debugf("Policy Details: %s, %s, %v", dg, rt, polDetails)

		rule.Name = polDetails.Name
		rule.SrcZones = make([]string, len(polDetails.SourceZones))
		copy(rule.SrcZones, polDetails.SourceZones)
		rule.DstZones = make([]string, len(polDetails.DestinationZones))
		copy(rule.DstZones, polDetails.DestinationZones)
		rule.SrcCIDR = polDetails.SourceAddresses[0]
		rule.DstCIDR = polDetails.DestinationAddresses[0]
		rule.Action = polDetails.Action
		for _, s := range polDetails.Services {
			var svc Service
			if s != "application-default" {
				svc, err = getService(c, PreDefined, s)
				if err != nil && dg != Shared {
					svc, err = getService(c, dg, s)
					if err != nil {
						continue
					}
				}
			}
			rule.Services = append(rule.Services, svc)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// Get Unix timestamp for easy comparison of the last config update time.
func getService(c *panw.Panorama, dg string, srv string) (Service, error) {
	var svc Service

	entry, err := c.Objects.Services.Get(dg, srv)
	if err != nil {
		log.Infof("service %s not present in %s", srv, dg)
		return svc, err
	}
	log.Infof("Service: %v", entry)

	svc.Protocol = entry.Protocol
	if svc.Protocol == "sctp" {
		// no support for SCTP ports in networkpolicy rule.
		return svc, nil
	}
	svc.SrcPorts = strings.Split(entry.SourcePort, ",")
	svc.DstPorts = strings.Split(entry.DestinationPort, ",")

	return svc, nil
}
