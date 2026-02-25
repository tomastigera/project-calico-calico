// Copyright 2020 Tigera Inc. All rights reserved.
package fortimanager

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	fortilib "github.com/projectcalico/calico/firewall-integration/pkg/fortimanager"
	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

const (
	healthReporterNameEW   = "FortimanagerEastWestController"
	healthReportIntervalEW = time.Second * 10
	SystemTierLabel        = "projectcalico.org/system-tier"
)

type EastWestController struct {
	ctx              context.Context
	cfg              *config.Config
	tier             string
	packageName      string
	fortiClient      fortilib.FortiFWClientApi
	calicoClientset  clientv3.ProjectcalicoV3Interface // Global
	resourceCache    rcache.ResourceCache
	healthAggregator *health.HealthAggregator
}

func NewEastWestController(ctx context.Context, cfg *config.Config, h *health.HealthAggregator,
	fc fortilib.FortiFWClientApi, calicoClient clientv3.ProjectcalicoV3Interface, tier, packageName string) *EastWestController {
	//  Reguster with health reporter.
	h.RegisterReporter(healthReporterNameEW, &health.HealthReport{Live: true}, healthReportIntervalEW)

	// update declared tier for compatibility with Fortimanager before proceeding
	err := createUpdateTierForFortimanager(calicoClient, tier)
	if err != nil {
		log.WithError(err).Error("Error creating/updating Tier")
		return nil
	}

	// List all GNPs in a tier
	listFunc := func() (map[string]any, error) {
		log.Debug("Listing all GNP's in a Tier")
		fwGNPS, err := getAllGlobalNetworkPoliciesFromTier(tier, calicoClient)
		if err != nil {
			return nil, err
		}
		return fwGNPS, err
	}

	// Setup a cache for FortiGate Firewall Addresses.
	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:    listFunc,
		ObjectType:  reflect.TypeFor[apiv3.GlobalNetworkPolicy](),
		LogTypeDesc: "Calico GlobalNetworkPolicies",
	}
	fcache := rcache.NewResourceCache(cacheArgs)

	return &EastWestController{
		ctx:              ctx,
		cfg:              cfg,
		tier:             tier,
		packageName:      packageName,
		fortiClient:      fc,
		calicoClientset:  calicoClient,
		resourceCache:    fcache,
		healthAggregator: h,
	}
}

// createUpdateTierForFortimanager updates the tier with appropriate properties for Fortimanager
func createUpdateTierForFortimanager(cl clientv3.ProjectcalicoV3Interface, tierName string) error {
	// Lookup to see if this object already exists in the calico datastore.
	tier, err := cl.Tiers().Get(context.Background(), tierName, metav1.GetOptions{})
	// const labels applied to all Tiers
	projectcalicoSystemTier := map[string]string{
		SystemTierLabel: strconv.FormatBool(true),
	}

	// The policy already exists, update it and write it back to the datastore.
	if tier != nil && err == nil {
		tier.Labels = projectcalicoSystemTier
		_, err = cl.Tiers().Update(context.Background(), tier, metav1.UpdateOptions{})
		if err != nil {
			log.WithError(err).Warning("Failed to update tier")
			return err
		}
	}
	// TODO: [EV-411] else if tier does not exist create the tier policy and apply the label
	return nil
}

// List all GlobalNetworkPolicies in a tier
func getAllGlobalNetworkPoliciesFromTier(tierName string, calicoClient clientv3.ProjectcalicoV3Interface) (map[string]any, error) {

	fwGNPs := make(map[string]any)
	labelSelector := fmt.Sprintf("projectcalico.org/tier = %s", tierName)
	// List all GNPs with label name matches with tier.
	gnps, err := calicoClient.GlobalNetworkPolicies().List(context.Background(), metav1.ListOptions{LabelSelector: labelSelector})
	if err != nil {
		return fwGNPs, err
	}

	// Iterate all GNP, update map with key as: GNP-name and value: GNP
	for _, gnp := range gnps.Items {
		log.Debugf("GNP-name: %s, %#v", gnp.Name, gnp)
		fwGNPs[gnp.Name] = gnp
	}
	return fwGNPs, nil
}

func (ew *EastWestController) Run() {
	defer uruntime.HandleCrash()

	workqueue := ew.resourceCache.GetQueue()
	defer workqueue.ShutDown()

	healthy := func() {
		ew.healthAggregator.Report(healthReporterNameEW, &health.HealthReport{Live: true})
	}
	healthy()

	log.Info("Starting FortiManager Controller resource cache")
	ew.resourceCache.Run(ew.cfg.FwPollInterval.String())

	// Recoincilation loop to check cached GNP with Cluster GNP
	go ew.runWorker()

	// Read FireWall rules from Fortimanager and convert to GNP and update in Cache.
	go ew.readFwRulesAndUpdateCache()

	<-ew.ctx.Done()

	log.Infof("Stopping FortiManager Controller")
}

// Read FireWall rules from Fortimanager and convert to GNP and update in Cache.
func (ew *EastWestController) readFwRulesAndUpdateCache() {
	for {
		log.Debug("List all Firewall Rules from FortiManager")
		// Check policy package is present in fortiManager
		err := ew.fortiClient.GetFirewallPolicyPackage(ew.packageName)
		if err != nil {
			log.WithError(err).Errorf("Policy package isn't present in FortiManager %v", ew.packageName)
			continue
		}
		// List all Firewall rules from FortiManager
		fwRules, err := ew.fortiClient.ListAllFirewallRulesInPkg(ew.packageName)
		if err != nil {
			log.WithError(err).Errorf("Unable to read policies in package %v", ew.packageName)
			continue
		}
		gnpList := make(map[string]bool)
		// Convert FWRule to GlobalNetworkPolicies
		for _, fwRule := range fwRules {
			gnps, err := ConvertFWRuleToGNPs(ew.tier, ew.packageName, fwRule)
			if err != nil {
				log.WithError(err).Errorf("Failed to convert a FwRule to GNPs, rule: %#v", fwRule)
				continue
			}
			// Set Cache with GNP and keep track of all GNPs cached.
			for _, gnp := range gnps {
				ew.resourceCache.Set(gnp.Name, gnp)
				gnpList[gnp.Name] = true
			}
		}

		// List all GNP's in cache, remove entries which aren't present in current sample.
		// This operation, removes
		gnpInCache := ew.resourceCache.ListKeys()
		for _, g := range gnpInCache {
			if _, ok := gnpList[g]; !ok {
				log.Infof("Delete GNP from cache:%+v", g)
				ew.resourceCache.Delete(g)
			}
		}
		time.Sleep(ew.cfg.FwFortiMgrEWPollInterval)
	}

}

func (ew *EastWestController) runWorker() {
	for ew.processNextItem() {
	}
}

func (ew *EastWestController) processNextItem() bool {
	workqueue := ew.resourceCache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync with FortiGate
	if err := ew.syncToK8sCluster(key.(string)); err != nil {
		ew.handleError(err, key.(string))
	}
	workqueue.Done(key)
	return true
}

// Sync GlobalNetworkPolicy to kubernetes cluster.
func (ew *EastWestController) syncToK8sCluster(key string) error {
	clog := log.WithField("Key: ", key)
	clog.Info("Should sync key", key)

	// Check the GNP present in Cache, if not remove from the cluster.
	obj, exists := ew.resourceCache.Get(key)
	if !exists {
		clog.Infof("Deleting GNP %+v", key)
		g, err := ew.calicoClientset.GlobalNetworkPolicies().Get(context.Background(), key, metav1.GetOptions{})
		if err == nil {
			var gracePeriodInSeconds int64
			er := ew.calicoClientset.GlobalNetworkPolicies().Delete(context.Background(), g.Name, metav1.DeleteOptions{GracePeriodSeconds: &gracePeriodInSeconds})
			if er != nil {
				log.WithError(er).Errorf("Failed to Delete GNP name :%+v :%+v", key, g.Name)
				return er
			}
		}
	} else {
		clog.Info("Create/Update the GNP in cluster")
		newGnp := obj.(apiv3.GlobalNetworkPolicy)
		oldGnp, err := ew.calicoClientset.GlobalNetworkPolicies().Get(context.Background(), newGnp.Name, metav1.GetOptions{})
		if err != nil {
			_, er := ew.calicoClientset.GlobalNetworkPolicies().Create(context.Background(), &newGnp, metav1.CreateOptions{})
			if er != nil {
				log.WithError(er).Errorf("Failed to Create GNP name :%+v GNP:%#v", key, newGnp)
				return er
			}
		} else {
			// Check the updated GNP policy is differ
			if !reflect.DeepEqual(newGnp.Spec, oldGnp.Spec) {
				clog.Info("Updating GNP in cluster")
				// Copy  new spec into GlobalNetworkPolicy Object and Update.
				oldGnp.Spec = newGnp.Spec
				_, er := ew.calicoClientset.GlobalNetworkPolicies().Update(context.Background(), oldGnp, metav1.UpdateOptions{})
				if er != nil {
					log.WithError(er).Errorf("Failed to Update GNP name :%+v GNP:%#v", key, oldGnp)
					return er
				}
			}
		}
	}
	return nil
}

func (ew *EastWestController) handleError(err error, key string) {
	workqueue := ew.resourceCache.GetQueue()
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < 5 {
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		log.WithError(err).Errorf("Error syncing k8s Cluster %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping cluster %q out of the queue: %v", key, err)
}
