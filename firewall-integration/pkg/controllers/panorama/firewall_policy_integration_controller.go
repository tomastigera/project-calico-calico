// Copyright 2022 Tigera Inc. All rights reserved.
package panorama

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	"github.com/projectcalico/calico/firewall-integration/pkg/controllers/controller"
	panclient "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/backend/client"
	pansyncer "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/backend/syncer"
	panutils "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/utils"
	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// Panorama prefix.
	PanoramaPolicyNamePrefix = "pan"
	// Timestamp format.
	TimestampFormat = "01-02-2006 15:04:05"
	// Default Panorama fiewall policy integration tier order.
	PanoramaTierOrderDefault = 101

	PanoramaTimeAnnotaionKey = FirewallPrefix + "latest_cache_update"
)

// The Panorama policy rules are filtered by the set of tags.
type FirewallPolicyFilter set.Set[string]

// The Panorama policy integration object id.
type panoramaObjectID struct {
	name string
}

// firewallPolicyIntegrationController implements the Controller interface for managing Panorama
// policy, syncing them to the Calico datastore as GlobalNetworkPolicy.
type firewallPolicyIntegrationController struct {
	cache        rcache.ResourceCache
	calicoClient clientv3.ProjectcalicoV3Interface
	k8sClient    *kubernetes.Clientset
	ctx          context.Context
	cfg          *config.Config

	// The controller's health report aggregator.
	healthAggregator              *health.HealthAggregator
	healthReporterName            string
	healthReportIntervalDuration  time.Duration
	healthReportIntervalMaxJitter time.Duration

	// Event recorder.
	eventRecorder record.EventRecorder

	// Used to pass control from polling to updating the data store.
	syncer bapi.Syncer
	// Syncer callback decoupler ensures syncer callbacks are serialized. This avoids the need
	// for locking our datastructures.
	decoupler   *calc.SyncerCallbacksDecoupler
	restartChan chan string

	// The minimum duration and the maximum jitter, used to define the sync interval per poll to
	// Panorama source.
	minDuration time.Duration
	// Define the max jitter to be one tenth the duration.
	maxJitter time.Duration

	// Number of worker threads.
	numberOfWorkers int

	// The utility functions accessing Panorama via api.
	pancli panutils.PanoramaClient
	// The Panorama device groups that the Panorama objects belong to. An empty value defaults to
	// "shared". An invalid value will result in an error and termination of the controller's
	// execution.
	deviceGroup string

	// Panorama policy tier parameters.
	tier      string
	tierOrder *float64
	// Calico policy order (default: 1000)
	policyOrder *float64

	// The firewall policy integration namespace the controller lives in. The namespace is used in the
	// event post logic to get the pods running in the given namespace. See postEvent().
	policyControllerNamespace string

	// Wait group.
	waitGroup *sync.WaitGroup

	// The rule to policy mapping. Used for faster access to the policies each Panorama rule defines.
	// The value is a set of policies, each of which contain at least one v3 rule referencing a
	// Panorama rule in it's annotations.
	panRuleToPolicyMap map[string]set.Set[string]

	// Mutex to lock policy for asynchronous syncing.
	mutex sync.Mutex
}

// NewFirewallPolicyIntegrationController returns a controller which manages Panorama
// firewallPolicyIntegrationController objects. Returns nil if it fails to connect via Panorama API.
func NewFirewallPolicyIntegrationController(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	c clientv3.ProjectcalicoV3Interface,
	pcli panutils.PanoramaClient,
	cfg *config.Config,
	h *health.HealthAggregator,
	wg *sync.WaitGroup,
) (controller.Controller, error) {
	log.Trace("instantiating Panorama policy integration controller")
	fpic := &firewallPolicyIntegrationController{
		calicoClient:                  c,
		k8sClient:                     clientset,
		ctx:                           ctx,
		cfg:                           cfg,
		deviceGroup:                   cfg.FwDeviceGroup,
		policyControllerNamespace:     cfg.FwPolicyControllerNamespace,
		healthReporterName:            "TigeraPolicyIntegrationController",
		healthReportIntervalDuration:  panoramaHealthReportInterval,
		healthReportIntervalMaxJitter: panoramaHealthReportInterval / jitterDenominator,
		minDuration:                   cfg.FwPollInterval,
		maxJitter:                     cfg.FwPollInterval / jitterDenominator,
		numberOfWorkers:               PanoramaDagControllerNumberOfWorkers,
		pancli:                        pcli,
		tier:                          cfg.FwPolicyTier,
		tierOrder:                     &cfg.FwPolicyTierOrder,
		policyOrder:                   &cfg.FwPolicyOrder,
		decoupler:                     calc.NewSyncerCallbacksDecoupler(),
		restartChan:                   make(chan string),
		panRuleToPolicyMap:            make(map[string]set.Set[string]),
		waitGroup:                     wg,
		mutex:                         sync.Mutex{},
	}

	// Define event recorder.
	fpic.eventRecorder = getEventRecorder(fpic.k8sClient)

	h.RegisterReporter(fpic.healthReporterName, &health.HealthReport{Live: true},
		healthReportInterval)
	fpic.healthAggregator = h

	// If the device group name is empty, then set it equal to "shared". If it is equal to shared
	// it should not be queried
	if len(fpic.deviceGroup) == 0 {
		fpic.deviceGroup = PanoramaSharedDeviceGroup
	} else {
		// Query the device group to verify its existence. Return an error if the API returns an error.
		err := panutils.QueryDeviceGroup(fpic.pancli, fpic.deviceGroup)
		// API has failed to successfully query the provided device group, no reason to run controller.
		if err != nil {
			// Post event
			postEvent(fpic.eventRecorder, fpic.ctx, fpic.k8sClient, fpic.policyControllerNamespace,
				err.Error())

			return nil, err
		}
	}

	// Convert tags filter to valid selector.Selector.
	filter := cfg.FwPanoramaFilterTags
	if len(filter) == 0 {
		log.Debug("Filter match is empty, no filter will be applied")
	}
	// Convert the dynamic match to a selector.
	sel, err := panutils.ConvertMatchFilterToSelector(filter)
	if err != nil {
		errMsg := fmt.Sprintf("failed to convert filter to selector: %s", filter)
		log.Fatal(errMsg)
		postEvent(fpic.eventRecorder, fpic.ctx, fpic.k8sClient,
			fpic.policyControllerNamespace, errMsg)
		return nil, err
	}
	log.Debugf("match: \"%s\" converted to selector: \"%s\"", filter, sel)
	// Parse the selector expression
	parsedSel, err := selector.Parse(sel)
	if err != nil {
		log.WithError(err).Debugf("failed parsing selector: %s", sel)
		return nil, err
	}

	// Function returns map of the globalNetworkPolicyName:globalNetworkPolicy stored by the
	// GlobalNetworkPolicy controller.
	listFunc := func() (map[string]interface{}, error) {
		log.Trace("Listing Panorama's GlobalNetworkPolicies Calico datastore")
		// Get all GlobalNetworkPolicies in a given tier from datastore.
		selector := fmt.Sprintf("projectcalico.org/tier = %s", fpic.tier)
		globalNetworkPolicies, err := c.GlobalNetworkPolicies().List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			log.WithError(err).Error("Unexpected error querying GlobalNetworkPolicies")
			postEvent(fpic.eventRecorder, fpic.ctx, fpic.k8sClient, fpic.policyControllerNamespace,
				fmt.Sprintf("Unexpected error querying GlobalNetworkPolicies, with error: %s", err.Error()))

			return nil, err
		}

		globalNetworkPoliciesMap := make(map[string]interface{})
		for i, gnp := range globalNetworkPolicies.Items {
			log.Tracef("Cache global network policy item %d: %#v", i, gnp)
			// Filter in only objects that are written by policy integration controller.
			if !isPanoramaGlobalNetworkPolicy(&gnp) {
				continue
			}
			// Set the GlobalNetworkPolicy map values relevant to this controller.
			// Names are unique identifiers.
			key := gnp.Name
			destGnp := &v3.GlobalNetworkPolicy{}
			copyGlobalNetworkPolicy(destGnp, gnp)
			globalNetworkPoliciesMap[key] = *destGnp
		}
		log.Debugf(
			"Found %d Panorama GlobalNetworkPolicies in Calico datastore",
			len(globalNetworkPoliciesMap))
		return globalNetworkPoliciesMap, nil
	}

	// Create a cache to store GlobalNetworkPolicies in.
	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:    listFunc,
		ObjectType:  reflect.TypeOf(v3.GlobalNetworkPolicy{}),
		LogTypeDesc: "FirewallPolicyIntegrationGlobalNetworkPolicies",
	}
	fpic.cache = rcache.NewResourceCache(cacheArgs)

	// Define the Panorama syncer. Ultimately the syncer will be responsible for accessing the
	// Panorama datastore that will trigger updates for the controller to process.
	firewallSyncOptions := pansyncer.FirewallPolicySyncOptions{
		Client:         pcli,
		DeviceGroup:    fpic.deviceGroup,
		Ticker:         jitter.NewTicker(fpic.minDuration, fpic.maxJitter),
		FilterSelector: parsedSel,
		Callbacks:      fpic.decoupler,
	}
	fpic.syncer = pansyncer.New(firewallSyncOptions)

	return fpic, nil
}

// Run starts the firewall policy integration controller.
func (c *firewallPolicyIntegrationController) Run() {
	defer uruntime.HandleCrash()
	defer c.waitGroup.Done()

	log.Info("Starting Panorama firewall policy integration controller")

	// Start the Panorama syncer.
	c.startPanoramaSyncer()

	select {
	case <-c.ctx.Done():
		log.Info("Panorama firewall policy integration controller stopping before starting reconciliation")
	default:
		log.Info("Finished syncing with Calico API (Panorama firewall policy integration controller)")

		// Start the Kubernetes reconciler cache to fix up any differences between the required and
		// configured data.
		c.cache.Run(c.cfg.FwPollInterval.String())
		defer c.cache.GetQueue().ShutDown()

		// Start a number of worker threads to read from the queue.
		for i := 0; i < c.numberOfWorkers; i++ {
			go wait.Until(c.runWorker, time.Second, c.ctx.Done())
		}
		log.Info("Panorama Panorama firewall policy integration controller is now running")
	}

	// Block until the controller is shut down. However, since the main routine only shuts down as
	// the result of a panic, there seems very little point in fully tidying up.
	<-c.ctx.Done()

	log.Info("Stopping Panorama firewall policy integration controller")
}

// runWorker processes the list of the cache queued items.
func (c *firewallPolicyIntegrationController) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem waits for an event on the output queue from the GlobalNetworkPolicies resource
// cache and syncs any received keys to the kubernetes datastore.
func (c *firewallPolicyIntegrationController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.cache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync the object to the Calico datastore.
	if err := c.syncToDatastore(key.(string)); err != nil {
		go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
			fmt.Sprintf("failed to sync key: %s to datastore: %s", key, err.Error()))
		c.handleErr(err, key.(string))
	}

	// Indicate that we're done processing this key, allowing for safe parallel processing such that
	// two objects with the same key are never processed in parallel.
	workqueue.Done(key)
	return true
}

// syncToDatastore syncs the given update to the Calico datastore. The provided key
// (GlobalNetworkPolicy name) can be used to find the corresponding resource within the resource
// cache. If the resource for the provided key exists in the cache, then the value should be written
// to the datastore. If it does not exist in the cache, then it should be deleted from the
// datastore.
func (c *firewallPolicyIntegrationController) syncToDatastore(key string) error {
	clog := log.WithField("key", key)
	clog.Debug("Syncing to datastore")

	// Create the tier if it doesn't exist.
	datastoreTier, err := c.calicoClient.Tiers().Get(c.ctx, c.tier, metav1.GetOptions{})
	if datastoreTier == nil || err != nil {
		log.WithError(err).Errorf("error querying tier: %s", c.tier)
		go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
			fmt.Sprintf("failed to query tier: %s", c.tier))
		// Create tier.
		if err := c.createUpdateTierForPanorama(c.tier, c.tierOrder); err != nil {
			log.WithError(err).Errorf("failure to create tier: %s", c.tier)
			return err
		}
	}

	// Start by looking up the existing entry if it already exists. Double check that the annotation
	// indicates this resource is owned by the firewall policy integration controller.
	currentGnp, err := c.calicoClient.GlobalNetworkPolicies().Get(c.ctx, key, metav1.GetOptions{})
	if err != nil {
		clog.WithError(err).Debugf("Error querying GlobalNetworkPolicies, with type %s", reflect.TypeOf(err))
		if !kerrors.IsNotFound(err) {
			clog.WithError(err).Info("Unexpected error querying GlobalNetworkPolicies")
			go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
				fmt.Sprintf("unexpected error querying GlobalNetworkPolicy %s: %s", key, err.Error()))
			// We hit an error other than "not found".
			return err
		}
		currentGnp = nil
	}

	// Check the controller's cache to see whether the resource *should* exist.
	value, exists := c.cache.Get(key)
	clog.Debugf("Reconciliation cache returned: %#v", value)
	clog.Debugf("Current GlobalNetworkPolicy: %#v", currentGnp)

	if !exists {
		// The object does not exist in the cache (and therefore is not required) - delete from the
		// datastore.
		clog.Info("Deleting GlobalNetworkPolicy from Calico datastore")
		err := c.calicoClient.GlobalNetworkPolicies().Delete(c.ctx, key, metav1.DeleteOptions{})
		if err != nil && !kerrors.IsNotFound(err) {
			clog.WithError(err).Infof("Unexpected error deleting GlobalNetworkPolicy: %s", key)
			go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
				fmt.Sprintf("unexpected error deleting GlobalNetworkPolicy %s: %s", key, err.Error()))
			// We hit an error other than "not found".
			return err
		}
		return nil
	}
	// The GlobalNetworkPolicy object should exist - update the Calico datastore to reflect the latest settings.
	clog.Debug("Create/Update GlobalNetworkPolicy in Calico datastore")
	requiredGnp := value.(v3.GlobalNetworkPolicy)

	if currentGnp == nil {
		clog.Info("Creating GlobalNetworkPolicy in Calico datastore")
		if _, err = c.calicoClient.GlobalNetworkPolicies().Create(c.ctx, &requiredGnp, metav1.CreateOptions{}); err != nil {
			clog.WithError(err).Infof("Error creating GlobalNetworkPolicy in Calico datastore: %#v", requiredGnp)
			go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
				fmt.Sprintf("failed to create GlobalNetworkPolicy %s: %s", key, err.Error()))
			return err
		}
	} else {
		// Copies all necessary fields, only if any of them differ.
		clog.Info("Updating GlobalNetworkPolicy in Calico datastore")
		mergedGnp := currentGnp.DeepCopy()
		copyGlobalNetworkPolicy(mergedGnp, requiredGnp)
		if !equality.Semantic.DeepEqual(mergedGnp.Annotations, currentGnp.Annotations) || !equality.Semantic.DeepEqual(mergedGnp.Spec, currentGnp.Spec) {
			if _, err = c.calicoClient.GlobalNetworkPolicies().Update(c.ctx, mergedGnp, metav1.UpdateOptions{}); err != nil {
				clog.WithError(err).Infof("Error updating GlobalNetworkPolicy in Calico datastore: %#v", mergedGnp)
				go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
					fmt.Sprintf("failed to update GlobalNetworkPolicy %s: %s", key, err.Error()))
				return err
			}
		}
	}

	return nil
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *firewallPolicyIntegrationController) handleErr(err error, key string) {
	clog := log.WithField("key", key)

	workqueue := c.cache.GetQueue()
	if err == nil {
		// Forget about the AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		clog.Debug("Forgetting key")
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < 5 {
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		clog.WithError(err).Errorf("Error polling GlobalNetworkPolicy %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully
	// process this key.
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping GlobalNetworkPolicy %q out of the queue: %v", key, err)
}

// startPanoramaSyncer starts the Panorama syncer. This blocks until the syncer is in-sync or
// we've been asked to stop.
func (c *firewallPolicyIntegrationController) startPanoramaSyncer() {
	log.Debug("Start Panorama syncer")

	healthy := func() {
		c.healthAggregator.Report(c.healthReporterName, &health.HealthReport{Live: true})
	}
	healthy()

	healthTicker := jitter.NewTicker(c.healthReportIntervalDuration, c.healthReportIntervalMaxJitter)
	log.Debugf("Health ticker duration sec: %f", healthTicker.MinDuration.Seconds())

	// Start the decoupler which will funnel the syncer updates to the controllers update methods
	// synchronously (so there is no chance of multiple concurrent updates).
	go c.decoupler.SendTo(c)
	c.syncer.Start()
	select {
	case <-c.ctx.Done():
	case <-healthTicker.C:
		healthy()
	}
}

// OnStatusUpdated implements the syncer interface.
func (c *firewallPolicyIntegrationController) OnStatusUpdated(status bapi.SyncStatus) {
	log.Debug("Firewall policy integration OnStatusUpdated")
}

// OnUpdates implements the syncer interface. This processes Panorama objects and subsequently
// updates the dirty rules.
func (c *firewallPolicyIntegrationController) OnUpdates(updates []bapi.Update) {
	log.Debug("Firewall policy integration OnUpdates")

	for _, u := range updates {
		var id panoramaObjectID
		var kind string
		switch rk := u.Key.(type) {
		case model.PanoramaObjectKey:
			id = panoramaObjectID{
				name: rk.Name,
			}
			kind = rk.Kind
		default:
			log.WithField("Key", rk).Error("Unexpected resource type in syncer update")
			go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
				fmt.Sprintf("Unexpected resource type in syncer update key: %s", rk.String()))
		}

		clog := log.WithFields(log.Fields{
			"name": id.name,
			"kind": kind,
		})

		switch kind {
		case panclient.PanoramaRuleKind:
			clog.Debug("Processing Panorama Rule")
			switch u.UpdateType {
			case bapi.UpdateTypeKVDeleted:
				log.Debugf("delete: %s", u.Key.String())
				key := getPanoramaRuleName(u.Key.String())
				c.deleteFromPolicy(key)
			case bapi.UpdateTypeKVNew:
				log.Debugf("insert: %s", u.Key.String())
				c.insertPolicy(u.Value.(panclient.RulePanorama))
			case bapi.UpdateTypeKVUpdated:
				log.Debugf("update: %s", u.Key.String())
				c.deleteFromPolicy(u.Value.(panclient.RulePanorama).Name)
				c.insertPolicy(u.Value.(panclient.RulePanorama))
			}
		}
	}
}

// copyGlobalNetworkPolicy copies a source to destination global network policy.
func copyGlobalNetworkPolicy(dst *v3.GlobalNetworkPolicy, src v3.GlobalNetworkPolicy) {
	log.Debug("Copy source to destination policy")

	// Copy the type metadata.
	dst.APIVersion = src.APIVersion
	dst.Kind = src.Kind
	// Copy Spec context, nets and allowedEgressDomains.
	src.Spec.DeepCopyInto(&dst.Spec)
	// Copy ObjectMeta context. Context relevant to this controller is name, labels and annotation.
	dst.Name = src.Name
	// Copy labels, except for 'tier'. Destination labels will be nil if source only contains the 'tier' key.
	filteredLabels := make(map[string]string)
	for key, label := range src.Labels {
		if key != "projectcalico.org/tier" {
			filteredLabels[key] = label
		}
	}
	if len(filteredLabels) > 0 {
		dst.Labels = filteredLabels
	}
	// Copy annotations. Destination annotations will be nil if source is empty.
	if len(src.Annotations) > 0 {
		dst.Annotations = make(map[string]string)
		for key, annotation := range src.Annotations {
			dst.Annotations[key] = annotation
		}
	}
}

// isPanoramaGlobalNetworkPolicy returns true if the GlobalNetworkPolicy contains the
// annotation: "firewall.tigera.io/type: Panorama".
func isPanoramaGlobalNetworkPolicy(gnp *v3.GlobalNetworkPolicy) bool {
	log.Debug("Verify as Panorama policy")

	if gnp != nil {
		if objType, found := gnp.Annotations[fmt.Sprintf("%s%s", FirewallPrefix, "type")]; found {
			return objType == ParoramaType
		}
	}

	return false
}

// insertPolicy inserts a Panorama rule mapping as a v3 rule into calico policy. Panorama source to
// destination relationships are mapped to calico v3Rules and subsequently ingested into policies.
func (c *firewallPolicyIntegrationController) insertPolicy(panRule panclient.RulePanorama) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	log.Debugf("Updating policies defined by Panorama rule: %s", panRule.Name)

	// Map the Panorama rule to the list of ingress and egress rules that will be used as updates to
	// the existing policy, or inserted into a new policy.
	v3RuleUpdates := createUpdateV3Rules(panRule)

	// Add the v3 update rules to policies.
	for name, update := range v3RuleUpdates {
		// The cache key is prefixed by the tier name, so as to match the Calico resource name.
		gnpName, err := generateGlobalNetworkPolicyName(c.tier, name)
		if err != nil {
			errMsg := fmt.Sprintf(
				"failed to generate a valid global network policy name for tier: %s, and name: %s",
				c.tier, name)
			log.Error(errMsg)
			go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace, errMsg)
		}
		key := gnpName
		// Update the Policy ingress/egress rules, with mappings defined in the Panorama rule.
		if item, exists := c.cache.Get(key); exists {
			// Update an existing policy.
			policy := item.(v3.GlobalNetworkPolicy)
			// Insert all new v3 rules into the ingress/egress rules.
			for _, rule := range update.ingress {
				if policy.Spec.Ingress, err = insertV3Rule(policy.Spec.Ingress, rule); err != nil {
					go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace, err.Error())
				}
			}
			for _, rule := range update.egress {
				if policy.Spec.Egress, err = insertV3Rule(policy.Spec.Egress, rule); err != nil {
					go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace, err.Error())
				}
			}
			// Define the policy's types of rules.
			hasIngress := len(policy.Spec.Ingress) > 0
			hasEgress := len(policy.Spec.Egress) > 0
			policy.Spec.Types = getGlobalNetworkPolicyTypes(hasIngress, hasEgress)

			// Add timestamp of the last update to this policy.
			t := time.Now().Format(TimestampFormat)
			policy.Annotations[PanoramaTimeAnnotaionKey] = t

			// Link this policy to the Panorama rule.
			c.mapPolicyToRule(panRule.Name, policy.Name)
			// Set the new cache value.  The cache compares to the old value and proceeds, only if there
			// is a difference.
			c.cache.Set(key, policy)
		} else {
			// Create new policy.

			// Create a new basic policy and complete context with new rules inserted into the ingress and
			// egress definitions.
			policy := createBasicGlobalNetworkPolicy(name, gnpName, c.tier, c.policyOrder)
			// Insert rules into the new policy.
			for _, rule := range update.ingress {
				if policy.Spec.Ingress, err = insertV3Rule(policy.Spec.Ingress, rule); err != nil {
					go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace, err.Error())
				}
			}
			for _, rule := range update.egress {
				if policy.Spec.Egress, err = insertV3Rule(policy.Spec.Egress, rule); err != nil {
					go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace, err.Error())
				}

			}
			// Define the policy's types of rules.
			hasIngress := len(policy.Spec.Ingress) > 0
			hasEgress := len(policy.Spec.Egress) > 0
			policy.Spec.Types = getGlobalNetworkPolicyTypes(hasIngress, hasEgress)

			// Add timestamp of the last update performed on this policy.
			t := time.Now().Format(TimestampFormat)
			policy.Annotations[PanoramaTimeAnnotaionKey] = t

			// Link this policy to the Panorama rule.
			c.mapPolicyToRule(panRule.Name, policy.Name)

			// Set the new cache value.
			c.cache.Set(key, *policy)
		}
	}
}

// deleteFromPolicy deletes all v3 rules in every policy that contains the Panorama rule name in its
// annotation.
func (c *firewallPolicyIntegrationController) deleteFromPolicy(panRuleName string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	log.Debugf("Deleting rules from policy, defined by Panorama rule: %s", panRuleName)

	// Inspect every policy that contains a reference to a Panorama rule and delete it.
	if policies, exists := c.panRuleToPolicyMap[panRuleName]; exists {
		for key := range policies.All() {
			if item, exists := c.cache.Get(key); exists {
				policy := item.(v3.GlobalNetworkPolicy)
				// delete every v3 rule referencing this Panorama rule in its annotation.
				policy.Spec.Ingress = deleteV3Rule(policy.Spec.Ingress, panRuleName)
				policy.Spec.Egress = deleteV3Rule(policy.Spec.Egress, panRuleName)

				hasIngress := len(policy.Spec.Ingress) > 0
				hasEgress := len(policy.Spec.Egress) > 0
				// Delete empty policy.
				if !hasIngress && !hasEgress {
					c.cache.Delete(key)
				} else {
					// Define the policy's types of rules.
					policy.Spec.Types = getGlobalNetworkPolicyTypes(hasIngress, hasEgress)
					// Set the new cache value.  The cache compares to the old value and proceeds, only if
					// there is a difference.
					c.cache.Set(key, policy)
				}
			}
		}
		// All Panorama rule references have been removed from the policies. Remove the mappings for
		// this key.
		c.panRuleToPolicyMap[panRuleName].Clear()
	}
}

// mapPolicyToRule adds the a policy to Panorama rule map. The map indicates which of
// policies contain v3 rules defined by the Panorama rule key.
func (c *firewallPolicyIntegrationController) mapPolicyToRule(ruleKey, policy string) {
	if rpmItem, exists := c.panRuleToPolicyMap[ruleKey]; exists {
		rpmItem.Add(policy)
	} else {
		c.panRuleToPolicyMap[ruleKey] = set.New[string]()
		c.panRuleToPolicyMap[ruleKey].Add(policy)
	}
}

// createUpdateTierForPanorama checks if a tier already exists. If not, create else update.
func (c *firewallPolicyIntegrationController) createUpdateTierForPanorama(name string, order *float64) error {
	if name == "default" {
		log.Debug("Tier name set to \"default\", no need to create a new tier")

		return nil
	}

	// const labels applied to all Tiers interacted by fw
	tierLabels := map[string]string{
		SystemTierLabel: strconv.FormatBool(true),
	}
	// Lookup to see if this object already exists in the datastore.
	t, err := c.calicoClient.Tiers().Get(context.Background(), name, metav1.GetOptions{})

	log.Debugf("Create/Update tiers in Calico datastore")
	if err != nil {
		// Doesn't exist - create it.
		tier := v3.Tier{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: tierLabels,
			},
			Spec: v3.TierSpec{
				Order: order,
			},
		}

		_, err := c.calicoClient.Tiers().Create(context.Background(), &tier, metav1.CreateOptions{})
		if err != nil {
			log.WithError(err).Warning("failed to create tier")
			go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
				fmt.Sprintf("failed to create tier: %s: %s", name, err.Error()))

			return err
		}
		log.Info(fmt.Sprintf("Successfully created tier: %s, with order: %d", name, order))

		return nil
	}

	// The policy already exists, update it and write it back to the datastore.
	t.Spec.Order = order
	t.Labels = tierLabels
	_, err = c.calicoClient.Tiers().Update(context.Background(), t, metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Warning("failed to update tier")
		go postEvent(c.eventRecorder, c.ctx, c.k8sClient, c.policyControllerNamespace,
			fmt.Sprintf("failed to create tier: %s: %s", name, err.Error()))

		return err
	}
	log.Info(fmt.Sprintf("Successfully updated tier: %s, with order: %d", name, order))

	return nil
}

// getEventRecorder returns the k8s EventsRecorder.
func getEventRecorder(k8sClient *kubernetes.Clientset) record.EventRecorder {
	if k8sClient == nil {
		return nil
	}

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(
		&typedcorev1.EventSinkImpl{
			Interface: k8sClient.CoreV1().Events(""),
		})
	recorder := broadcaster.NewRecorder(scheme.Scheme,
		v1.EventSource{Component: "firewall-policy-integration"})

	return recorder
}

// postEvent uses Kubernetes Events to write an error message to the event
// steam of pods in the same namespace.
// TODO(dimitrin): Define a new Event type.
func postEvent(recorder record.EventRecorder, ctx context.Context, k8sClient *kubernetes.Clientset, namespace, message string) {
	if recorder == nil {
		return
	}

	log.Debugf("Posting event message: message: %s", message)

	pods, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Could not list pods in namespace: %s", namespace)
	}
	for _, pod := range pods.Items {
		ref, err := reference.GetReference(scheme.Scheme, &pod)
		if err != nil {
			log.WithError(err).Errorf("Could not get reference for pod: %v\n", pod.Name)
		}
		recorder.Event(ref, v1.EventTypeWarning, "tigera-policy-integration-error", message)
	}
}

// getPanoramaRuleName removes the prefix and suffix returned by a model.Key type, which exposes
// the Panorama rule name.
// TODO(dimitrin): Alter libcalico-go Key.String() to return the name without surrounding it by
// 'Object()'
func getPanoramaRuleName(keyName string) string {
	trimmed := strings.TrimPrefix(keyName, "Object(name=")
	trimmed = strings.TrimSuffix(trimmed, ")")

	return trimmed
}
