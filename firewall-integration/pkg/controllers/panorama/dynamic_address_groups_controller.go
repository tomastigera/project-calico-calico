// Copyright 2021-2022 Tigera Inc. All rights reserved.
package panorama

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	"github.com/projectcalico/calico/firewall-integration/pkg/controllers/controller"
	panutils "github.com/projectcalico/calico/firewall-integration/pkg/controllers/panorama/utils"
	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// Panorama GlobalNetworkSet constants.
	PanoramaAddressGroupType            = "AddressGroup"
	PanoramaNamePrefix                  = "pan."
	PanoramaSharedDeviceGroup           = "shared"
	PanoramaUnsupportedIpRangesError    = "unsupported-ip-ranges-present"
	PanoramaUnsupportedIpWildcardsError = "unsupported-ip-wildcards-present"

	// The number of workers threads for the dynamic address groups controller.
	PanoramaDagControllerNumberOfWorkers = 5

	// The duration between health reports issued by this controller.
	panoramaHealthReportInterval = healthReportInterval / 3

	// The denominator in the fraction defining the jitter.
	jitterDenominator = 10
)

// The address groups are filtered by the set of tags.
type AddressGroupsFilter set.Set[string]

// dynamicAddressGroupsController implements the Controller interface for managing Panorama
// dynamic address groups, syncing them to the Calico datastore as GlobalNetworkSet.
type dynamicAddressGroupsController struct {
	cache            rcache.ResourceCache
	globalNetworkSet clientv3.GlobalNetworkSetInterface
	ctx              context.Context
	cfg              *config.Config

	// The controller's health report aggregator.
	healthAggregator              *health.HealthAggregator
	healthReporterName            string
	healthReportIntervalDuration  time.Duration
	healthReportIntervalMaxJitter time.Duration

	// Used to pass control from polling to updating the data store.
	inSync   chan struct{}
	isInSync bool

	// The minimum duration and the maximum jitter, used to define the sync interval per poll to
	// Panorama source.
	minDuration time.Duration
	// Define the max jitter to be one tenth the duration.
	maxJitter time.Duration

	// Number of worker threads.
	numberOfWorkers int

	// The utility functions accessing Panorama via api.
	pancli panutils.PanoramaClient
	// The Panorama device groups that the address groups and addresses belong to.  An empty value
	// defaults to "shared". An invalid value will result in an error and termination of the
	// controller's execution.
	deviceGroup string
	// Panorama address group tags.
	tags AddressGroupsFilter

	// Wait group.
	waitGroup *sync.WaitGroup
}

// NewDynamicAddressGroupsController returns a controller which manages Panorama
// dynamicAddressGroupsController objects.
// Returns nil if it fails to connect via Panorama API.
func NewDynamicAddressGroupsController(
	ctx context.Context,
	clientset *kubernetes.Clientset,
	gns clientv3.GlobalNetworkSetInterface,
	pcl panutils.PanoramaClient,
	cfg *config.Config,
	h *health.HealthAggregator,
	wg *sync.WaitGroup,
) (controller.Controller, error) {
	log.Trace("instantiating Panorama dynamic address groups controller")
	dagc := &dynamicAddressGroupsController{
		globalNetworkSet:              gns,
		ctx:                           ctx,
		cfg:                           cfg,
		deviceGroup:                   cfg.FwDeviceGroup,
		pancli:                        pcl,
		healthReporterName:            "TigeraAddressGroupsController",
		healthReportIntervalDuration:  panoramaHealthReportInterval,
		healthReportIntervalMaxJitter: panoramaHealthReportInterval / jitterDenominator,
		inSync:                        make(chan struct{}),
		minDuration:                   cfg.FwPollInterval,
		maxJitter:                     cfg.FwPollInterval / jitterDenominator,
		numberOfWorkers:               PanoramaDagControllerNumberOfWorkers,
		waitGroup:                     wg,
	}

	var err error

	h.RegisterReporter(dagc.healthReporterName, &health.HealthReport{Live: true},
		healthReportInterval)
	dagc.healthAggregator = h

	// Panorama tags delimeters, spaces and a single comma.
	tags, err := panutils.SplitTags(cfg.FwPanoramaTags)
	if err != nil {
		log.WithError(err).Debugf("failed parsing tags.")
		return nil, err
	}
	if len(tags) == 0 {
		log.Warnf("The list of tags evaluates to an empty list, tags: %v", tags)
	}
	// Define the set of tags, used as a filter.
	dagc.tags = set.FromArray(tags)

	// If the device group name is empty, then set it equal to "shared". If it is equal to shared
	// it should not be queried
	if len(dagc.deviceGroup) == 0 {
		dagc.deviceGroup = PanoramaSharedDeviceGroup
	} else {
		// Query the device group to verify its existence. Return an error if the API returns an error.
		err = panutils.QueryDeviceGroup(dagc.pancli, dagc.deviceGroup)
		// API has failed to successfully query the provided device group, no reason to run controller.
		if err != nil {
			return nil, err
		}
	}

	// Function returns map of the globalNetworkSetName:globalNetworkSet stored by the
	// GlobalNetworkSet controller.
	listFunc := func() (map[string]interface{}, error) {
		log.Trace("Listing Panorama's address group GlobalNetworkSets Calico datastore")
		// Get all GlobalNetworkSets from datastore.
		globalNetworkSets, err := dagc.globalNetworkSet.List(ctx, metav1.ListOptions{})
		if err != nil {
			log.WithError(err).Error("Unexpected error querying GlobalNetworkSets")
			return nil, err
		}

		globalNetworkSetsMap := make(map[string]interface{})
		for _, gns := range globalNetworkSets.Items {
			// Filter in only objects that are written by address groups controller.
			if !dagc.isPanoramaGlobalNetworkSet(&gns) {
				continue
			} else {
				// Set the GlobalNetworkSet map values relevant to this controller.
				// Names are unique identifiers.
				key := gns.Name
				destGlobalNetworkSet := &v3.GlobalNetworkSet{}
				dagc.copyGlobalNetworkSet(destGlobalNetworkSet, gns)
				globalNetworkSetsMap[key] = *destGlobalNetworkSet
			}
		}
		log.Debugf(
			"Found %d Panorama address groups GlobalNetworkSets in Calico datastore",
			len(globalNetworkSetsMap))
		return globalNetworkSetsMap, nil
	}

	// Create a Cache to store GlobalNetworkSets in.
	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:    listFunc,
		ObjectType:  reflect.TypeOf(v3.GlobalNetworkSet{}),
		LogTypeDesc: "AddressGroupGlobalNetworkSets",
	}
	dagc.cache = rcache.NewResourceCache(cacheArgs)

	return dagc, nil
}

// Run starts the controller.
func (c *dynamicAddressGroupsController) Run() {
	defer uruntime.HandleCrash()
	defer c.waitGroup.Done()

	log.Info("Starting Panorama DynamicAddressGroups controller")

	// Start the Panorama processor.
	go c.startPolling()

	select {
	case <-c.ctx.Done():
		log.Info("Panorama DynamicAddressGroups controller stopping before starting reconciliation")
	case <-c.inSync:
		log.Info("Finished syncing with Calico API (Panorama DynamicAddressGroups)")

		// Start the Kubernetes reconciler cache to fix up any differences between the required and
		// configured data.
		c.cache.Run(c.cfg.FwPollInterval.String())
		defer c.cache.GetQueue().ShutDown()

		// Start a number of worker threads to read from the queue.
		for i := 0; i < c.numberOfWorkers; i++ {
			go wait.Until(c.runWorker, time.Second, c.ctx.Done())
		}
		log.Info("Panorama DynamicAddressGroups controller is now running")
	}

	// Block until the controller is shut down. However, since the main routine only shuts down as
	// the result of a panic, there seems very little point in fully tidying up.
	<-c.ctx.Done()

	log.Info("Stopping Panorama DynamicAddressGroups controller")
}

// runWorker processes the list of the cache queued items.
func (c *dynamicAddressGroupsController) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem waits for an event on the output queue from the GlobalNetworkSets resource
// cache and syncs any received keys to the kubernetes datastore.
func (c *dynamicAddressGroupsController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.cache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync the object to the Calico datastore.
	if err := c.syncToDatastore(key.(string)); err != nil {
		c.handleErr(err, key.(string))
	}

	// Indicate that we're done processing this key, allowing for safe parallel processing such that
	// two objects with the same key are never processed in parallel.
	workqueue.Done(key)
	return true
}

// syncToDatastore syncs the given update to the Calico datastore. The provided key can be used to
// find the corresponding resource within the resource cache. If the resource for the provided key
// exists in the cache, then the value should be written to the datastore. If it does not exist
// in the cache, then it should be deleted from the datastore.
func (c *dynamicAddressGroupsController) syncToDatastore(key string) error {
	clog := log.WithField("key", key)
	clog.Debug("Synching to datastore")

	// Start by looking up the existing entry if it already exists. Double check that the annotation
	// indicates this resource is owned by the dynamic address groups controller.
	currentGns, err := c.globalNetworkSet.Get(c.ctx, key, metav1.GetOptions{})
	if err != nil {
		clog.WithError(err).Debugf("Error querying GlobalNetworkSets, with type %s", reflect.TypeOf(err))
		if !kerrors.IsNotFound(err) {
			clog.WithError(err).Info("Unexpected error querying GlobalNetworkSets")
			// We hit an error other than "not found".
			return err
		}
		currentGns = nil
	}

	// Check the controller's cache to see whether the resource *should* exist.
	value, exists := c.cache.Get(key)
	clog.Debugf("Reconciliation cache returned: %#v", value)
	clog.Debugf("Current GlobalNetworkSet: %#v", currentGns)

	if !exists {
		// The object does not exist in the cache (and therefore is not required) - delete from the
		// datastore.
		clog.Info("Deleting GlobalNetworkSet from Calico datastore")
		err := c.globalNetworkSet.Delete(c.ctx, key, metav1.DeleteOptions{})
		if err != nil && !kerrors.IsNotFound(err) {
			clog.WithError(err).Infof("Unexpected error deleting GlobalNetworkSet: %s", key)
			// We hit an error other than "not found".
			return err
		}
		return nil
	}
	// The GlobalNetworkSet object should exist - update the Calico datastore to reflect the latest settings.
	clog.Debug("Create/Update GlobalNetworkSet in Calico datastore")
	requiredGns := value.(v3.GlobalNetworkSet)

	if currentGns == nil {
		clog.Info("Creating GlobalNetworkSet in Calico datastore")
		if _, err = c.globalNetworkSet.Create(c.ctx, &requiredGns, metav1.CreateOptions{}); err != nil {
			clog.WithError(err).Infof("Error creating GlobalNetworkSet in Calico datastore: %#v", requiredGns)
			return err
		}
	} else {
		// Copies all necessary fields, only if any of them differ.
		clog.Info("Updating GlobalNetworkSet in Calico datastore")
		c.copyGlobalNetworkSet(currentGns, requiredGns)
		if _, err = c.globalNetworkSet.Update(c.ctx, currentGns, metav1.UpdateOptions{}); err != nil {
			clog.WithError(err).Infof("Error updating GlobalNetworkSet in Calico datastore: %#v", currentGns)
			return err
		}
	}

	return nil
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *dynamicAddressGroupsController) handleErr(err error, key string) {
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
		clog.WithError(err).Errorf("Error polling GlobalNetworkSet %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully
	// process this key.
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping GlobalNetworkSet %q out of the queue: %v", key, err)
}

// startPolling runs through an infinite loop until, stopCh is returned. Will wait until
// the sync interval ticker to poll Panorama anew.
func (c *dynamicAddressGroupsController) startPolling() {
	healthy := func() {
		c.healthAggregator.Report(c.healthReporterName, &health.HealthReport{Live: true})
	}
	healthy()

	// Define the controller polling ticker.
	ticker := jitter.NewTicker(c.minDuration, c.maxJitter)
	log.Debugf("Ticker duration sec: %f", ticker.MinDuration.Seconds())
	// Define the health report ticker.
	healthTicker := jitter.NewTicker(c.healthReportIntervalDuration, c.healthReportIntervalMaxJitter)
	log.Debugf("Health ticker duration sec: %f", healthTicker.MinDuration.Seconds())

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			// TODO(dimitrin): Create an event driven approach to updates manifested in Panorama. The
			// controller should only process items when an event has occurred.
			c.updateCache()
		case <-healthTicker.C:
			healthy()
		}
	}
}

// updateCache updates the resource cache with latest from Panorama.
// Will make a call to Panorama and retrieve all tagged address groups and all addresses
// associated with the particular device group.
// Will verify a change to the cached GlobalNetworkSets's addresses before performing any updates.
func (c *dynamicAddressGroupsController) updateCache() {
	log.Trace("Update Panorama DynamicAddressGroups resource cache")
	// AddressGroups will access the Panorama resource and retrieve the latest values.
	// The tags have already been converted to the k8s naming scheme.
	addressGroups, err := panutils.GetAddressGroups(c.pancli, c.tags, c.deviceGroup)
	if err != nil {
		log.WithError(err).Errorf("Failed to retrieve address groups from Panorama. Device group: \"%s\". Tags: %s", c.deviceGroup, c.tags)
		return
	}
	// Convert address groups to GlobalNetworkSets. Keep track of the keys (GNS names).
	gnsKeys := make(map[string]bool)
	for _, addressGroup := range addressGroups {
		gns := c.convertAddressGroupToGlobalNetworkSet(addressGroup)
		// The cache keys are the valid k8s version of the address group name.
		key := gns.Name
		// Performs a deep equals check and updates the key if the object has changed.
		c.cache.Set(key, gns)
		log.Debugf("Set GlobalNetworkSet: %s, in the resource cache", key)

		gnsKeys[key] = true
	}
	// Delete all entries in the cache which are not present in the polled address groups.
	for _, key := range c.cache.ListKeys() {
		if !gnsKeys[key] {
			log.Infof("Delete GlobalNetworkSet: %s from cache", key)
			c.cache.Delete(key)
		}
	}

	// The cache is now in sync.
	if !c.isInSync {
		log.Debug("Cache is in sync")
		c.isInSync = true
		c.inSync <- struct{}{}
	}
}

// convertAddressGroupToGlobalNetworkSet creates a new GlobalNetworkSet from the values of and
// address group.
func (c *dynamicAddressGroupsController) convertAddressGroupToGlobalNetworkSet(
	addressGroup panutils.AddressGroup,
) v3.GlobalNetworkSet {
	// Add the address group as a GlobalNetworkSet to the resource cache.
	gns := v3.GlobalNetworkSet{}
	// Set the GNS name to a valid Kubernetes (RFC1123) version of the address group's name, with the
	// "pan." prefix.
	gns.Name = panutils.GetRFC1123Name(PanoramaNamePrefix + addressGroup.Entry.Name)
	// Copy address group addresses only when populated.
	if len(addressGroup.Addresses.IpNetmasks) > 0 {
		gns.Spec.Nets = addressGroup.Addresses.IpNetmasks
	}
	if len(addressGroup.Addresses.Fqdns) > 0 {
		gns.Spec.AllowedEgressDomains = addressGroup.Addresses.Fqdns
	}
	gns.Labels = make(map[string]string, len(addressGroup.Entry.Tags))
	gns.Labels[fmt.Sprintf("%s%s", FirewallPrefix, PanoramaAddressGroupKeyName)] = addressGroup.Entry.Name
	for _, tag := range addressGroup.Entry.Tags {
		gns.Labels[FirewallPrefix+panutils.GetRFC1123Name(tag)] = ""
	}

	gns.Annotations = make(map[string]string)
	// Define a comma delimited string of errors to the error annotation of the GlobalNetworkSet.
	// The error annotation will be an empty string if there are not errors.
	errorAnnotationSuffix := "errors"
	gns.Annotations[FirewallPrefix+errorAnnotationSuffix] = ""
	controllerErrors := make([]string, 0)
	if len(addressGroup.Addresses.IpRanges) != 0 {
		controllerErrors = append(controllerErrors, PanoramaUnsupportedIpRangesError)
		// Log the unsupported ip-ranges.
		ipRangesStr := strings.Join(addressGroup.Addresses.IpRanges[:], ",")
		log.Debugf("%s: \"%s\"", FirewallPrefix+"unsupported-ip-ranges", ipRangesStr)
	}
	if len(addressGroup.Addresses.IpWildcards) != 0 {
		controllerErrors = append(controllerErrors, PanoramaUnsupportedIpWildcardsError)
		// Log the unsupported ip-wildcards.
		IpWildcardsStr := strings.Join(addressGroup.Addresses.IpWildcards[:], ",")
		log.Debugf("%s: \"%s\"", FirewallPrefix+"unsupported-ip-wildcards", IpWildcardsStr)
	}
	if addressGroup.Err != nil {
		controllerErrors = append(controllerErrors, addressGroup.Err.Error())
		log.Debugf("%s: \"%s\"", FirewallPrefix+errorAnnotationSuffix, addressGroup.Err.Error())
	}
	gns.Annotations[FirewallPrefix+errorAnnotationSuffix] = strings.Join(controllerErrors, ",")

	gns.Annotations[FirewallPrefix+"type"] = ParoramaType
	gns.Annotations[FirewallPrefix+"object-type"] = PanoramaAddressGroupType
	gns.Annotations[FirewallPrefix+"name"] = addressGroup.Entry.Name
	gns.Annotations[FirewallPrefix+"device-groups"] = c.deviceGroup
	if len(c.deviceGroup) == 0 {
		gns.Annotations[FirewallPrefix+"device-groups"] = PanoramaSharedDeviceGroup
	}

	return gns
}

// copyGlobalNetworkSet copies the GlobalNetworkSet context necessary to this controller, from a
// source to a destination. This controller is responsible for updating the labels, annotations,
// spec.nets and spec.AllowedEgressDomains.
func (c *dynamicAddressGroupsController) copyGlobalNetworkSet(
	gnsDest *v3.GlobalNetworkSet, gnsSrc v3.GlobalNetworkSet,
) {
	// Copy Spec context, nets and allowedEgressDomains.
	gnsSrc.Spec.DeepCopyInto(&gnsDest.Spec)
	// Copy ObjectMeta context. Context relevant to this controller is name, labels and annotation.
	gnsDest.Name = gnsSrc.GetObjectMeta().GetName()
	gnsDest.Labels = make(map[string]string)
	for key, label := range gnsSrc.GetObjectMeta().GetLabels() {
		gnsDest.Labels[key] = label
	}
	gnsDest.Annotations = make(map[string]string)
	for key, annotation := range gnsSrc.GetObjectMeta().GetAnnotations() {
		gnsDest.Annotations[key] = annotation
	}
}

// isPanoramaGlobalNetworkSet returns true if the GlobalNetworkSet contains the
// annotation: "firewall.tigera.io/type: Panorama".
func (*dynamicAddressGroupsController) isPanoramaGlobalNetworkSet(gns *v3.GlobalNetworkSet) bool {
	if gns != nil {
		if panType, found := gns.Annotations[FirewallPrefix+"type"]; found {
			return panType == ParoramaType
		}
	}

	return false
}
