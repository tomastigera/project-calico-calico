// Copyright 2019-2024 Tigera Inc. All rights reserved.
package fortimanager

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	xconfig "github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
	fortilib "github.com/projectcalico/calico/firewall-integration/pkg/fortimanager"
	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// Controller health
const (
	healthReporterName   = "FortimanagerSelectorController"
	healthReportInterval = time.Second * 10
)

// Selection option
const (
	fwRoutableNode = "node"
)

// Firewall address
const (
	// A special firewall address object that this controller creates and manages.
	// This is used when a address group object has no matching pods/nodes for
	// the created policy. We use this in place of the "none" object because, the
	// "none" address can be removed by users or by a FortiManager managing
	// a FortiGate device and if there no objects that references this none address.
	noMembers = "no-members"
	// the subnet that we will assign to the no-members address object.
	// Even though it's used in the subnet field and called as a subnet,
	// it's still only valid as an IP address. A mask of /32 or 255.255.255.255
	// is automatically added by the appropriate client code.
	noMembersSubnet = "0.0.0.0"
)

type SelectorsController struct {
	ctx                context.Context
	cfg                *config.Config
	routablePod        bool
	k8sClientset       *kubernetes.Clientset
	fortiClients       map[string]fortilib.FortiFWClientApi
	k8sPodInformer     cache.Controller
	devToRcacheAddr    map[string]rcache.ResourceCache
	devToRcacheAddrGrp map[string]rcache.ResourceCache
	xrefCache          xrefcache.XrefCache
	healthAggregator   *health.HealthAggregator
	gnpToNodes         map[string]set.Set[string]
	gnpToPods          map[string]set.Set[v3.ResourceID]
	syncerUpdateChan   chan []syncer.Update
	calicoClientset    clientv3.ProjectcalicoV3Interface
	calicoGnpInformer  cache.Controller
}

func NewSelectorsController(
	ctx context.Context,
	cfg *config.Config,
	h *health.HealthAggregator,
	k8sClientset *kubernetes.Clientset,
	fcs map[string]fortilib.FortiFWClientApi,
	calicoClient clientv3.ProjectcalicoV3Interface,
) *SelectorsController {

	// Register with health reporting aggregator.
	h.RegisterReporter(healthReporterName, &health.HealthReport{Live: true}, healthReportInterval)

	// Create the Cross reference cache that we will use to track selector to node updates.
	healthy := func() {
		h.Report(healthReporterName, &health.HealthReport{Live: true})
	}
	xrefcacheConfig := &xconfig.Config{}
	xc := xrefcache.NewXrefCache(xrefcacheConfig, healthy)

	// Channel to serialize updates to the xrefcache
	// TODO(doublek): Make this buffered if necessary.
	syncerUpdateChan := make(chan []syncer.Update)

	// List/Watch Kubernetes Pods.
	podListWatcher := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "pods", "", fields.Everything())

	// Bind the Endpoint cache to Kubernetes cache.
	_, podInformer := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: podListWatcher,
		ObjectType:    &v1.Pod{},
		ResyncPeriod:  0,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				log.Debugf("Got ADD event for Pod: %#v", obj)
				pod := obj.(*v1.Pod)

				if pod.Spec.NodeName == "" {
					log.Infof("Filtering out pod that doesn't have a assigned node")
					return
				}

				pod.TypeMeta = resources.TypeK8sPods
				updates := []syncer.Update{
					{
						Type:       syncer.UpdateTypeSet,
						ResourceID: resources.GetResourceID(pod),
						Resource:   pod,
					},
				}

				log.Debugf("Dispatching pod updates : %+v", updates)
				syncerUpdateChan <- updates
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				log.Debugf("Got UPDATE event for Pod")
				log.Debugf("Old Pod: %#v", oldObj)
				log.Debugf("Updated Pod: %#v", newObj)
				pod := newObj.(*v1.Pod)

				if pod.Spec.NodeName == "" {
					log.Infof("Filtering out pod that doesn't have a assigned node")
					return
				}
				pod.TypeMeta = resources.TypeK8sPods

				updates := []syncer.Update{
					{
						Type:       syncer.UpdateTypeSet,
						ResourceID: resources.GetResourceID(pod),
						Resource:   pod,
					},
				}

				log.Debugf("Dispatching pod updates : %+v", updates)
				syncerUpdateChan <- updates
			},
			DeleteFunc: func(obj interface{}) {
				log.Debugf("Got DELETE event for Pod: %#v", obj)
				pod := obj.(*v1.Pod)

				if pod.Spec.NodeName == "" {
					log.Infof("Filtering out pod that doesn't have a assigned node")
					return
				}

				pod.TypeMeta = resources.TypeK8sPods

				updates := []syncer.Update{
					{
						Type:       syncer.UpdateTypeDeleted,
						ResourceID: resources.GetResourceID(pod),
						Resource:   pod,
					},
				}
				log.Debugf("Dispatching pod updates : %+v", updates)
				syncerUpdateChan <- updates
			},
		},
		Indexers: cache.Indexers{},
	})

	gnpToNodes := make(map[string]set.Set[string])
	gnpToPods := make(map[string]set.Set[v3.ResourceID])
	// Create cache clients for all Forti devices
	devToRcacheAddr := getResourceCacheAddress(fcs)
	devToRcacheAddrGrp := getResourceCacheAddressGrps(fcs)
	routablePod := cfg.FwAddressSelection != fwRoutableNode

	log.Infof("Firewall Controller is configured with routablePod:%+v", routablePod)
	log.Debugf("Device to RCacheAddr:%#v", devToRcacheAddr)
	log.Debugf("Device to RCacheAddrGrp:%#v", devToRcacheAddrGrp)

	sc := &SelectorsController{
		ctx:                ctx,
		cfg:                cfg,
		xrefCache:          xc,
		gnpToPods:          gnpToPods,
		gnpToNodes:         gnpToNodes,
		devToRcacheAddr:    devToRcacheAddr,
		devToRcacheAddrGrp: devToRcacheAddrGrp,
		routablePod:        routablePod,
		k8sClientset:       k8sClientset,
		k8sPodInformer:     podInformer,
		calicoClientset:    calicoClient,
		syncerUpdateChan:   syncerUpdateChan,
		healthAggregator:   h,
		fortiClients:       fcs,
		calicoGnpInformer:  newCalicoGnpInformer(cfg, gnpToNodes, gnpToPods, calicoClient, devToRcacheAddrGrp, syncerUpdateChan),
	}

	// Deal with selector to address group mappings
	if sc.routablePod {
		xc.RegisterOnUpdateHandler(resources.TypeCalicoGlobalNetworkPolicies,
			xrefcache.EventEndpointMatchStarted|xrefcache.EventEndpointMatchStopped,
			sc.onUpdate)
	} else {
		xc.RegisterOnUpdateHandler(resources.TypeCalicoGlobalNetworkPolicies,
			xrefcache.EventNodeAssigned|xrefcache.EventNodeRemoved,
			sc.onUpdate)
	}

	xc.RegisterOnStatusUpdateHandler(sc.onStatusUpdate)

	return sc
}

// Get label selector for selecting network policies
func getPolicySelectorLabel(policySelector string) string {
	// Remove single quotes from selector expression.
	// Single quotes in selector expression isn't processed by kubernetes api's
	// especially by option selector.
	return strings.ReplaceAll(policySelector, "'", "")
}

// Create ListWatcher & Informer for Global Network Policies
func newCalicoGnpInformer(cfg *config.Config, gnpToNodes map[string]set.Set[string], gnpToPods map[string]set.Set[v3.ResourceID],
	calicoClient clientv3.ProjectcalicoV3Interface,
	devToRcacheAddrGrp map[string]rcache.ResourceCache,
	syncerUpdateChan chan<- []syncer.Update) cache.Controller {

	log.WithFields(log.Fields{
		"policySelector":    cfg.FwPolicySelectorExpression,
		"NameSpaceSelector": cfg.FwPolicyNamespaceSelector,
		"label":             getPolicySelectorLabel(cfg.FwPolicySelectorExpression),
	}).Info("Forti network policy selectors")
	// ListWatcher for all GlobalNetwork Policies
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.LabelSelector = getPolicySelectorLabel(cfg.FwPolicySelectorExpression)
			return calicoClient.GlobalNetworkPolicies().List(context.Background(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.LabelSelector = getPolicySelectorLabel(cfg.FwPolicySelectorExpression)
			return calicoClient.GlobalNetworkPolicies().Watch(context.Background(), options)
		},
	}

	// Informer for Gnp
	_, gnpInformer := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: lw,
		ObjectType:    &v3.GlobalNetworkPolicy{},
		ResyncPeriod:  0,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				// Handle GNP add events
				log.Debugf("Got Add Event for GNP: %+v", obj)
				gnp := obj.(*v3.GlobalNetworkPolicy)

				// Create address Group
				addrGroup := AddressGroup{
					Name:    gnp.Name,
					Members: set.New[string](),
				}

				// Insert Address Group in Cache
				for _, cache := range devToRcacheAddrGrp {
					cache.Set(gnp.Name, addrGroup)
				}

				gnpToNodes[gnp.Name] = set.New[string]()
				gnpToPods[gnp.Name] = set.New[v3.ResourceID]()

				gnp.TypeMeta = resources.TypeCalicoGlobalNetworkPolicies
				// Create an update
				updates := []syncer.Update{
					{
						Type:       syncer.UpdateTypeSet,
						ResourceID: resources.GetResourceID(gnp),
						Resource:   gnp,
					},
				}
				// Dispatch to syncer
				log.Debugf("Dispatching GNP updates : %+v", updates)
				syncerUpdateChan <- updates

			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				// Handle GNP add events
				log.Debugf("Got UPDATE event for new GNP: %+v", newObj)
				log.Debugf("Got UPDATE event for old GNP: %+v", oldObj)

				gnpNew := newObj.(*v3.GlobalNetworkPolicy)
				gnpOld := oldObj.(*v3.GlobalNetworkPolicy)

				// If there is no change in Tier, Selector and name just return
				if gnpNew.Name == gnpOld.Name && gnpNew.Spec.Selector == gnpOld.Spec.Selector {
					log.Debug("No change in UPDATE event for GNP's")
					return
				}

				// Create address Group
				addrGroup := AddressGroup{
					Name:    gnpNew.Name,
					Members: set.New[string](),
				}

				// Update Address Group in Cache
				for _, cache := range devToRcacheAddrGrp {
					cache.Set(gnpNew.Name, addrGroup)
				}

				gnpNew.TypeMeta = resources.TypeCalicoGlobalNetworkPolicies

				gnpToNodes[gnpNew.Name] = set.New[string]()
				gnpToPods[gnpNew.Name] = set.New[v3.ResourceID]()

				// Create an update
				updates := []syncer.Update{
					{
						Type:       syncer.UpdateTypeSet,
						ResourceID: resources.GetResourceID(gnpNew),
						Resource:   gnpNew,
					},
				}
				// Dispatch to syncer
				log.Debugf("Dispatching GNP updates : %+v", updates)
				syncerUpdateChan <- updates

			},
			DeleteFunc: func(obj interface{}) {
				log.Debugf("Got DELETE event for GNP: %#v", obj)

				gnp := obj.(*v3.GlobalNetworkPolicy)

				gnp.TypeMeta = resources.TypeCalicoGlobalNetworkPolicies

				// Delete GNP key in local Map
				delete(gnpToNodes, gnp.Name)
				delete(gnpToPods, gnp.Name)

				// Delete Address Group in Cache
				for _, cache := range devToRcacheAddrGrp {
					cache.Delete(gnp.Name)
				}

				updates := []syncer.Update{
					{
						Type:       syncer.UpdateTypeDeleted,
						ResourceID: resources.GetResourceID(gnp),
						Resource:   gnp,
					},
				}

				// Dispatch to syncer
				log.Debugf("Dispatching GNP updates : %+v", updates)
				syncerUpdateChan <- updates
			},
		},
		Indexers: cache.Indexers{},
	})

	return gnpInformer
}

func (sc *SelectorsController) Run() {
	defer uruntime.HandleCrash()

	for _, cache := range sc.devToRcacheAddrGrp {
		workqueue := cache.GetQueue()
		defer workqueue.ShutDown()
	}

	log.Infof("Starting FortiGate Selector Controller")

	healthy := func() {
		sc.healthAggregator.Report(healthReporterName, &health.HealthReport{Live: true})
	}
	// TODO(doublek): Report at healthReportInterval.
	healthy()

	stopCh := make(chan struct{})
	defer close(stopCh)

	// Start XrefCache updater/worker so that updates from our pod informer
	// can be dispatched to the XrefCache.
	log.Infof("Starting XrefCache worker")
	// go sc.runXrefCacheWorker()
	go sc.runXrefCacheWorker()
	defer close(sc.syncerUpdateChan)

	log.Debug("Waiting to sync with Kubernetes API (Pods)")
	go sc.k8sPodInformer.Run(stopCh)
	for !sc.k8sPodInformer.HasSynced() {
	}
	// Signal that we've synced our initial pod state.
	sc.xrefCache.OnStatusUpdate(syncer.NewStatusUpdateInSync())
	log.Debug("Finished syncing with Kubernetes API (Pods)")

	// Start Address Group caches for all Forti Devices
	for dev, cache := range sc.devToRcacheAddrGrp {
		log.Infof("Starting FortiGate Address Group Cache for device:%#v polling time:%#v", dev, sc.cfg.FwPollInterval.String())
		cache.Run(sc.cfg.FwPollInterval.String())
	}
	for dev := range sc.devToRcacheAddrGrp {
		go sc.runWorkerAddrGrp(dev)
	}

	// Start Address caches for all Forti Devices
	for dev, cache := range sc.devToRcacheAddr {
		log.Infof("Starting FortiGate Address Cache for device:%#v polling time:%#v", dev, sc.cfg.FwPollInterval.String())
		cache.Run(sc.cfg.FwPollInterval.String())
	}
	sc.addNoMemberAddress()
	for dev := range sc.devToRcacheAddr {
		go sc.runWorkerAddr(dev)
	}

	stopChGnp := make(chan struct{})
	defer close(stopChGnp)

	log.Debugf("Waiting to sync with GlobalNetwork Policies")
	go sc.calicoGnpInformer.Run(stopChGnp)
	for !sc.calicoGnpInformer.HasSynced() {
	}

	log.Debugf("Finished syncing with Calico(GNP)")

	<-sc.ctx.Done()

	log.Infof("Stopping FortiGate Selector Controller")
}

// addNoMemberAddress tracks the special "no-member" firewall address object.
// This should be called after the cache is started and ideally before starting
// any of the other syncing methods.
func (sc *SelectorsController) addNoMemberAddress() {
	faddr := fortilib.RespFortiGateFWAddressData{
		Name:    noMembers,
		Comment: TigeraComment,
		Type:    fortilib.FortiGateIpMaskType,
		SubType: fortilib.FortiGateSdnType,
		Subnet:  noMembersSubnet,
	}
	log.Infof("Tracking Fortidevices with %v: fw:%#v", noMembers, faddr)
	for _, cache := range sc.devToRcacheAddr {
		cache.Set(faddr.Name, faddr)
	}
}

// Serializes updates to the xrefcache.
func (sc *SelectorsController) runXrefCacheWorker() {
	for updates := range sc.syncerUpdateChan {
		log.WithField("updates", updates).Info("Sending updates")
		sc.xrefCache.OnUpdates(updates)
	}
}

func (sc *SelectorsController) onUpdate(update syncer.Update) {
	if !sc.routablePod {
		sc.handleNodeUpdate(update)
	} else {
		sc.handlePodUpdate(update)
	}

}

func (sc *SelectorsController) onStatusUpdate(status syncer.StatusUpdate) {
	switch status.Type {
	case syncer.StatusTypeFailed:
		log.Fatalf("Error occurred: %v", status.Error)
	case syncer.StatusTypeComplete:
		log.Info("Selectors processed")
	}
}

func (sc *SelectorsController) runWorkerAddrGrp(dev string) {
	for sc.processNextItemAddrGrp(dev) {
	}
}

func (sc *SelectorsController) processNextItemAddrGrp(dev string) bool {
	workqueue := sc.devToRcacheAddrGrp[dev].GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync with FortiManager
	if err := sc.syncToFortiGateAddrGrp(key.(string), dev); err != nil {
		sc.handleError(err, key.(string), dev, true)
	}

	workqueue.Done(key)
	return true
}

func (sc *SelectorsController) runWorkerAddr(dev string) {
	for sc.processNextItemAddr(dev) {
	}
}

func (sc *SelectorsController) processNextItemAddr(dev string) bool {
	workqueue := sc.devToRcacheAddr[dev].GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}
	// Sync with FortiGate
	if err := sc.syncToFortiGateAddr(key.(string), dev); err != nil {
		sc.handleError(err, key.(string), dev, false)
	}
	workqueue.Done(key)
	return true
}

func (sc *SelectorsController) syncToFortiGateAddrGrp(key, dev string) error {
	clog := log.WithFields(log.Fields{
		"key":    key,
		"device": dev,
	})
	clog.Debugf("Should sync key:%v for device:%v", key, dev)
	fc := sc.fortiClients[dev]

	obj, exists := sc.devToRcacheAddrGrp[dev].Get(key)
	if !exists {
		// The object doesn't exist. Delete from FortiGate.
		clog.Debugf("Deleting AddressGroup from FortiGate %+v", key)
		err := fc.DeleteFirewallAddressGroup(key)
		if err != nil {
			if _, ok := err.(fortilib.ErrorResourceDoesNotExist); !ok {
				log.WithError(err).Error("Error when deleting Address Group")
				return err
			}
		}
		return nil
	} else {
		// The object exists - update the datastore to reflect.
		addr := obj.(AddressGroup)
		clog.Debugf("Create/Update AddressGroup in FortiGate %#v", addr)

		// Lookup to see if this object already exists in the FortiGate.
		existingAddressGroup, err := fc.GetFirewallAddressGroup(addr.Name)
		if err != nil {
			if _, ok := err.(fortilib.ErrorResourceDoesNotExist); !ok {
				log.WithError(err).Error("Error when creating Firewall Address")
				return nil
			}
			log.Debugf("Will create address group now %+v", addr)
			// Need to create Address Group
			fwAddrGrp := fortilib.FortiFWAddressGroup{
				Name:    addr.Name,
				Comment: TigeraComment,
				Members: []string{noMembers},
			}
			err := fc.CreateFirewallAddressGroup(fwAddrGrp)
			if err != nil {
				clog.WithError(err).Warning("Failed to create AddressGroup in FortiGate")
				return err
			}
			clog.Debug("Successfully created AddressGroup")
			return nil
		}

		// Existing object. Time to update it.
		clog.Debug("Updating AddressGroup in FortiGate")
		members := []string{}
		for item := range addr.Members.All() {
			nodeName := item
			members = append(members, nodeName)
		}
		if len(members) == 0 {
			members = []string{noMembers}
		}
		addrGroupData := fortilib.FortiFWAddressGroup{
			Name:    existingAddressGroup.Name,
			Comment: TigeraComment,
			Members: members,
		}

		err = fc.UpdateFirewallAddressGroup(addrGroupData)
		if err != nil {
			clog.WithError(err).Warning("Failed to update AddressGroup in FortiGate")
			return err
		}
		clog.Debug("Successfully updated AddressGroup in FortiGate")
		return nil
	}
}

func (sc *SelectorsController) syncToFortiGateAddr(key, dev string) error {
	clog := log.WithFields(log.Fields{
		"key":    key,
		"device": dev,
	})
	clog.Debugf("Should sync key:%v for device:%v", key, dev)
	fc := sc.fortiClients[dev]

	obj, exists := sc.devToRcacheAddr[dev].Get(key)
	if !exists {
		fortiFWAddr := fortilib.FortiFWAddress{
			Name: key,
		}
		// The object doesn't exist. Delete from FortiGate.
		clog.Debug("Deleting FirewallAddress from FortiGate")
		err := fc.DeleteFirewallAddress(fortiFWAddr)
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			// We hit an error other than "does not exist".
			return err
		}
		return nil
	} else {
		// The object exists - update the datastore to reflect.
		clog.Debug("Create/Update FirewallAddress in FortiGate")
		addr := obj.(fortilib.RespFortiGateFWAddressData)

		// Create a Firewall Object in Fortidevice
		fortiFWAddr := fortilib.FortiFWAddress{
			Name:    addr.Name,
			IpAddr:  addr.Subnet,
			Mask:    "255.255.255.255",
			Comment: TigeraComment,
		}
		// Lookup to see if this object already exists in the FortiGate.
		_, err := fc.GetFirewallAddress(addr.Name)
		if err != nil {
			// TODO(doublek): Handle doesn't exist error here.
			if _, ok := err.(fortilib.ErrorResourceDoesNotExist); !ok {
				log.WithError(err).Error("Error when creating Firewall Address")
				return nil
			}

			err := fc.CreateFirewallAddress(fortiFWAddr)
			if err != nil {
				clog.WithError(err).Warning("Failed to create FirewallAddress in FortiGate")
				return err
			}
			clog.Debug("Successfully created FirewallAddress")
			return nil
		}

		// Existing object. Time to update it.
		clog.Debug("Updating FirewallAddress in FortiGate")
		err = fc.UpdateFirewallAddress(fortiFWAddr)
		if err != nil {
			clog.WithError(err).Warning("Failed to update FirewallAddress in FortiGate")
			return err
		}
		clog.Debug("Successfully updated FirewallAddress in FortiGate")
		return nil
	}
}

func (sc *SelectorsController) handleError(err error, key, dev string, addrGrp bool) {

	var workqueue workqueue.TypedRateLimitingInterface[any]
	if addrGrp {
		workqueue = sc.devToRcacheAddrGrp[dev].GetQueue()
	} else {
		workqueue = sc.devToRcacheAddr[dev].GetQueue()
	}
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
		log.WithError(err).Errorf("Error syncing Profile %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping Profile %q out of the queue: %v", key, err)
}

// Handles the NodeAssigned/NodeRemoved events from the xrefcache
// Based on the Update, AddressCache and AddressGroup cache are modified
func (sc *SelectorsController) handleNodeUpdate(update syncer.Update) {

	cachedEntry := sc.xrefCache.Get(update.ResourceID)
	cachedEntryGNP := cachedEntry.(*xrefcache.CacheEntryNetworkPolicy)

	log.Infof("NodeUpdate: %#v", update)
	if update.Type&xrefcache.EventNodeAssigned != 0 {
		log.Infof("Received node assigned update %+v", update)
		log.Debugf("Node info from cache %+v", cachedEntryGNP.ScheduledNodes)

		// Create Firewall Address Object for every single Node
		for node := range cachedEntryGNP.ScheduledNodes {

			nodeName := string(node)
			// Get Node status from dataStore
			n, err := sc.k8sClientset.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
			if err != nil {
				log.WithError(err).Errorf("Failed to get Node resource from k8s client for node:%#v", nodeName)
				continue
			}
			// Convert Node information into Fortinet Firewall Address object
			fw, err := ConvertK8sNodeToFortinetFirewallAddress(n)
			if err != nil {
				log.WithError(err).Errorf("Failed to convert node to FW address object %#v", nodeName)
				continue
			}
			log.Infof("Node Name:%v fw:%#v", nodeName, fw)
			for _, cache := range sc.devToRcacheAddr {
				// Update Address Cache
				cache.Set(fw.Name, fw)
			}
		}

		// Create an Address Group for a global network policy
		// Address Group name must match with network policy Name.
		nodes := sc.gnpToNodes[update.ResourceID.Name]
		members := []string{}
		for node := range cachedEntryGNP.ScheduledNodes {
			nodes.Add(node)
			log.Infof("Assigning node %v to address group %v", node, update.ResourceID.Name)
			members = append(members, node)
		}
		// Update gnpTONodes to reflect new nodes
		sc.gnpToNodes[update.ResourceID.Name] = nodes

		addrGroup := AddressGroup{
			Name:    update.ResourceID.Name,
			Members: set.FromArray(members),
		}
		// Update AddressGroup Cache
		for _, cache := range sc.devToRcacheAddrGrp {
			// Update AddressGroup Cache
			cache.Set(addrGroup.Name, addrGroup)
		}

	} else if update.Type&xrefcache.EventNodeRemoved != 0 {
		log.Infof("Received node removed update %+v", update)

		// Iterate over nodes linked to a GNP, if Node is
		// NOT present in xrefcache, that means Node had been removed.
		nodes := sc.gnpToNodes[update.ResourceID.Name]
		for item := range nodes.All() {
			nodeName := item
			// If a Node isn't present in xrefcache, delete in Fortigate
			_, ok := cachedEntryGNP.ScheduledNodes[nodeName]
			if !ok {
				for _, cache := range sc.devToRcacheAddr {
					cache.Delete(nodeName)
				}
			}
		}

		// Create an Address Group for a global network policy
		// Address Group name must match with network policy Name.
		nodes = sc.gnpToNodes[update.ResourceID.Name]
		members := []string{}
		for item := range nodes.All() {
			nodeName := item
			_, ok := cachedEntryGNP.ScheduledNodes[nodeName]
			if !ok {
				// The Node that we were tracking is no longer referenced in the GNP,
				// Remove this node as the address group member.
				log.Infof("Removing node %v from address group %v", nodeName, update.ResourceID.Name)
				nodes.Discard(item)
				continue
			}
			members = append(members, nodeName)
		}
		if len(members) == 0 {
			members = []string{noMembers}
		}
		addrGroup := AddressGroup{
			Name:    update.ResourceID.Name,
			Members: set.FromArray(members),
		}

		for _, cache := range sc.devToRcacheAddrGrp {
			// Update AddressGroup Cache
			cache.Set(addrGroup.Name, addrGroup)
		}
	} else {
		log.Warningf("Received update we didn't subscribe for %+v", update)
	}
}

// Handles the PodAssigned/NodeRemoved events from the xrefcache
// Based on the Update, AddressCache and AddressGroup cache are modified
func (sc *SelectorsController) handlePodUpdate(update syncer.Update) {
	cachedEntry := sc.xrefCache.Get(update.ResourceID)
	cachedEntryGNP := cachedEntry.(*xrefcache.CacheEntryNetworkPolicy)
	if update.Type&xrefcache.EventEndpointMatchStarted != 0 {
		log.Infof("Received node Event Policy started %#v", update)

		// Create a Firewall Address object in Address cache.
		for id := range cachedEntryGNP.SelectedPods.All() {
			p, err := sc.k8sClientset.CoreV1().Pods(id.Namespace).Get(context.Background(), id.Name, metav1.GetOptions{})
			if err != nil {
				log.WithError(err).Errorf("failed to get pod resource from k8s client for pod:%#v", id.Name)
				continue
			} else {
				fw, err := ConvertK8sPodToFortinetFirewallAddress(p)
				if err != nil {
					log.WithError(err).Error("Failed to convert to Fortinet Firewall Address")
					continue
				}
				for _, cache := range sc.devToRcacheAddr {
					// Update address object in Address Cache.
					cache.Set(fw.Name, fw)
				}
			}
		}

		// Create a Firewall Address Group object in AddressGroup cache.
		// Create an Address Group for a global network policy
		// Address Group name must match with network policy Name.
		pods := sc.gnpToPods[update.ResourceID.Name]
		members := []string{}
		for id := range cachedEntryGNP.SelectedPods.All() {
			podName := fmt.Sprintf("%s-%s", id.Namespace, id.Name)
			pods.Add(id)
			log.Infof("Assigning pod %v to address group %v", podName, update.ResourceID.Name)
			members = append(members, podName)
		}
		sc.gnpToPods[update.ResourceID.Name] = pods

		addrGroup := AddressGroup{
			Name:    update.ResourceID.Name,
			Members: set.FromArray(members),
		}
		for _, cache := range sc.devToRcacheAddrGrp {
			// Update AddressGroup Cache
			cache.Set(addrGroup.Name, addrGroup)
		}
	} else if update.Type&xrefcache.EventEndpointMatchStopped != 0 {
		log.Infof("Received pod event Policy stopped %#v", update)

		// If applicable, Delete a Firewall Address object in Address cache.
		// Iterate over pods linked to a GNP, if a pod is
		// NOT present in xrefcache, that means pod had been removed.
		pods := sc.gnpToPods[update.ResourceID.Name]
		for item := range pods.All() {

			podName := fmt.Sprintf("%s-%s", item.Namespace, item.Name)
			ok := cachedEntryGNP.SelectedPods.Contains(item)
			if !ok {
				log.Debugf("Pod is not present in xrefCache, hence delete :%#v", podName)
				for _, cache := range sc.devToRcacheAddr {
					cache.Delete(podName)
				}
			}
		}

		// Modify an Address Group for a global network policy
		// Address Group name must match with network policy Name.
		pods = sc.gnpToPods[update.ResourceID.Name]
		members := []string{}
		for item := range pods.All() {
			podName := fmt.Sprintf("%s-%s", item.Namespace, item.Name)
			ok := cachedEntryGNP.SelectedPods.Contains(item)
			if !ok {
				// The pod that we were tracking is no longer referenced in the GNP,
				// Remove this node as the address group member.
				log.Infof("Removing pod %v from address group %v", podName, update.ResourceID.Name)
				pods.Discard(item)
				continue
			}
			members = append(members, podName)
		}
		if len(members) == 0 {
			members = []string{noMembers}
		}
		addrGroup := AddressGroup{
			Name:    update.ResourceID.Name,
			Members: set.FromArray(members),
		}

		for _, cache := range sc.devToRcacheAddrGrp {
			cache.Set(addrGroup.Name, addrGroup)
		}
	} else {
		log.Warningf("Received update we didn't subscribe for %+v", update)
	}
}

func getResourceCacheAddressGrps(fcs map[string]fortilib.FortiFWClientApi) map[string]rcache.ResourceCache {

	devToRcacheAddrGrp := make(map[string]rcache.ResourceCache)
	for dev, fc := range fcs {

		// List FortiGate address groups
		listFuncAddrGrp := func() (map[string]interface{}, error) {
			groups := make(map[string]interface{})

			addrGroups, err := fc.ListAllFirewallAddressGroups()
			if err != nil {
				return nil, err
			}

			for _, addrg := range addrGroups {
				if !strings.Contains(addrg.Comment, TigeraComment) {
					log.Debugf("Filtering out %s as it's not something we manage", addrg.Name)
					continue
				}
				groups[addrg.Name] = addrg
			}
			log.Debugf("List of address groups: %+v", groups)
			return groups, nil
		}

		// Setup a cache for FortiGate Firewall Addresses.
		cacheArgsAddrGrp := rcache.ResourceCacheArgs{
			ListFunc:    listFuncAddrGrp,
			ObjectType:  reflect.TypeOf(AddressGroup{}),
			LogTypeDesc: fmt.Sprintf("Fortidevice AddressGroup for dev :%s", dev),
		}
		fcacheAddrGrp := rcache.NewResourceCache(cacheArgsAddrGrp)
		devToRcacheAddrGrp[dev] = fcacheAddrGrp
	}
	return devToRcacheAddrGrp
}

func getResourceCacheAddress(fcs map[string]fortilib.FortiFWClientApi) map[string]rcache.ResourceCache {

	devToRcacheAddr := make(map[string]rcache.ResourceCache)
	for dev, fc := range fcs {
		// List FortiGate firewall addresses
		listFuncAddr := func() (map[string]interface{}, error) {
			addresses := make(map[string]interface{})

			fwAddresses, err := fc.ListAllFirewallAddresses()
			if err != nil {
				return nil, err
			}

			for _, addr := range fwAddresses {
				// Filter only Addresses managed by
				if !strings.Contains(addr.Comment, TigeraComment) {
					continue
				}
				addresses[addr.Name] = fortilib.RespFortiGateFWAddressData{
					Name:    addr.Name,
					Comment: addr.Comment,
					Type:    addr.Type,
					SubType: addr.SubType,
					Subnet:  addr.IpAddr,
				}
			}
			log.Debugf("List of addresses: %+v", addresses)
			return addresses, nil
		}

		// Setup a cache for FortiGate Firewall Addresses.
		cacheArgsAddr := rcache.ResourceCacheArgs{
			ListFunc:    listFuncAddr,
			ObjectType:  reflect.TypeOf(fortilib.RespFortiGateFWAddressData{}),
			LogTypeDesc: fmt.Sprintf("Fortidevice Address for dev :%s", dev),
		}
		fcacheAddr := rcache.NewResourceCache(cacheArgsAddr)
		devToRcacheAddr[dev] = fcacheAddr
	}

	return devToRcacheAddr
}
