// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package xrefcache

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/ips"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	internalv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	// The set of pod flags that are updated directly from the network policy flags associated with the pod.
	CacheEntryEndpointAndNetworkPolicy = CacheEntryFlagsEndpoint & CacheEntryFlagsNetworkPolicy
)

const (
	fakePodIP       = "255.255.255.255"
	fakePodNodeName = "@"
)

var (
	KindsEndpoint = []metav1.TypeMeta{
		resources.TypeCalicoHostEndpoints,
		resources.TypeK8sPods,
	}
)

// VersionedEndpointResource is an extension of the VersionedResource interface, specific to handling Pods.
type VersionedEndpointResource interface {
	VersionedResource
	GetFlowLogAggregationName() string
	GetCalicoV1Labels() uniquelabels.Map
	GetCalicoV1Profiles() []string
	getIPOrEndpointIDs() (set.Set[string], error)
	getEnvoyEnabled(engine *endpointHandler) bool
	getServiceAccount() *apiv3.ResourceID
}

// CacheEntryEndpoint implements the CacheEntry interface, and is what we stored in the Pods cache.
type CacheEntryEndpoint struct {
	// The versioned policy resource.
	VersionedEndpointResource

	// Boolean values associated with this pod. Valid flags defined by CacheEntryFlagsEndpoint.
	Flags CacheEntryFlags

	// Policies applied to this pod.
	AppliedPolicies set.Typed[apiv3.ResourceID]

	// Services whose endpoints include this endpoint
	Services set.Typed[apiv3.ResourceID]

	// Service account associated with this endpoint.
	ServiceAccount *apiv3.ResourceID

	// --- Internal data ---
	cacheEntryCommon
	clog         *log.Entry
	policySorter PolicySorter
}

// getVersionedResource implements the CacheEntry interface.
func (c *CacheEntryEndpoint) getVersionedResource() VersionedResource {
	return c.VersionedEndpointResource
}

// setVersionedResource implements the CacheEntry interface.
func (c *CacheEntryEndpoint) setVersionedResource(r VersionedResource) {
	c.VersionedEndpointResource = r.(VersionedEndpointResource)
}

// GetOrderedTiersAndPolicies returns the ordered set of tiers with their policies that apply to this endpoint.
func (c *CacheEntryEndpoint) GetOrderedTiersAndPolicies() []*TierWithOrderedPolicies {
	allTiers := c.policySorter.GetOrderedTiersAndPolicies()

	// TODO(rlb): We don't cache the results at the moment. We can do some revision based processing and cache if we
	//            find that we need to. Basic idea would be to give the policySorter a revision so we can tell if the
	//            ourRevision is out of date. Our revision would also be reset if there was a change to which policies
	//            applied to this endpoint.
	var filteredTiers []*TierWithOrderedPolicies
	for _, t := range allTiers {
		var filteredPols []*CacheEntryNetworkPolicy
		for _, p := range t.OrderedPolicies {
			if c.AppliedPolicies.Contains(p.getResourceID()) {
				filteredPols = append(filteredPols, p)
			}
		}
		if len(filteredPols) > 0 {
			filteredTiers = append(filteredTiers, &TierWithOrderedPolicies{
				Tier:            t.Tier,
				OrderedPolicies: filteredPols,
			})
		}
	}
	return filteredTiers
}

// versionedK8sNamespace implements the VersionedEndpointResource interface.
type versionedK8sPod struct {
	*corev1.Pod
	v3      *internalv3.WorkloadEndpoint
	v1      *model.WorkloadEndpoint
	validIP bool
}

// GetFlowLogAggregationName implements the VersionedEndpointResource interface.
func (v *versionedK8sPod) GetFlowLogAggregationName() string {
	if v.GenerateName != "" {
		return fmt.Sprintf("%s*", v.GenerateName)
	} else {
		return v.Name
	}
}

// GetPrimary implements the VersionedNetworkSetResource interface.
func (v *versionedK8sPod) GetPrimary() resources.Resource {
	return v.Pod
}

// GetCalicoV3 implements the VersionedEndpointResource interface.
func (v *versionedK8sPod) GetCalicoV3() resources.Resource {
	return v.v3
}

// getCalicoV1 implements the VersionedEndpointResource interface.
func (v *versionedK8sPod) GetCalicoV1() interface{} {
	return v.v1
}

// getLabels implements the VersionedEndpointResource interface.
func (v *versionedK8sPod) GetCalicoV1Labels() uniquelabels.Map {
	return v.v1.Labels
}

// getLabels implements the VersionedEndpointResource interface.
func (v *versionedK8sPod) GetCalicoV1Profiles() []string {
	return v.v1.ProfileIDs
}

func (v *versionedK8sPod) getIPOrEndpointIDs() (set.Set[string], error) {
	if v.validIP {
		// Where possible use the IP address to identify the pod.
		return ips.NormalizedIPSet(v.v3.Spec.IPNetworks...)
	}
	// If the pod IP address is not present (which it might not be since we don't recommend auditing pod status)
	// then use the pod ID converted to a string to identify this endpoint.
	id := resources.GetResourceID(v.Pod).String()
	log.Debugf("Including %s in IP/endpoint ID match", id)
	return set.From[string](id), nil
}

func (v *versionedK8sPod) getEnvoyEnabled(engine *endpointHandler) bool {
	// If all of the required checks passed then return true.
	var checked bool

	// Check annotations.
	if engine.podIstioSidecarAnnotation != "" {
		if _, ok := v.Annotations[engine.podIstioSidecarAnnotation]; !ok {
			log.Debugf("Pod annotation does not incude %s", engine.podIstioSidecarAnnotation)
			return false
		}
		checked = true
	}
	// Check init containers.
	if engine.podIstioInitContainerRegex != nil {
		var found bool
		for idx := range v.Spec.InitContainers {
			if engine.podIstioInitContainerRegex.MatchString(v.Pod.Spec.InitContainers[idx].Image) {
				found = true
				break
			}
		}
		if !found {
			log.Debugf("No Istio init container found")
			return false
		}
		checked = true
	}
	// Check containers.
	if engine.podIstioContainerRegex != nil {
		var found bool
		for idx := range v.Spec.Containers {
			if engine.podIstioContainerRegex.MatchString(v.Pod.Spec.Containers[idx].Image) {
				found = true
				break
			}
		}
		if !found {
			log.Debugf("No Istio container found")
			return false
		}
		checked = true
	}

	return checked
}

func (v *versionedK8sPod) getServiceAccount() *apiv3.ResourceID {
	if v.Spec.ServiceAccountName == "" {
		return nil
	}
	return &apiv3.ResourceID{
		TypeMeta:  resources.TypeK8sServiceAccounts,
		Name:      v.Spec.ServiceAccountName,
		Namespace: v.Namespace,
	}
}

// versionedCalicoHostEndpoint implements the VersionedEndpointResource interface.
type versionedCalicoHostEndpoint struct {
	*apiv3.HostEndpoint
	v1 *model.HostEndpoint
}

// GetFlowLogAggregationName implements the VersionedEndpointResource interface.
func (v *versionedCalicoHostEndpoint) GetFlowLogAggregationName() string {
	// v3.HostEndpoint's Node field corresponds to the v1.HostEndpointKey's
	// Hostname which is used as the aggregate name.
	return v.Spec.Node
}

// GetPrimary implements the VersionedNetworkSetResource interface.
func (v *versionedCalicoHostEndpoint) GetPrimary() resources.Resource {
	return v.HostEndpoint
}

// GetCalicoV3 implements the VersionedEndpointResource interface.
func (v *versionedCalicoHostEndpoint) GetCalicoV3() resources.Resource {
	return v.HostEndpoint
}

// getCalicoV1 implements the VersionedEndpointResource interface.
func (v *versionedCalicoHostEndpoint) GetCalicoV1() interface{} {
	return v.v1
}

// getLabels implements the VersionedEndpointResource interface.
func (v *versionedCalicoHostEndpoint) GetCalicoV1Labels() uniquelabels.Map {
	return v.v1.Labels
}

// getLabels implements the VersionedEndpointResource interface.
func (v *versionedCalicoHostEndpoint) GetCalicoV1Profiles() []string {
	return v.v1.ProfileIDs
}

func (v *versionedCalicoHostEndpoint) getIPOrEndpointIDs() (set.Set[string], error) {
	if len(v.Spec.ExpectedIPs) == 0 {
		return nil, errors.New("no expectedIPs configured")
	}
	return ips.NormalizedIPSet(v.Spec.ExpectedIPs...)
}

func (v *versionedCalicoHostEndpoint) getEnvoyEnabled(engine *endpointHandler) bool {
	return false
}

func (v *versionedCalicoHostEndpoint) getServiceAccount() *apiv3.ResourceID {
	return nil
}

// newEndpointHandler creates a resourceHandler used to handle the Pods cache.
func newEndpointHandler(config *config.Config) resourceHandler {
	var podIstioContainerRegex, podIstioInitContainerRegex *regexp.Regexp
	if config.PodIstioContainerRegex != "" {
		log.Debugf("Using regex for istio container: %s", config.PodIstioContainerRegex)
		podIstioContainerRegex = regexp.MustCompile(config.PodIstioContainerRegex)
	}
	if config.PodIstioInitContainerRegex != "" {
		log.Debugf("Using regex for istio init container: %s", config.PodIstioInitContainerRegex)
		podIstioInitContainerRegex = regexp.MustCompile(config.PodIstioInitContainerRegex)
	}
	return &endpointHandler{
		podIstioSidecarAnnotation:  config.PodIstioSidecarAnnotation,
		podIstioContainerRegex:     podIstioContainerRegex,
		podIstioInitContainerRegex: podIstioInitContainerRegex,
		includeStaged:              config.IncludeStagedNetworkPolicies,
		converter:                  conversion.NewConverter(),
	}
}

// endpointHandler implements the resourceHandler.
type endpointHandler struct {
	CacheAccessor
	converter conversion.Converter

	// Istio checks to determine if Envoy is enabled.
	podIstioSidecarAnnotation  string
	podIstioInitContainerRegex *regexp.Regexp
	podIstioContainerRegex     *regexp.Regexp
	includeStaged              bool
}

// kinds implements the resourceHandler interface.
func (c *endpointHandler) kinds() []metav1.TypeMeta {
	return KindsEndpoint
}

// register implements the resourceHandler interface.
func (c *endpointHandler) register(cache CacheAccessor) {
	nptm := policyKinds(c.includeStaged)
	c.CacheAccessor = cache
	c.EndpointLabelSelector().RegisterCallbacks(nptm, c.policyMatchStarted, c.policyMatchStopped)
	c.IPOrEndpointManager().RegisterCallbacks(KindsServices, c.ipMatchStarted, c.ipMatchStopped)

	// Register for updates for all NetworkPolicy events. We don't care about Added/Deleted/Updated events as any
	// changes to the cross-referencing will result in a notification here where we will requeue any changed endpoints.
	for _, kind := range nptm {
		c.RegisterOnUpdateHandler(
			kind,
			syncer.UpdateType(CacheEntryFlagsNetworkPolicy),
			c.queueEndpointsForRecalculation,
		)
	}
}

// newCacheEntry implements the resourceHandler interface.
func (c *endpointHandler) newCacheEntry() CacheEntry {
	return &CacheEntryEndpoint{
		AppliedPolicies: set.New[apiv3.ResourceID](),
		Services:        set.New[apiv3.ResourceID](),
		policySorter:    c.PolicySorter(),
	}
}

// convertToVersioned implements the resourceHandler interface.
func (c *endpointHandler) convertToVersioned(res resources.Resource) (VersionedResource, error) {
	// Accept AAPIS versions of the Calico resources, but convert them to the libcalico-go versions.
	switch tr := res.(type) {
	case *apiv3.HostEndpoint:
		res = &apiv3.HostEndpoint{
			TypeMeta:   tr.TypeMeta,
			ObjectMeta: tr.ObjectMeta,
			Spec:       tr.Spec,
		}
	}

	switch in := res.(type) {
	case *apiv3.HostEndpoint:
		v1, err := updateprocessors.ConvertHostEndpointV3ToV1(&model.KVPair{
			Key: model.ResourceKey{
				Kind: apiv3.KindHostEndpoint,
				Name: in.Name,
			},
			Value: in,
		})
		if err != nil {
			return nil, err
		}

		return &versionedCalicoHostEndpoint{
			HostEndpoint: in,
			v1:           v1.Value.(*model.HostEndpoint),
		}, nil
	case *corev1.Pod:
		// If pod status is being archived then we will have the actual pod status to hand and can ignore completed
		// or failed pods.
		if conversion.IsFinished(in) {
			id := resources.GetResourceID(in)
			log.Debugf("Pod status indicates finished: %s is %s", id, in.Status.Phase)
			return nil, cerrors.ErrorResourceDoesNotExist{
				Identifier: id,
				Err:        errors.New("pod status indicates finished"),
			}
		}

		// Check if an IP address is available, if not then it won't be possible to convert the Pod.
		// TODO: revert line below to use the method in libcalico-go-private:
		// podIPs, ipErr := c.converter.GetPodIPs(in)
		podIPs, ipErr := getPodIPs(in)
		validIP := true
		if ipErr != nil || len(podIPs) == 0 {
			// There is no valid IP. In this case we need to sneak in an IP address in order to get the conversion
			// to succeed. We'll flag that this IP address is not actually valid which will mean the getIPOrEndpointIDs
			// will not return this invalid IP. The upshot of this is that we might be flagging a pod that never became
			// active, but we are focussing mostly on intent and so this is a good approximation.
			log.Debugf("Setting fake IP in Pod to ensure conversion is handled correctly - IP will be ignored: %s",
				resources.GetResourceID(in))
			in.Status.PodIP = fakePodIP
			validIP = false
		}

		// The pod node name is updated as part of status despite being in the pod spec. As a result we have to handle
		// it being not set gracefully.
		if in.Spec.NodeName == "" {
			in.Spec.NodeName = fakePodNodeName
		}

		kvps, err := c.converter.PodToWorkloadEndpoints(in)
		if err != nil {
			return nil, err
		}
		log.WithField("id", resources.GetResourceID(in)).Debug("Converted Pod to Calico WEP")

		// This needs to be re evaluated to handle multi WorkloadEndpoints being returned in the multi-NICs case (ticket
		// SAAS-833)
		kvp := kvps[0]

		v3, ok := kvp.Value.(*internalv3.WorkloadEndpoint)
		if !ok {
			// Handle gracefully the possibility that the Value is nil.
			log.Error("Pod to workload endpoint conversion failed")
			return nil, nil
		}

		v1, err := updateprocessors.ConvertWorkloadEndpointV3ToV1Value(v3)
		if err != nil {
			return nil, err
		}
		if v1 == nil {
			// The update processor may filter out WEPs, for example if the Pod was completed then the IPNets will have
			// been removed.
			log.Debug("Update processor has filtered out the workload endpoint")
			return nil, nil
		}

		return &versionedK8sPod{
			Pod:     in,
			v3:      v3,
			v1:      v1.(*model.WorkloadEndpoint),
			validIP: validIP,
		}, nil
	}

	return nil, nil
}

// TODO: Remove method and use the method in libcalico-go-private:
func getPodIPs(pod *corev1.Pod) ([]*cnet.IPNet, error) {
	var podIPs []string
	if ips := pod.Status.PodIPs; len(ips) != 0 {
		log.WithField("ips", ips).Debug("PodIPs field filled in")
		for _, ip := range ips {
			podIPs = append(podIPs, ip.IP)
		}
	} else if ip := pod.Status.PodIP; ip != "" {
		log.WithField("ip", ip).Debug("PodIP field filled in")
		podIPs = append(podIPs, ip)
	} else if ips := pod.Annotations[conversion.AnnotationPodIPs]; ips != "" {
		log.WithField("ips", ips).Debug("No PodStatus IPs, use Calico plural annotation")
		podIPs = append(podIPs, strings.Split(ips, ",")...)
	} else if ip := pod.Annotations[conversion.AnnotationPodIP]; ip != "" {
		log.WithField("ip", ip).Debug("No PodStatus IPs, use Calico singular annotation")
		podIPs = append(podIPs, ip)
	} else {
		log.Debug("Pod has no IP")
		return nil, nil
	}
	var podIPNets []*cnet.IPNet
	for _, ip := range podIPs {
		_, ipNet, err := cnet.ParseCIDROrIP(ip)
		if err != nil {
			log.WithFields(log.Fields{"ip": ip, "pod": pod.Name}).WithError(err).Error("Failed to parse pod IP")
			return nil, err
		}
		podIPNets = append(podIPNets, ipNet)
	}
	return podIPNets, nil
}

// resourceAdded implements the resourceHandler interface.
func (c *endpointHandler) resourceAdded(id apiv3.ResourceID, entry CacheEntry) {
	x := entry.(*CacheEntryEndpoint)
	x.clog = log.WithField("id", id)

	// Set the service account now since it is not changeable after creation.
	x.ServiceAccount = x.getServiceAccount()

	// Our updated processing can do the rest.
	c.resourceUpdated(id, entry, nil)
}

// resourceUpdated implements the resourceHandler interface.
func (c *endpointHandler) resourceUpdated(id apiv3.ResourceID, entry CacheEntry, prev VersionedResource) {
	x := entry.(*CacheEntryEndpoint)

	x.clog.Debugf("Configuring profiles: %v", x.GetCalicoV1Profiles())

	// Update the labels associated with this pod. Use the labels and profile from the v1 model since these are
	// modified to include namespace and service account details.
	c.EndpointLabelSelector().UpdateLabels(id, x.GetCalicoV1Labels(), x.GetCalicoV1Profiles())

	// Update the IP manager with the entries updated IP addresses or if the IP address is unknown the endpoint ID.
	i, err := x.getIPOrEndpointIDs()
	if err != nil {
		x.clog.Info("Unable to determine IP addresses")
	}
	c.IPOrEndpointManager().SetOwnerKeys(id, i)
}

// resourceDeleted implements the resourceHandler interface.
func (c *endpointHandler) resourceDeleted(id apiv3.ResourceID, _ CacheEntry) {
	// Delete the labels associated with this pod. Default cache processing will remove this cache entry.
	c.EndpointLabelSelector().DeleteLabels(id)

	// Delete the endpoint from the IP manager.
	c.IPOrEndpointManager().DeleteOwner(id)
}

// recalculate implements the resourceHandler interface.
func (c *endpointHandler) recalculate(podId apiv3.ResourceID, epEntry CacheEntry) syncer.UpdateType {
	x := epEntry.(*CacheEntryEndpoint)

	// ------
	// See note in flags.go for details of the bitwise operations for boolean values and their associated update type.
	// ------

	// Store the current set of flags.
	oldFlags := x.Flags

	// Clear the set of flags that will be reset from the applied network Policies.
	x.Flags &^= CacheEntryEndpointAndNetworkPolicy

	// Iterate through the applied network Policies and recalculate the flags that the network policy applies to the
	// x.
	for polId := range x.AppliedPolicies.All() {
		policy, ok := c.GetFromXrefCache(polId).(*CacheEntryNetworkPolicy)

		if !ok {
			// The applied Policies should always be in the cache since deletion of the underlying policy should remove
			// the reference from the set.
			log.Errorf("%s applied policy is missing from cache: %s", podId, polId)
			continue
		}

		// The x flags are the combined set of flags from the applied Policies filtered by the allowed set of
		// flags for a Pod.
		x.Flags |= policy.Flags & CacheEntryEndpointAndNetworkPolicy

		// If all flags that the policy can set in the x are now set then exit without checking the other Policies.
		if x.Flags&CacheEntryEndpointAndNetworkPolicy == CacheEntryEndpointAndNetworkPolicy {
			break
		}
	}

	// Determine if envoy is enabled and set the flag appropriately.
	if x.getEnvoyEnabled(c) {
		x.Flags |= CacheEntryEnvoyEnabled
	} else {
		x.Flags &^= CacheEntryEnvoyEnabled
	}

	// Return the delta between the old and new flags as a set up UpdateType flags.
	changed := syncer.UpdateType(oldFlags ^ x.Flags)
	x.clog.Debugf("Recalculated, returning update: %d", changed)

	return changed
}

func (c *endpointHandler) queueEndpointsForRecalculation(update syncer.Update) {
	x := update.Resource.(*CacheEntryNetworkPolicy)
	for podId := range x.SelectedPods.All() {
		c.QueueUpdate(podId, nil, update.Type)
	}
	for hepId := range x.SelectedHostEndpoints.All() {
		c.QueueUpdate(hepId, nil, update.Type)
	}
}

// policyMatchStarted is called synchronously from the policy or pod resource update methods when a policy<->pod match
// has started. We update  our set of applied Policies and then queue for asynchronous recalculation - this ensures we
// wait until all related changes to have occurred further up the casading chain of events before we recalculate.
func (c *endpointHandler) policyMatchStarted(policyId, podId apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(podId).(*CacheEntryEndpoint)
	if !ok {
		// This is called synchronously from the resource update methods, so we don't expect the entries to have been
		// removed from the cache at this point.
		log.Errorf("Match started on pod, but pod is not in cache: %s matches %s", policyId, podId)
		return
	}
	x.clog.Debugf("Policy applied: %s", policyId)
	// Update the policy list in our pod data and queue a recalculation.
	x.AppliedPolicies.Add(policyId)
	c.QueueUpdate(podId, x, EventPolicyMatchStarted)
}

// policyMatchStopped is called synchronously from the policy or pod resource update methods when a policy<->pod match
// has stopped. We update  our set of applied Policies and then queue for asynchronous recalculation - this ensures we
// wait until all related changes to have occurred further up the chain of events before we recalculate.
func (c *endpointHandler) policyMatchStopped(policyId, podId apiv3.ResourceID) {
	x, ok := c.GetFromOurCache(podId).(*CacheEntryEndpoint)
	if !ok {
		// This is called synchronously from the resource update methods, so we don't expect the entries to have been
		// removed from the cache at this point.
		log.Errorf("Match stopped on pod, but pod is not in cache: %s no longer matches %s", policyId, podId)
		return
	}
	x.clog.Debugf("Policy no longer applied: %s", policyId)
	// Update the policy list in our pod data and queue a recalculation.
	x.AppliedPolicies.Discard(policyId)
	c.QueueUpdate(podId, x, EventPolicyMatchStopped)
}

func (c *endpointHandler) ipMatchStarted(ep, service apiv3.ResourceID, ip string, firstIP bool) {
	x, ok := c.GetFromOurCache(ep).(*CacheEntryEndpoint)
	if !ok {
		// This is called synchronously from the resource update methods, so we don't expect the entries to have been
		// removed from the cache at this point.
		log.Errorf("Match started on EP, but EP is not in cache: %s matches %s", ep, service)
		return
	}
	// This is the first IP to match, start tracking this service.
	if firstIP {
		x.clog.Debugf("Start tracking service: %s", service)
		x.Services.Add(service)
		c.QueueUpdate(ep, x, EventServiceAdded)
	}
}

func (c *endpointHandler) ipMatchStopped(ep, service apiv3.ResourceID, ip string, lastIP bool) {
	x, ok := c.GetFromOurCache(ep).(*CacheEntryEndpoint)
	if !ok {
		// This is called synchronously from the resource update methods, so we don't expect the entries to have been
		// removed from the cache at this point.
		log.Errorf("Match started on EP, but EP is not in cache: %s matches %s", ep, service)
		return
	}
	// This is the last IP to match, stop tracking this service.
	if lastIP {
		x.clog.Debugf("Stop tracking service: %s", service)
		x.Services.Discard(service)
		c.QueueUpdate(ep, x, EventServiceDeleted)
	}
}
