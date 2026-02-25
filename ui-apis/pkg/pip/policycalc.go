package pip

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/projectcalico/calico/compliance/pkg/api"
	compcfg "github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/replay"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/policycalc"
)

var (
	// These are the resource types that we need to query from the k8s API to populate our internal cache.
	requiredPolicyTypes = []metav1.TypeMeta{
		resources.TypeCalicoStagedKubernetesNetworkPolicies,
		resources.TypeCalicoStagedGlobalNetworkPolicies,
		resources.TypeCalicoStagedNetworkPolicies,
		resources.TypeCalicoTiers,
		resources.TypeCalicoNetworkPolicies,
		resources.TypeCalicoGlobalNetworkPolicies,
		resources.TypeK8sNetworkPolicies,
		resources.TypeK8sNamespaces,
		resources.TypeK8sServiceAccounts,
	}
	// These are the resource types that we need to query from the k8s API to populate our internal cache.
	requiredEndpointTypes = []metav1.TypeMeta{
		resources.TypeCalicoNetworkSets,
		resources.TypeCalicoGlobalNetworkSets,
		resources.TypeCalicoHostEndpoints,
		resources.TypeK8sPods,
	}
)

// GetPolicyCalculator loads the initial configuration and updated configuration and returns a primed PolicyCalculator
// used for checking flow impact.
func (s *pip) GetPolicyCalculator(ctx context.Context, params *PolicyImpactParams) (policycalc.PolicyCalculator, error) {
	// Create a new x-ref cache. Use a blank compliance config for the config settings since the XrefCache currently
	// requires it but doesn't use any fields except the istio config (which we're not concerned with in the pip use
	// case).
	//
	// We just use the xref cache to determine the ordered set of tiers and policies before and after the updates. Set
	// in-sync immediately since we aren't interested in callbacks.
	xc := xrefcache.NewXrefCache(&compcfg.Config{IncludeStagedNetworkPolicies: true}, func() {})
	xc.OnStatusUpdate(syncer.NewStatusUpdateInSync())

	// Populate the endpoint cache. Run this on a go-routine so we can double up with the other queries.
	// Depending on configuration, the endpoint cache may be populated from historical data (snapshots and audit logs),
	// and/or from current endpoint configuration. The default is neither - we only use flow log data for our
	// calculations.
	ec := policycalc.NewEndpointCache()
	wgEps := sync.WaitGroup{}
	wgEps.Go(func() {
		if s.cfg.AugmentFlowLogDataWithAuditLogData {
			log.Debug("Augmenting flow log data with audit log data")
			s.syncFromArchive(ctx, params, ec)
		}
		if s.cfg.AugmentFlowLogDataWithCurrentConfiguration {
			log.Debug("Augmenting flow log data with current datastore configuration")
			_ = s.syncFromDatastore(ctx, params.ClusterName, requiredEndpointTypes, ec)
		}
	})

	// Load the initial set of policy. If this errors we cannot continue.
	if err := s.syncFromDatastore(ctx, params.ClusterName, requiredPolicyTypes, xc); err != nil {
		return nil, err
	}

	// Extract the current set of config from the xrefcache.
	resourceDataBefore := resourceDataFromXrefCache(xc)

	// Apply the preview changes to the xref cache. This also constructs the set of impacted resources for use by the
	// policy calculator.
	impacted, err := ApplyPIPPolicyChanges(xc, params.ResourceActions)
	if err != nil {
		return nil, err
	}

	// Extract the updated set of config from the xrefcache.
	resourceDataAfter := resourceDataFromXrefCache(xc)

	// Wait for the archived endpoint query to complete. We don't track if the endpoint cache population errors since
	// we can still do a PIP query without it, however, chance of indeterminate calculations will be higher.
	wgEps.Wait()

	// Create the policy calculator.
	calc := policycalc.NewPolicyCalculator(s.cfg, ec, resourceDataBefore, resourceDataAfter, impacted)

	return calc, nil
}

// syncFromArchive will load archived configuration and invoke the syncer callbacks.
func (s *pip) syncFromArchive(cxt context.Context, params *PolicyImpactParams, cb syncer.SyncerCallbacks) {
	// If we could not determine the time interval, then we can't populate the cache from archived data.
	if params.FromTime == nil || params.ToTime == nil {
		log.Debug("No From/To time available, so cannot load archived data")
		return
	}

	// Create a store to use.
	store := api.NewComplianceStore(s.lsclient, params.ClusterName)

	// Populate the cache from the replayer.
	r := replay.New(
		*params.FromTime,
		*params.ToTime,
		store,
		store,
		cb,
	)
	r.Start(cxt)
}

// syncFromDatastore will load the current set of configuration from the datastore and invoke the syncer callbacks.
// This is used to populate both the xrefcache and the EndpointCache which both implement the syncer callbacks
// interface.
func (s *pip) syncFromDatastore(ctx context.Context, clusterName string, types []metav1.TypeMeta, cb syncer.SyncerCallbacks) error {
	wg := sync.WaitGroup{}
	lock := sync.Mutex{}
	errs := make(chan error, len(types))
	defer close(errs)

	for _, t := range types {
		// If we are running in an FV framework then skip config load of Calico resources which require an AAPIS.
		if s.cfg.RunningFunctionalVerification && t.APIVersion == v3.GroupVersionCurrent {
			log.Warningf("Running functional verification - skipping config load from datastore for %s", t.Kind)
			return nil
		}

		wg.Add(1)
		go func(t metav1.TypeMeta) {
			defer wg.Done()

			// List current resource configuration for this type.
			l, err := s.listSrc.RetrieveList(clusterName, t)
			if err != nil {
				errs <- err
				return
			}

			// Invoke the syncer callbacks for each item in the list. We need to lock around the callbacks because the
			// syncer interfaces are assumed not to be go-routine safe.
			lock.Lock()
			err = meta.EachListItem(l.ResourceList, func(obj runtime.Object) error {
				res := obj.(resources.Resource)
				cb.OnUpdates([]syncer.Update{{
					Type:       syncer.UpdateTypeSet,
					Resource:   res,
					ResourceID: resources.GetResourceID(res),
				}})
				return nil
			})
			lock.Unlock()

			if err != nil {
				errs <- err
				return
			}
		}(t)
	}
	wg.Wait()

	// Return the first error if there is one. Use non-blocking version of the channel operator.
	select {
	case err := <-errs:
		log.WithError(err).Warning("Hit error loading configuration from datastore")
		cb.OnStatusUpdate(syncer.StatusUpdate{
			Type:  syncer.StatusTypeFailed,
			Error: err,
		})
		return err
	default:
		log.Info("Loaded configuration from datastore")
		return nil
	}
}

// resourceDataFromXrefCache creates the policy configuration from the data stored in the xrefcache.
func resourceDataFromXrefCache(xc xrefcache.XrefCache) *policycalc.ResourceData {
	// Create an empty config.
	rd := &policycalc.ResourceData{}

	// Grab the ordered tiers and policies from the xrefcache and convert to the required type.
	xrefTiers := xc.GetOrderedTiersAndPolicies()
	rd.Tiers = make(policycalc.Tiers, len(xrefTiers))
	for i := range xrefTiers {
		for _, t := range xrefTiers[i].OrderedPolicies {
			rd.Tiers[i] = append(rd.Tiers[i], policycalc.Policy{
				CalicoV3Policy: t.GetCalicoV3(),
				ResourceID:     resources.GetResourceID(t.GetPrimary()),
				Staged:         t.IsStaged(),
			})
		}
	}

	// Grab the namespaces and the service accounts.
	_ = xc.EachCacheEntry(resources.TypeK8sNamespaces, func(ce xrefcache.CacheEntry) error {
		rd.Namespaces = append(rd.Namespaces, ce.GetPrimary().(*corev1.Namespace))
		return nil
	})
	_ = xc.EachCacheEntry(resources.TypeK8sServiceAccounts, func(ce xrefcache.CacheEntry) error {
		rd.ServiceAccounts = append(rd.ServiceAccounts, ce.GetPrimary().(*corev1.ServiceAccount))
		return nil
	})

	return rd
}

// ApplyPolicyChanges applies the supplied resource updates on top of the loaded configuration in the xrefcache.
func ApplyPIPPolicyChanges(xc xrefcache.XrefCache, rs []ResourceChange) (policycalc.ImpactedResources, error) {
	impacted := make(policycalc.ImpactedResources)
	var err error

	for _, r := range rs {
		// Extract resource data.
		resource := r.Resource
		if resource == nil {
			continue
		}
		action := r.Action
		id := resources.GetResourceID(r.Resource)
		log.Debugf("Applying resource update: %s", id)

		// If this is a staged resource set then determine the corresponding "enforced" resource and the staged action.
		// Depending on both the preview action and the staged action we may need to do additional modifications to the
		// resource data.
		var enforced resources.Resource
		var staged bool
		var stagedAction v3.StagedAction
		switch np := resource.(type) {
		case *v3.StagedNetworkPolicy:
			log.Debug("Enforcing StagedNetworkPolicy")
			stagedAction, enforced = v3.ConvertStagedPolicyToEnforced(np)
			staged = true
		case *v3.StagedGlobalNetworkPolicy:
			log.Debug("Enforcing StagedGlobalNetworkPolicy")
			stagedAction, enforced = v3.ConvertStagedGlobalPolicyToEnforced(np)
			staged = true
		case *v3.StagedKubernetesNetworkPolicy:
			log.Debug("Enforcing StagedKubernetesNetworkPolicy")
			stagedAction, enforced = v3.ConvertStagedKubernetesPolicyToK8SEnforced(np)
			staged = true
		}

		// Locate the resource in the xrefcache, if it exists, and determine if it has been modified. If the resource is
		// not modified then we can use measured flow log data to augment the calculation.
		modified := true
		existing := xc.Get(id)
		if existing != nil {
			log.Debug("Check if resource is modified")
			modified, err = IsResourceModifiedForPIP(existing.GetPrimary(), resource)
			if err != nil {
				return nil, err
			}
		}

		// Apply the update to the xrefcache, and update our set of previewed resources.
		switch action {
		case "update", "create":
			log.Debugf("Update or create resource: id=%s; modified=%v", id, modified)
			// If this is a staged policy delete:
			// - the xrefcache will not add the resource and we do not need to explicitly consider the staged resource
			//   in the calculation
			// - the enforced resource will be deleted in the processing below.
			// Otherwise:
			// -after applying the update we should have the entry in the cache and the entry should validate correctly
			//   for both the actual resource and the Calico v3 representation.
			if staged && stagedAction == v3.StagedActionDelete {
				log.Infof("Staged delete: %v", resource)
			} else {
				// This resource is updated or created so update our impact data and the xrefcache.
				log.Debug("Updating cache")
				impacted.Add(id, policycalc.Impact{Modified: modified, Deleted: false})
				xc.OnUpdates([]syncer.Update{{
					Type:       syncer.UpdateTypeSet,
					Resource:   resource,
					ResourceID: id,
				}})

				if xcres := xc.Get(id); xcres == nil {
					// The xrefcache will delete resources that could not be converted (which may be the case with
					// incorrect data). Check the resource is present, and if not, error.
					log.Infof("Invalid resource data: %v", resource)
					return nil, fmt.Errorf("invalid resource in preview request: %s", id.String())
				} else if v3res := xcres.GetCalicoV3(); v3res != nil {
					// Validate the calico representation of the resource.
					log.Debug("Validating Calico v3 resource")
					if err := validator.Validate(v3res); err != nil {
						log.WithError(err).Info("previous resource failed validation")
						return nil, err
					}
				}
			}

			// If this is a update or create of a staged resource then we enforce the staged policy which effectively
			// overrides the corresponding enforced resource. In this case delete the enforced resource from the cache
			// so that it no longer participates in the calculation. Note that we do this for staged deletes as
			// well.
			if staged {
				enforcedId := resources.GetResourceID(enforced)
				log.Debugf("Delete enforced resource: %s", enforcedId)
				xc.OnUpdates([]syncer.Update{{
					Type:       syncer.UpdateTypeDeleted,
					Resource:   enforced,
					ResourceID: enforcedId,
				}})
				impacted.Add(enforcedId, policycalc.Impact{Modified: false, Deleted: true})
			}

		case "delete":
			// We are previewing deletion of a resource.  Simply delete the resource from the xrefcache so it no longer
			// participates in the calculation. If this is a deletion of a staged delete then this is effectivly a
			// no-op, but no need to handle this explicitly since the staged resource will no exists in the before or
			// after data.
			log.Debugf("Delete resource: id=%s", id)
			impacted.Add(id, policycalc.Impact{Modified: false, Deleted: true})
			xc.OnUpdates([]syncer.Update{{
				Type:       syncer.UpdateTypeDeleted,
				Resource:   resource,
				ResourceID: id,
			}})
		default:
			log.Warningf("Invalid preview action: %s", action)
			return nil, fmt.Errorf("invalid action in preview request: %s", action)
		}
	}

	return impacted, nil
}

// IsResourceModifiedForPIP compares the before and after resource to determine if the settings have been modified in a
// way that will impact the policy calculation of this specific resource. If modified then we cannot use historical data
// in the flow log to augment the pip calculation.
//
// Note that for policies, we don't care about order changes because the order doesn't impact whether or not the policy
// itself will match a flow. This is a minor finesse for the situation where we decrease the order of a policy but don't
// change anything else - in this case we can still use the match data in the flow log for this policy (if we have any)
// to augment the calculation.
func IsResourceModifiedForPIP(r1, r2 resources.Resource) (bool, error) {
	if r1 == nil || r2 == nil {
		// A resource is not modified if either is nil.  Created or deleted, but not modified (in the sense that we
		// mean.
		log.Debug("At least one resource is nil - not modified")
		return false, nil
	}

	if reflect.TypeOf(r1) != reflect.TypeOf(r2) {
		// Resource types do not match.  This indicates a bug rather than an abuse of the API, but return an error
		// up the stack for debugging purposes.
		log.Errorf("Resource types do not match: %v != %v", reflect.TypeOf(r1), reflect.TypeOf(r2))
		return false, fmt.Errorf("resource type before and after do not match: %v != %v", reflect.TypeOf(r1), reflect.TypeOf(r2))
	}

	// Copy the resources since we modify them to do the comparison.
	r1 = r1.DeepCopyObject().(resources.Resource)
	r2 = r2.DeepCopyObject().(resources.Resource)
	var mod bool

	switch rc1 := r1.(type) {
	case *v3.NetworkPolicy:
		log.Debug("Compare v3.NetworkPolicy")
		rc2 := r2.(*v3.NetworkPolicy)

		// For the purposes of PIP we don't care if the order changed since that doesn't impact the policy rule matches,
		// so nil out the order before comparing.  We only need to compare the spec for policies.
		rc1.Spec.Order = nil
		rc2.Spec.Order = nil
		mod = !reflect.DeepEqual(rc1.Spec, rc2.Spec)
	case *v3.StagedNetworkPolicy:
		log.Debug("Compare v3.StagedNetworkPolicy")
		rc2 := r2.(*v3.StagedNetworkPolicy)

		// For the purposes of PIP we don't care if the order changed since that doesn't impact the policy rule matches,
		// so nil out the order.
		rc1.Spec.Order = nil
		rc2.Spec.Order = nil
		mod = !reflect.DeepEqual(rc1.Spec, rc2.Spec)
	case *v3.GlobalNetworkPolicy:
		log.Debug("Compare v3.GlobalNetworkPolicy")
		rc2 := r2.(*v3.GlobalNetworkPolicy)

		// For the purposes of PIP we don't care if the order changed since that doesn't impact the policy rule matches,
		// so nil out the order before comparing.  We only need to compare the spec for policies.
		rc1.Spec.Order = nil
		rc2.Spec.Order = nil
		mod = !reflect.DeepEqual(rc1.Spec, rc2.Spec)
	case *v3.StagedGlobalNetworkPolicy:
		log.Debug("Compare v3.StagedGlobalNetworkPolicy")
		rc2 := r2.(*v3.StagedGlobalNetworkPolicy)

		// For the purposes of PIP we don't care if the order changed since that doesn't impact the policy rule matches,
		// so nil out the order before comparing.  We only need to compare the spec for policies.
		rc1.Spec.Order = nil
		rc2.Spec.Order = nil
		mod = !reflect.DeepEqual(rc1.Spec, rc2.Spec)
	case *networkingv1.NetworkPolicy:
		log.Debug("Compare networkingv1.NetworkPolicy")
		rc2 := r2.(*networkingv1.NetworkPolicy)

		// We only need to compare the spec for policies. Kubernetes policies do not have an order.
		mod = !reflect.DeepEqual(rc1.Spec, rc2.Spec)
	case *v3.StagedKubernetesNetworkPolicy:
		log.Debug("Compare v3.StagedKubernetesNetworkPolicy")

		// We only need to compare the spec for policies. Kubernetes policies do not have an order.
		rc2 := r2.(*v3.StagedKubernetesNetworkPolicy)
		mod = !reflect.DeepEqual(rc1.Spec, rc2.Spec)
	default:
		log.Infof("Unhandled resource type for policy impact preview: %s", resources.GetResourceID(r1))
		return false, fmt.Errorf("resource type not valid for policy preview: %v", resources.GetResourceID(r1))
	}

	// Not a supported resource update type. Assume it changed.
	log.Debugf("Resource modified: %v", mod)
	return mod, nil
}
