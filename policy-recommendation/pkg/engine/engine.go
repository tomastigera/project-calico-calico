// Copyright (c) 2024-2025 Tigera Inc. All rights reserved.

package engine

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	libcselector "github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	linseed "github.com/projectcalico/calico/linseed/pkg/client"
	calicores "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	"github.com/projectcalico/calico/policy-recommendation/pkg/flows"
	poltypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
	"github.com/projectcalico/calico/policy-recommendation/utils"
)

const (
	// DefaultStabilizationPeriod is the default stabilization period.
	defaultStabilizationPeriod = 5 * time.Minute

	// DefaultInterval is the default recommendation interval.
	defaultInterval = 10 * time.Minute

	// DefaultLookback is the default lookback period.
	defaultLookback = 24 * time.Hour

	// DefaultSelector is the default namespace selector.
	DefaultSelector = `(!projectcalico.org/name starts with "tigera-" && ` +
		`!projectcalico.org/name starts with "calico-" && ` +
		`!projectcalico.org/name starts with "kube-" && ` +
		`!projectcalico.org/name starts with "openshift-")`
)

// Clock is an interface added for testing purposes.
type Clock interface {
	NowRFC3339() string
}

type recommendationScope struct {
	// initialLookback is the flow log query lookback period for the first run of the engine.
	initialLookback time.Duration

	// interval is the engine run interval.
	interval time.Duration

	// minPollInterval is the minimum polling interval used by the engine to query for new
	// recommendations.
	minPollInterval time.Duration

	// stabilization is the period used to determine if a recommendation is stable.
	stabilization time.Duration

	// selector is the logical expression used to select namespaces for processing.
	selector libcselector.Selector

	// passIntraNamespaceTraffic is a flag to allow/pass intra-namespace traffic.
	passIntraNamespaceTraffic bool

	// Metadata
	uid types.UID

	// Logger
	clog *log.Entry
}

type RecommendationEngine interface {
	Run(stopChan chan struct{})
	AddNamespace(ns string)
	RemoveNamespace(ns string)
	GetNamespaces() set.Set[string]
	GetFilteredNamespaces() set.Set[string]
	ReceiveScopeUpdate(scope v3.PolicyRecommendationScope)
}

type recommendationEngine struct {
	// Cache for storing the recommendations (SNPs)
	cache rcache.ResourceCache

	// Namespaces are the namespaces that are present in the cluster.
	namespaces set.Set[string]

	// filterNamespaces is the set of namespaces that were filtered in by the selector.
	filteredNamespaces set.Set[string]

	// Channel for receiving PolicyRecommendationScope updates
	updateChannel chan v3.PolicyRecommendationScope

	// Context for the engine
	ctx context.Context

	// Calico client
	calico calicoclient.ProjectcalicoV3Interface

	// Linseed client
	linseedClient linseed.Client

	// Cluster name
	cluster string

	// Engine scope
	scope *recommendationScope

	// Clock for setting the latest update timestamp
	clock Clock

	// Cluster domain
	clusterDomain string

	// Query for querying flows logs
	query flows.PolicyRecommendationQuery

	// Lock
	mutex sync.Mutex

	// Logger
	clog *log.Entry
}

// NewRecommendationEngine returns a new RecommendationEngine struct.
func NewRecommendationEngine(
	ctx context.Context,
	clusterID string,
	calico calicoclient.ProjectcalicoV3Interface,
	linseedClient linseed.Client,
	query flows.PolicyRecommendationQuery,
	cache rcache.ResourceCache,
	scope *v3.PolicyRecommendationScope,
	minPollInterval metav1.Duration,
	clock Clock,
) RecommendationEngine {
	logEntry := log.WithField("clusterID", utils.GetLogClusterID(clusterID))

	clusterDomain, err := utils.GetClusterDomain(utils.DefaultResolveConfPath)
	if err != nil {
		clusterDomain = utils.DefaultClusterDomain
		log.WithError(err).Warningf("Defaulting cluster domain to %s", clusterDomain)
	}

	// Create a new scope with the default values.
	sc := newRecommendationScope(minPollInterval, logEntry)
	sc.updateScope(*scope)

	return &recommendationEngine{
		ctx:                ctx,
		calico:             calico,
		linseedClient:      linseedClient,
		cache:              cache,
		filteredNamespaces: set.New[string](),
		namespaces:         set.New[string](),
		cluster:            clusterID,
		scope:              sc,
		updateChannel:      make(chan v3.PolicyRecommendationScope),
		clock:              clock,
		clusterDomain:      clusterDomain,
		query:              query,
		mutex:              sync.Mutex{},
		clog:               logEntry,
	}
}

// Run starts the engine. It runs the engine loop and processes the recommendations. It also updates
// the engine scope with the latest PolicyRecommendationScopeSpec. It stops the engine when the
// stopChan is closed.
func (e *recommendationEngine) Run(stopChan chan struct{}) {
	interval := defaultInterval
	if e.scope != nil {
		if e.scope.interval >= e.scope.minPollInterval {
			interval = e.scope.interval
		} else {
			e.clog.Warnf("Invalid interval: %s, the interval must be greater than 30 seconds, using default interval: %s", e.scope.interval.String(), interval.String())
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	e.clog.Debugf("Starting new ticker with interval: %s", interval.String())

	for {
		select {
		case update, ok := <-e.updateChannel:
			if !ok {
				continue // Channel closed, exit the loop
			}
			e.clog.Debugf("[Consumer] Received scope update: %+v", update)

			e.mutex.Lock()

			oldInterval := e.scope.interval
			oldSelector := e.scope.selector.String()
			// Update the engine scope with the new PolicyRecommendationScopeSpec.
			e.scope.updateScope(update)

			if oldInterval != e.scope.interval {
				// The interval has changed, update the ticker with the new interval.
				// Stop the previous ticker and start a new one with the updated interval.
				ticker.Stop()
				ticker.C = time.NewTicker(e.scope.interval).C
				e.clog.Debugf("Updated ticker with new interval: %s", e.scope.interval.String())
			}

			if oldSelector != e.scope.selector.String() {
				// The namespace selector has changed, update the filtered namespaces.
				e.filterNamespaces(e.scope.selector.String())
			}
			e.mutex.Unlock()
		case <-ticker.C:
			e.clog.Debug("Reconciliation interval is up, running engine")

			if e.cache == nil {
				e.clog.Warn("Cache is not set, avoiding engine run")
				continue
			}
			if e.scope == nil {
				e.clog.Warn("Scope is not set, avoiding engine run")
				continue
			}

			e.clog.Debugf("Iterating through namespaces, using selector: %s", e.scope.selector.String())
			e.filteredNamespaces.Iter(func(namespace string) error {
				rec := e.getRecommendation(namespace)
				if rec != nil && e.update(rec) {
					// The recommendation contains new rules, or status metadata has been updated so add to
					// cache for syncing. This will trigger an update in the datastore.
					e.cache.Set(namespace, *rec)
					e.clog.WithField("namespace", namespace).Debug("Updated cache item")
				}

				return nil
			})
		case <-stopChan:
			e.clog.Info("Received stop signal, stopping engine")
			return
		}
	}
}

// AddNamespace adds the namespace for tracking, and if the filter is true, adds it to the
// filtered namespaces.
func (e *recommendationEngine) AddNamespace(ns string) {
	if !e.namespaces.Contains(ns) {
		e.namespaces.Add(ns)
		e.clog.WithField("namespace", ns).Debug("Namespace not found in namespaces set")
	}

	if !e.filteredNamespaces.Contains(ns) && (e.scope.selector.String() == "" || e.scope.selector.Evaluate(map[string]string{v3.LabelName: ns})) {
		e.filteredNamespaces.Add(ns)
		e.clog.WithField("namespace", ns).Debug("Added namespace to filtered namespaces")
	}
}

func (e *recommendationEngine) ReceiveScopeUpdate(scope v3.PolicyRecommendationScope) {
	e.updateChannel <- scope
}

// GetScope returns the engine scope.
func (e *recommendationEngine) GetScope() *recommendationScope {
	return e.scope
}

// GetNamespaces returns the set of namespaces.
func (e *recommendationEngine) GetNamespaces() set.Set[string] {
	return e.namespaces
}

// GetFilteredNamespaces returns the set of filtered namespaces.
func (e *recommendationEngine) GetFilteredNamespaces() set.Set[string] {
	return e.filteredNamespaces
}

// RemoveNamespace removes the namespace from the tracked namespace, the filtered namespaces and the
// cache.
func (e *recommendationEngine) RemoveNamespace(ns string) {
	if e.namespaces.Contains(ns) {
		e.namespaces.Discard(ns)
	}
	if e.filteredNamespaces.Contains(ns) {
		e.filteredNamespaces.Discard(ns)
	}
	if _, ok := e.cache.Get(ns); ok {
		e.cache.Delete(ns)
	}

	// Remove every rule referencing the deleted namespace from the cache items.
	for _, key := range e.cache.ListKeys() {
		if val, ok := e.cache.Get(key); ok {
			snp := val.(v3.StagedNetworkPolicy)
			e.removeRulesReferencingDeletedNamespace(&snp, ns)
			e.cache.Set(key, snp)
		}
	}
}

// filterNamespaces filters the namespaces based on the selector.
func (e *recommendationEngine) filterNamespaces(selector string) {
	parsedSelector, _ := libcselector.Parse(selector)
	e.filteredNamespaces = set.New[string]() // Reset the filtered namespaces set.

	e.namespaces.Iter(func(ns string) error {
		_, exists := e.cache.Get(ns)
		if parsedSelector.String() == "" || parsedSelector.Evaluate(map[string]string{v3.LabelName: ns}) {
			e.filteredNamespaces.Add(ns)
		} else if exists {
			// The namespace is not selected by the new selector, remove it from the
			// cache. This will subsequently remove it from the datastore.
			e.cache.Delete(ns)
			e.clog.WithField("namespace", ns).Info("Deleted namespace from cache")
		}
		return nil
	})
}

// getRecommendation returns the recommendation for the namespace. If the recommendation does not
// exist in the cache, it will create a new one.
func (e *recommendationEngine) getRecommendation(ns string) *v3.StagedNetworkPolicy {
	if item, found := e.cache.Get(ns); found {
		if recommendation, ok := item.(v3.StagedNetworkPolicy); ok {
			return &recommendation
		}
		e.clog.Warnf("unexpected item in cache: %+v", item)
		return nil
	}

	// Create a new recommendation for this namespace. The recommendation is a StagedNetworkPolicy.
	// This will only be used if there are new rules to add. Otherwise, the recommendation will be
	// discarded.
	recommendation := calicores.NewStagedNetworkPolicy(
		utils.GenerateRecommendationName(poltypes.PolicyRecommendationTierName, ns, utils.SuffixGenerator),
		ns,
		poltypes.PolicyRecommendationTierName,
		e.scope.uid,
	)

	return recommendation
}

// update processes the flows logs into new rules and adds them to the recommendation. Returns true
// if there is an update to recommendation (SNP).
func (e *recommendationEngine) update(snp *v3.StagedNetworkPolicy) bool {
	if snp == nil {
		e.clog.Debug("Empty staged network policy")
		return false
	}
	if snp.Spec.StagedAction != v3.StagedActionLearn {
		// Skip this recommendation, the engine only processes "Learn" recommendations.
		e.clog.WithField("recommendation", snp.Name).Debug("Ignoring recommendation, staged action is not learning")
		return false
	}
	// Query flows logs for the namespace
	params := flows.NewRecommendationFlowLogQueryParams(e.getLookback(*snp), snp.Namespace, e.cluster)
	flows, err := e.query.QueryFlows(params)
	if err != nil {
		e.clog.WithError(err).WithField("params", params).Warning("Failed to query flows logs")
		return false
	}
	// New flow logs were found, process and sort them into the existing rules in the policy.
	// If the rules have changed, update the recommendation. If the rules have not changed, then there
	// still may be a status update to process.
	rec := newRecommendation(
		e.cluster,
		snp.Namespace,
		e.scope.interval,
		e.scope.stabilization,
		e.scope.passIntraNamespaceTraffic,
		utils.GetServiceNameSuffix(e.clusterDomain),
		snp,
		e.clock,
	)

	if len(flows) == 0 {
		e.clog.WithField("params", params).Debug("No matching flows logs found")
		// No matching flows found, however we may still want to update the status
		return rec.updateStatus(snp)
	}

	// Return true if the recommendation has been updated, by adding new rules or updating the status.
	return rec.update(flows, snp)
}

// getLookback returns the InitialLookback period if the policy is new and has not previously
// been updated, otherwise use twice the engine-run interval (Default: 2.5min).
func (e *recommendationEngine) getLookback(snp v3.StagedNetworkPolicy) time.Duration {
	initialLookback := defaultLookback
	interval := defaultInterval
	if e.scope != nil {
		if e.scope.initialLookback != 0 {
			initialLookback = e.scope.initialLookback
		}
		if e.scope.interval != 0 {
			interval = e.scope.interval
		}
	}

	_, ok := snp.Annotations[calicores.LastUpdatedKey]
	if !ok {
		// First time run will use the initial lookback
		return initialLookback
	}
	// Twice the engine-run interval
	lookback := interval * 2

	return lookback
}

// removeRulesReferencingDeletedNamespace removes every rule from the staged network policy
// referencing the passed in namespace.
func (e *recommendationEngine) removeRulesReferencingDeletedNamespace(snp *v3.StagedNetworkPolicy, namespace string) {
	e.clog.Debugf("Remove all references to namespace: %s, from staged network policy: %s", namespace, snp.Name)
	ingress := []v3.Rule{}
	for i, rule := range snp.Spec.Ingress {
		if rule.Source.NamespaceSelector != namespace {
			ingress = append(ingress, snp.Spec.Ingress[i])
		}
	}
	snp.Spec.Ingress = ingress

	egress := []v3.Rule{}
	for i, rule := range snp.Spec.Egress {
		if rule.Destination.NamespaceSelector != namespace {
			egress = append(egress, snp.Spec.Egress[i])
		}
	}
	snp.Spec.Egress = egress
}

// recommendationScope

func newRecommendationScope(minPollInterval metav1.Duration, lg *log.Entry) *recommendationScope {
	parsedSelector, _ := libcselector.Parse(DefaultSelector)
	return &recommendationScope{
		initialLookback:           defaultLookback,
		interval:                  defaultInterval,
		minPollInterval:           minPollInterval.Duration,
		stabilization:             defaultStabilizationPeriod,
		selector:                  parsedSelector,
		passIntraNamespaceTraffic: false,
		uid:                       "",
		clog:                      lg,
	}
}

// updateScope updates the engine scope with the new PolicyRecommendationScopeSpec.
func (sc *recommendationScope) updateScope(new v3.PolicyRecommendationScope) {
	if new.Spec.Interval != nil && sc.interval != new.Spec.Interval.Duration {
		if new.Spec.Interval.Duration < sc.minPollInterval {
			sc.clog.Warnf("Invalid interval: %s, the interval must be greater than 30 seconds", new.Spec.Interval.Duration.String())
		} else {
			sc.interval = new.Spec.Interval.Duration
			sc.clog.Infof("[Consumer] Setting new interval to: %s", sc.interval.String())
		}
	}

	if new.Spec.InitialLookback != nil && sc.initialLookback != new.Spec.InitialLookback.Duration {
		if new.Spec.InitialLookback.Duration < sc.interval {
			sc.clog.Warnf("Invalid initial lookback: %s, the initial lookback must be greater than the interval: %s", new.Spec.InitialLookback.Duration.String(), sc.interval.String())
		} else {
			sc.initialLookback = new.Spec.InitialLookback.Duration
			sc.clog.Infof("[Consumer] Setting new initial lookback to: %s", sc.initialLookback.String())
		}
	}

	if new.Spec.StabilizationPeriod != nil && sc.stabilization != new.Spec.StabilizationPeriod.Duration {
		if new.Spec.StabilizationPeriod.Duration < sc.interval {
			sc.clog.Warnf("Invalid stabilization period: %s, the stabilization period must be greater than the interval: %s", new.Spec.StabilizationPeriod.Duration.String(), sc.interval.String())
		} else {
			sc.stabilization = new.Spec.StabilizationPeriod.Duration
			sc.clog.Infof("[Consumer] Setting new stabilization to: %s", sc.stabilization.String())
		}
	}

	if sc.passIntraNamespaceTraffic != new.Spec.NamespaceSpec.IntraNamespacePassThroughTraffic {
		sc.passIntraNamespaceTraffic = new.Spec.NamespaceSpec.IntraNamespacePassThroughTraffic
		sc.clog.Infof("[Consumer] Setting passIntraNamespaceTraffic to: %t", sc.passIntraNamespaceTraffic)
	}

	parsedSelector, err := libcselector.Parse(new.Spec.NamespaceSpec.Selector)
	if err != nil {
		sc.clog.WithError(err).Warningf("failed to parse selector: %s, setting to default", new.Spec.NamespaceSpec.Selector)
		parsedSelector, _ = libcselector.Parse(DefaultSelector)
	}
	if sc.selector == nil || sc.selector.String() != parsedSelector.String() {
		sc.selector = parsedSelector
		sc.clog.Infof("[Consumer] Setting new namespace selector to: %s", parsedSelector.String())
	}

	if new.UID != sc.uid {
		sc.uid = new.UID
		sc.clog.Infof("[Consumer] Setting recommendation owner UID to: %s", sc.uid)
	}
}

// Defined for testing purposes.

// GetInterval returns the engine interval.
func (s *recommendationScope) GetInterval() time.Duration {
	return s.interval
}

// GetInitialLookback returns the engine initial lookback.
func (s *recommendationScope) GetInitialLookback() time.Duration {
	return s.initialLookback
}

// GetStabilization returns the engine stabilization period.
func (s *recommendationScope) GetStabilization() time.Duration {
	return s.stabilization
}

// GetSelector returns the engine namespace selector.
func (s *recommendationScope) GetSelector() libcselector.Selector {
	return s.selector
}

// GetPassIntraNamespaceTraffic returns the engine passIntraNamespaceTraffic flag.
func (s *recommendationScope) GetPassIntraNamespaceTraffic() bool {
	return s.passIntraNamespaceTraffic
}
