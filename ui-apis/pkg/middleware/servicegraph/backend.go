// Copyright (c) 2021,2023 Tigera, Inc. All rights reserved.

package servicegraph

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	lsclient "github.com/projectcalico/calico/linseed/pkg/client"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/k8s"
	v1 "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

// Sanity check the realServiceGraphBackend satisfies the ServiceGraphBackend interface.
var _ ServiceGraphBackend = &realServiceGraphBackend{}

type ServiceGraphBackend interface {
	// These methods access data for the cache and therefore use an application context rather than the user request
	// context.
	GetFlowConfig(ctx context.Context, cluster string) (*FlowConfig, error)
	GetL3FlowData(ctx context.Context, cluster string, namespaces string, tr lmav1.TimeRange, fc *FlowConfig) ([]L3Flow, error)
	GetL7FlowData(ctx context.Context, cluster string, tr lmav1.TimeRange) ([]L7Flow, error)
	GetDNSData(ctx context.Context, cluster string, tr lmav1.TimeRange) ([]DNSLog, error)
	GetEvents(ctx context.Context, cluster string, tr lmav1.TimeRange) ([]Event, error)
	GetServiceLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error)
	GetReplicaSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error)
	GetStatefulSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error)
	GetDaemonSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error)
	GetPodsLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error)

	// These methods access data for a specific user request and therefore use the users request context.
	NewRBACFilter(ctx context.Context, rd *RequestData) (RBACFilter, error)
	NewNameHelper(ctx context.Context, rd *RequestData) (NameHelper, error)
}

type realServiceGraphBackend struct {
	authz            auth.RBACAuthorizer
	reviewer         authzreview.Reviewer
	clientSetFactory k8s.ClientSetFactory
	config           *Config
	linseed          lsclient.Client
}

func (r *realServiceGraphBackend) GetPodsLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, err
	}

	pods := make(map[v1.NamespacedName]LabelSelectors)
	podsList, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to list pods")
	}
	for _, pod := range podsList.Items {
		if len(pod.OwnerReferences) == 0 {
			key := v1.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}
			pods[key] = AppendLabels(pods[key], pod.Labels)
		}
	}

	return pods, nil
}

func (r *realServiceGraphBackend) GetStatefulSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, err
	}

	statefulSets := make(map[v1.NamespacedName]LabelSelectors)
	stsList, err := cs.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to list statefulSets")
	}
	for _, sts := range stsList.Items {
		key := v1.NamespacedName{Name: sts.Name, Namespace: sts.Namespace}
		statefulSets[key] = AppendLabelSelectors(statefulSets[key], sts.Spec.Selector)
	}

	return statefulSets, nil
}

func (r *realServiceGraphBackend) GetDaemonSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, err
	}

	daemonSets := make(map[v1.NamespacedName]LabelSelectors)
	dsList, err := cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to list daemonSets")
	}
	for _, ds := range dsList.Items {
		key := v1.NamespacedName{Name: ds.Name, Namespace: ds.Namespace}
		daemonSets[key] = AppendLabelSelectors(daemonSets[key], ds.Spec.Selector)
	}

	return daemonSets, nil
}

func (r *realServiceGraphBackend) GetReplicaSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, err
	}

	replicaSets := make(map[v1.NamespacedName]LabelSelectors)
	rsList, err := cs.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to list replicaSets")
	}
	for _, rs := range rsList.Items {
		key := v1.NamespacedName{Name: rs.Name, Namespace: rs.Namespace}
		replicaSets[key] = AppendLabelSelectors(replicaSets[key], rs.Spec.Selector)
	}

	return replicaSets, nil
}

func (r *realServiceGraphBackend) GetServiceLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, err
	}

	services := make(map[v1.NamespacedName]LabelSelectors)
	svList, err := cs.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		log.WithError(err).Errorf("Failed to list services")
	}
	for _, sv := range svList.Items {
		key := v1.NamespacedName{Name: sv.Name, Namespace: sv.Namespace}
		services[key] = AppendLabels(services[key], sv.Spec.Selector)
	}

	return services, nil
}

func (r *realServiceGraphBackend) GetFlowConfig(ctx context.Context, cluster string) (*FlowConfig, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, err
	}
	return GetFlowConfig(ctx, cs)
}

func (r *realServiceGraphBackend) GetL3FlowData(ctx context.Context, cluster string, namespace string, tr lmav1.TimeRange, fc *FlowConfig) ([]L3Flow, error) {
	return GetL3FlowData(ctx, r.linseed, cluster, namespace, tr, fc, r.config)
}

func (r *realServiceGraphBackend) GetDNSData(
	ctx context.Context, cluster string, tr lmav1.TimeRange,
) ([]DNSLog, error) {
	return GetDNSClientData(ctx, r.linseed, cluster, tr, r.config)
}

func (r *realServiceGraphBackend) GetL7FlowData(
	ctx context.Context, cluster string, tr lmav1.TimeRange,
) ([]L7Flow, error) {
	return GetL7FlowData(ctx, r.linseed, cluster, tr, r.config)
}

func (r *realServiceGraphBackend) GetEvents(
	ctx context.Context, cluster string, tr lmav1.TimeRange,
) ([]Event, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(cluster)
	if err != nil {
		return nil, err
	}
	return GetEvents(ctx, r.linseed, cs, cluster, tr, r.config)
}

func (r *realServiceGraphBackend) NewRBACFilter(ctx context.Context, rd *RequestData) (RBACFilter, error) {
	if !r.config.FineGrainedRBAC {
		return NewAllowAllRBACFilter(), nil
	}
	return NewRBACFilter(ctx, r.authz, r.reviewer, rd.ServiceGraphRequest.Cluster)
}

func (r *realServiceGraphBackend) NewNameHelper(ctx context.Context, rd *RequestData) (NameHelper, error) {
	cs, err := r.clientSetFactory.NewClientSetForApplication(rd.ServiceGraphRequest.Cluster)
	if err != nil {
		return nil, err
	}
	return NewNameHelper(ctx, cs, rd.ServiceGraphRequest.SelectedView.HostAggregationSelectors)
}

// ---- Mock backend for testing ----

type MockServiceGraphBackend struct {
	FlowConfig                   FlowConfig
	FlowConfigErr                error
	L3                           []L3Flow
	L3Err                        error
	L7                           []L7Flow
	L7Err                        error
	DNS                          []DNSLog
	DNSErr                       error
	Events                       []Event
	EventsErr                    error
	RBACFilter                   RBACFilter
	RBACFilterErr                error
	NameHelper                   NameHelper
	NameHelperErr                error
	ServiceLabels                map[v1.NamespacedName]LabelSelectors
	ServiceLabelsErr             error
	ReplicaSetLabels             map[v1.NamespacedName]LabelSelectors
	ReplicaSetLabelsErr          error
	StatefulSetLabels            map[v1.NamespacedName]LabelSelectors
	StatefulSetLabelsErr         error
	DaemonSetLabels              map[v1.NamespacedName]LabelSelectors
	DaemonSetLabelsErr           error
	PodsLabels                   map[v1.NamespacedName]LabelSelectors
	PodsLabelsErr                error
	lock                         sync.Mutex
	numCallsFlowConfig           int
	numCallsL3                   int
	numCallsL7                   int
	numCallsDNS                  int
	numCallsEvents               int
	numCallsRBACFilter           int
	numCallsNameHelper           int
	numCallsGetServiceLabels     int
	numCallsGetReplicaSetLabels  int
	numCallsGetStatefulSetLabels int
	numCallsGetDaemonSetLabels   int
	numCallsGetPodsLabels        int
	wgLinseed                    sync.WaitGroup
	numBlockedLinseed            int
}

func (m *MockServiceGraphBackend) GetServiceLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsGetServiceLabels++
	return m.ServiceLabels, m.ServiceLabelsErr
}

func (m *MockServiceGraphBackend) GetPodsLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsGetPodsLabels++
	return m.PodsLabels, m.PodsLabelsErr
}

func (m *MockServiceGraphBackend) GetReplicaSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsGetReplicaSetLabels++
	return m.ReplicaSetLabels, m.ReplicaSetLabelsErr
}

func (m *MockServiceGraphBackend) GetStatefulSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsGetStatefulSetLabels++
	return m.StatefulSetLabels, m.StatefulSetLabelsErr
}

func (m *MockServiceGraphBackend) GetDaemonSetLabels(ctx context.Context, cluster string) (map[v1.NamespacedName]LabelSelectors, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsGetDaemonSetLabels++
	return m.DaemonSetLabels, m.DaemonSetLabelsErr
}

func (m *MockServiceGraphBackend) waitLinseed() {
	m.lock.Lock()
	m.numBlockedLinseed++
	m.lock.Unlock()
	m.wgLinseed.Wait()
	m.lock.Lock()
	m.numBlockedLinseed--
	m.lock.Unlock()
}

func (m *MockServiceGraphBackend) GetFlowConfig(ctx context.Context, cluster string) (*FlowConfig, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsFlowConfig++
	if m.FlowConfigErr != nil {
		return nil, m.FlowConfigErr
	}
	return &m.FlowConfig, nil
}

func (m *MockServiceGraphBackend) GetL3FlowData(
	ctx context.Context, cluster string, namespace string, tr lmav1.TimeRange, fc *FlowConfig,
) ([]L3Flow, error) {
	m.waitLinseed()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsL3++
	return m.L3, m.L3Err
}

func (m *MockServiceGraphBackend) GetL7FlowData(
	ctx context.Context, cluster string, tr lmav1.TimeRange,
) ([]L7Flow, error) {
	m.waitLinseed()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsL7++
	return m.L7, m.L7Err
}

func (m *MockServiceGraphBackend) GetDNSData(
	ctx context.Context, cluster string, tr lmav1.TimeRange,
) ([]DNSLog, error) {
	m.waitLinseed()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsDNS++
	return m.DNS, m.DNSErr
}

func (m *MockServiceGraphBackend) GetEvents(
	ctx context.Context, cluster string, tr lmav1.TimeRange,
) ([]Event, error) {
	m.waitLinseed()
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsEvents++
	return m.Events, m.EventsErr
}

func (m *MockServiceGraphBackend) NewRBACFilter(ctx context.Context, rd *RequestData) (RBACFilter, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsRBACFilter++
	if m.RBACFilterErr != nil {
		return nil, m.RBACFilterErr
	}
	return m.RBACFilter, nil
}

func (m *MockServiceGraphBackend) NewNameHelper(ctx context.Context, rd *RequestData) (NameHelper, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.numCallsNameHelper++
	if m.NameHelperErr != nil {
		return nil, m.NameHelperErr
	}
	return m.NameHelper, nil
}

func (m *MockServiceGraphBackend) SetBlockLinseed() {
	m.wgLinseed.Add(1)
}

func (m *MockServiceGraphBackend) SetUnblockLinseed() {
	m.wgLinseed.Done()
}

func (m *MockServiceGraphBackend) GetNumCallsFlowConfig() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numCallsFlowConfig
}

func (m *MockServiceGraphBackend) GetNumCallsL3() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numCallsL3
}

func (m *MockServiceGraphBackend) GetNumCallsL7() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numCallsL7
}

func (m *MockServiceGraphBackend) GetNumCallsDNS() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numCallsDNS
}

func (m *MockServiceGraphBackend) GetNumCallsEvents() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numCallsEvents
}

func (m *MockServiceGraphBackend) GetNumCallsRBACFilter() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numCallsRBACFilter
}

func (m *MockServiceGraphBackend) GetNumCallsNameHelper() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numCallsNameHelper
}

func (m *MockServiceGraphBackend) GetNumBlocked() int {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.numBlockedLinseed
}
