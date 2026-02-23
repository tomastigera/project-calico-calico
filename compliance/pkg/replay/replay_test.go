// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package replay_test

import (
	"context"
	"encoding/json"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/apis/audit"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/replay"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/lma/pkg/list"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

// NewNetworkPolicyList creates a new (zeroed) NetworkPolicyList struct with the TypeMetadata initialised to the current
// version.
// This is defined locally as it's a convenience method that is not widely used.
func NewNetworkPolicyList() *apiv3.NetworkPolicyList {
	return &apiv3.NetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindNetworkPolicyList,
			APIVersion: apiv3.GroupVersionCurrent,
		},
	}
}

var _ = Describe("Replay", func() {
	var (
		ctx = context.Background()

		baseTime            = time.Date(2019, 4, 3, 20, 0o1, 0, 0, time.UTC)
		mockListDestination *api.MockListDestination
		mockEventFetcher    *api.MockReportEventFetcher
		mockSyncerCallbacks *syncer.MockSyncerCallbacks
	)

	BeforeEach(func() {
		mockListDestination = new(api.MockListDestination)
		mockEventFetcher = new(api.MockReportEventFetcher)
		mockSyncerCallbacks = new(syncer.MockSyncerCallbacks)
	})

	AfterEach(func() {
		mockListDestination.AssertExpectations(GinkgoT())
		mockEventFetcher.AssertExpectations(GinkgoT())
		mockSyncerCallbacks.AssertExpectations(GinkgoT())
	})

	It("should send both an insync and a complete status update in a complete run through", func() {
		By("initializing the replayer with mock interfaces")
		replayer := replay.New(baseTime.Add(time.Minute), baseTime.Add(2*time.Minute), mockListDestination, mockEventFetcher, mockSyncerCallbacks)

		// make the initial network policy without a typemeta
		np := apiv3.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Namespace: "some-namespace", Name: "some-netpol", ResourceVersion: "100"},
			Spec:       apiv3.NetworkPolicySpec{Selector: `foo == "bar"`},
		}

		npList := NewNetworkPolicyList()
		npList.GetObjectKind().SetGroupVersionKind(resources.TypeCalicoNetworkPolicies.GroupVersionKind())

		npList.Items = append(npList.Items, np)

		By("Mocking RetrieveList to return empty results for all resource except for NetworkPolicies")
		for _, helper := range resources.GetAllResourceHelpers() {
			resList := resourceListFromHelper(helper)
			var tResList *list.TimestampedResourceList
			if helper.TypeMeta() == resources.TypeCalicoNetworkPolicies {
				tResList = newTimeStampedResourceList(npList, baseTime.Add(15*time.Second), baseTime.Add(16*time.Second))
			} else {
				tResList = newTimeStampedResourceList(resList, baseTime, baseTime)
			}

			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(tResList, nil)
		}

		By("setting a network policy audit event before the start time")
		npUpdate1 := np
		npUpdate1.TypeMeta = resources.TypeCalicoNetworkPolicies
		npUpdate1.Spec.Selector = `foo == "baz"`

		By("setting a network policy audit event after the start time")
		npUpdate2 := np
		npUpdate2.TypeMeta = resources.TypeCalicoNetworkPolicies
		npUpdate2.Spec.Selector = `foo == "barbaz"`

		By("setting a network policy audit event after the start time but with a bad resource version")
		npUpdate3 := np
		npUpdate3.TypeMeta = resources.TypeCalicoNetworkPolicies
		npUpdate3.Spec.Selector = `foo == "blah"`

		auditEvent1 := newAuditEvent(v1.Update, audit.StageResponseComplete, &npUpdate1, &npUpdate1, baseTime.Add(30*time.Second), "101")
		auditEvent2 := newAuditEvent(v1.Update, audit.StageResponseComplete, &npUpdate2, &npUpdate2, baseTime.Add(75*time.Second), "102")
		auditEvent3 := newAuditEvent(v1.Update, audit.StageResponseComplete, &npUpdate3, &npUpdate3, baseTime.Add(90*time.Second), "100")

		By("Mocking the first GetAuditEvents to send just auditEvent1")
		mockEventFetcher.On("GetAuditEvents", mock.Anything, mock.Anything, mock.Anything).Return(
			createAuditEventChannel(auditEvent1)).Once()
		By("Mocking the second GetAuditEvents to send auditEvent2 and auditEvent3")
		mockEventFetcher.On("GetAuditEvents", mock.Anything, mock.Anything, mock.Anything).Return(
			createAuditEventChannel(auditEvent2, auditEvent3)).Once()

		resourceID := apiv3.ResourceID{TypeMeta: resources.TypeCalicoNetworkPolicies, Name: "some-netpol", Namespace: "some-namespace"}
		mockSyncerCallbacks.On("OnUpdates", []syncer.Update{{Type: syncer.UpdateTypeSet, ResourceID: resourceID, Resource: &npUpdate1}})
		mockSyncerCallbacks.On("OnUpdates", []syncer.Update{{Type: syncer.UpdateTypeSet, ResourceID: resourceID, Resource: &npUpdate2}})

		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateInSync()).Return()
		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateComplete()).Return()

		// Make the replay call.
		replayer.Start(ctx)
	})

	It("should properly handle a Status event", func() {
		replayer := replay.New(baseTime.Add(time.Minute), baseTime.Add(2*time.Minute), mockListDestination, mockEventFetcher, mockSyncerCallbacks)
		np := &apiv3.NetworkPolicy{TypeMeta: resources.TypeCalicoNetworkPolicies}

		for _, helper := range resources.GetAllResourceHelpers() {
			resList := resourceListFromHelper(helper)
			tResList := newTimeStampedResourceList(resList, baseTime, baseTime)

			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(tResList, nil)
		}

		auditEvent := newAuditEvent(v1.Create, audit.StageResponseComplete, np,
			&metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}},
			baseTime.Add(30*time.Second), "100")

		mockEventFetcher.On("GetAuditEvents", mock.Anything, mock.Anything, mock.Anything).Return(
			createAuditEventChannel(auditEvent)).Once()
		// return an empty channel for the replay
		mockEventFetcher.On("GetAuditEvents", mock.Anything, mock.Anything, mock.Anything).Return(
			createAuditEventChannel()).Once()

		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateInSync()).Return()
		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateComplete()).Return()

		Expect(func() {
			replayer.Start(ctx)
		}).ShouldNot(Panic())
	})

	It("should properly handle a StageResponseStarted event", func() {
		replayer := replay.New(baseTime.Add(time.Minute), baseTime.Add(2*time.Minute), mockListDestination, mockEventFetcher, mockSyncerCallbacks)
		np := &apiv3.NetworkPolicy{TypeMeta: resources.TypeCalicoNetworkPolicies}
		for _, helper := range resources.GetAllResourceHelpers() {
			resList := resourceListFromHelper(helper)
			tResList := newTimeStampedResourceList(resList, baseTime, baseTime)

			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(tResList, nil)
		}

		auditEvent := newAuditEvent(v1.Update, audit.StageResponseStarted, np, nil, baseTime.Add(75*time.Second), "102")
		mockEventFetcher.On("GetAuditEvents", mock.Anything, mock.Anything, mock.Anything).Return(
			createAuditEventChannel(auditEvent)).Once()
		mockEventFetcher.On("GetAuditEvents", mock.Anything, mock.Anything, mock.Anything).Return(
			createAuditEventChannel()).Once()

		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateInSync()).Return()
		mockSyncerCallbacks.On("OnStatusUpdate", syncer.NewStatusUpdateComplete()).Return()

		Expect(func() {
			replayer.Start(ctx)
		}).ShouldNot(Panic())
	})
})

func createAuditEventChannel(events ...*api.AuditEventResult) <-chan *api.AuditEventResult {
	auditChan := make(chan *api.AuditEventResult, len(events))
	defer close(auditChan)
	for _, event := range events {
		auditChan <- event
	}

	return auditChan
}

func newAuditEvent(verb v1.Verb, stage audit.Stage, objRef resources.Resource, respObj any, timestamp time.Time, resVer string) *api.AuditEventResult {
	// Get the resource helper.
	tm := resources.GetTypeMeta(objRef)
	rh := resources.GetResourceHelperByTypeMeta(tm)

	// Create the audit event.
	ev := &audit.Event{
		Verb:  string(verb),
		Stage: stage,
		ObjectRef: &audit.ObjectReference{
			Name:       objRef.GetObjectMeta().GetName(),
			Namespace:  objRef.GetObjectMeta().GetNamespace(),
			APIGroup:   objRef.GetObjectKind().GroupVersionKind().Group,
			APIVersion: objRef.GetObjectKind().GroupVersionKind().Version,
			Resource:   rh.Plural(),
		},
		StageTimestamp: metav1.MicroTime{Time: timestamp},
	}

	// Set the response object if this is a response complete stage event.
	if stage == audit.StageResponseComplete {
		if obj, ok := respObj.(resources.Resource); ok {
			obj.GetObjectMeta().SetResourceVersion(resVer)
		}
		resJson, err := json.Marshal(respObj)
		ev.ResponseObject = &runtime.Unknown{Raw: resJson}
		if err != nil {
			panic(err)
		}
	}

	return &api.AuditEventResult{Event: ev, Err: nil}
}

func resourceListFromHelper(helper resources.ResourceHelper) resources.ResourceList {
	resList := helper.NewResourceList()
	tm := helper.TypeMeta()
	resList.GetObjectKind().SetGroupVersionKind((&tm).GroupVersionKind())
	return resList
}

func newTimeStampedResourceList(resourceList resources.ResourceList, startTime, completedTime time.Time) *list.TimestampedResourceList {
	return &list.TimestampedResourceList{
		ResourceList:              resourceList,
		RequestStartedTimestamp:   metav1.Time{Time: startTime},
		RequestCompletedTimestamp: metav1.Time{Time: completedTime},
	}
}
