// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package dispatcher_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/compliance/pkg/dispatcher"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	pod1ID = apiv3.ResourceID{
		TypeMeta:  resources.TypeK8sPods,
		Name:      "test",
		Namespace: "namespace",
	}
	pod1Add = syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: pod1ID,
		Resource:   resources.NewResource(resources.TypeK8sPods),
	}
	pod2ID = apiv3.ResourceID{
		TypeMeta:  resources.TypeK8sPods,
		Name:      "test2",
		Namespace: "namespace2",
	}
	pod2Delete = syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: pod2ID,
	}
	policy1ID = apiv3.ResourceID{
		TypeMeta:  resources.TypeCalicoNetworkPolicies,
		Name:      "testNP",
		Namespace: "namespace",
	}
	policy1Update = syncer.Update{
		Type:       syncer.UpdateTypeSet,
		ResourceID: policy1ID,
		Resource:   resources.NewResource(resources.TypeCalicoNetworkPolicies),
	}
	policy2ID = apiv3.ResourceID{
		TypeMeta:  resources.TypeCalicoNetworkPolicies,
		Name:      "testNP2",
		Namespace: "namespace",
	}
	policy2Delete = syncer.Update{
		Type:       syncer.UpdateTypeDeleted,
		ResourceID: policy2ID,
	}
)

type tester struct {
	d         dispatcher.Dispatcher
	policies  set.Set[apiv3.ResourceID]
	pods      set.Set[apiv3.ResourceID]
	status    set.Set[syncer.StatusUpdate]
	resources int
}

func newTester() *tester {
	return &tester{
		d:        dispatcher.NewDispatcher("test"),
		policies: set.New[apiv3.ResourceID](),
		pods:     set.New[apiv3.ResourceID](),
		status:   set.New[syncer.StatusUpdate](),
	}
}

func (t *tester) onPodUpdate(update syncer.Update) {
	log.WithField("type", update.Type).Info("Pod update")
	t.pods.Add(update.ResourceID)
	if update.Resource != nil {
		t.resources++
	}
}

func (t *tester) onPolicyUpdate(update syncer.Update) {
	log.WithField("type", update.Type).Info("Policy update")
	t.policies.Add(update.ResourceID)
	if update.Resource != nil {
		t.resources++
	}
}

func (t *tester) onStatusUpdate(status syncer.StatusUpdate) {
	log.WithField("status", status).Info("Status update")
	t.status.Add(status)
}

func (t *tester) registerPodUpdates(types syncer.UpdateType) {
	t.d.RegisterOnUpdateHandler(
		resources.TypeK8sPods,
		types,
		t.onPodUpdate,
	)
}

func (t *tester) registerPolicyUpdates(types syncer.UpdateType) {
	t.d.RegisterOnUpdateHandler(
		resources.TypeCalicoNetworkPolicies,
		types,
		t.onPolicyUpdate,
	)
}

func (t *tester) registerOnStatusCallbacks() {
	t.d.RegisterOnStatusUpdateHandler(t.onStatusUpdate)
}

var _ = Describe("label selector checks", func() {
	It("should get pod callbacks when registered", func() {
		t := newTester()

		By("Registering for pod deleted and new callbacks, and no policy or status callbacks")
		t.registerPodUpdates(syncer.UpdateTypeDeleted | syncer.UpdateTypeSet)

		By("Sending new and deleted pod updates")
		t.d.OnUpdate(pod1Add)
		t.d.OnUpdate(pod2Delete)

		By("Sending update and deleted policy updates")
		t.d.OnUpdate(policy1Update)
		t.d.OnUpdate(policy2Delete)

		By("Sending an onStatusUpdate")
		t.d.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})

		By("Checking we get updates for both pod resources")
		Expect(t.pods.Len()).To(Equal(2))
		Expect(t.pods.Equals(set.From[apiv3.ResourceID](pod1ID, pod2ID))).To(BeTrue())

		By("Checking we get no updates for policy resources")
		Expect(t.policies.Len()).To(BeZero())

		By("Checking we got one new or modified resource")
		Expect(t.resources).To(Equal(1))

		By("Checking we get no status updates")
		Expect(t.status.Len()).To(BeZero())
	})

	It("should get pod, policy and status callbacks when registered", func() {
		t := newTester()

		By("Registering for pod deleted, policy updated and status callbacks")
		t.registerPodUpdates(syncer.UpdateTypeDeleted)
		t.registerPolicyUpdates(syncer.UpdateTypeSet)
		t.registerOnStatusCallbacks()

		By("Sending new and deleted pod updates")
		t.d.OnUpdate(pod1Add)
		t.d.OnUpdate(pod2Delete)

		By("Sending update and deleted policy updates")
		t.d.OnUpdate(policy1Update)
		t.d.OnUpdate(policy2Delete)

		By("Sending an onStatusUpdate")
		t.d.OnStatusUpdate(syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		})

		By("Checking we get updates for the pod delete")
		Expect(t.pods.Len()).To(Equal(1))
		Expect(t.pods.Equals(set.From[apiv3.ResourceID](pod2ID))).To(BeTrue())

		By("Checking we get updates for the policy update")
		Expect(t.policies.Len()).To(Equal(1))
		Expect(t.policies.Equals(set.From[apiv3.ResourceID](policy1ID))).To(BeTrue())

		By("Checking we got one new or modified resource")
		Expect(t.resources).To(Equal(1))
		Expect(t.status.Len()).To(Equal(1))

		By("Checking we the in-sync status update")
		Expect(t.status.Equals(set.From[syncer.StatusUpdate](syncer.StatusUpdate{
			Type: syncer.StatusTypeInSync,
		}))).To(BeTrue())
	})

})
