// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package labelselector_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/labelselector"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	podID = apiv3.ResourceID{
		TypeMeta:  resources.TypeK8sPods,
		Name:      "test",
		Namespace: "namespace",
	}
	policyID = apiv3.ResourceID{
		TypeMeta:  resources.TypeCalicoNetworkPolicies,
		Name:      "testNP",
		Namespace: "namespace",
	}
	podSet    = set.From[apiv3.ResourceID](podID)
	policySet = set.From[apiv3.ResourceID](policyID)
)

type tester struct {
	l        labelselector.LabelSelector
	policies set.Set[apiv3.ResourceID]
	pods     set.Set[apiv3.ResourceID]
}

func newTester() *tester {
	return &tester{
		l:        labelselector.New(),
		policies: set.New[apiv3.ResourceID](),
		pods:     set.New[apiv3.ResourceID](),
	}
}

func (t *tester) onMatchPodStart(policy, pod apiv3.ResourceID) {
	t.pods.Add(pod)
}

func (t *tester) onMatchPodStopped(policy, pod apiv3.ResourceID) {
	t.pods.Discard(pod)
}

func (t *tester) onMatchPolicyStart(policy, pod apiv3.ResourceID) {
	t.policies.Add(policy)
}

func (t *tester) onMatchPolicyStopped(policy, pod apiv3.ResourceID) {
	t.policies.Discard(policy)
}

func (t *tester) registerPodCallbacks() {
	t.l.RegisterCallbacks(
		[]metav1.TypeMeta{resources.TypeK8sPods},
		t.onMatchPodStart,
		t.onMatchPodStopped,
	)
}

func (t *tester) registerPolicyCallbacks() {
	t.l.RegisterCallbacks(
		[]metav1.TypeMeta{resources.TypeCalicoNetworkPolicies},
		t.onMatchPolicyStart,
		t.onMatchPolicyStopped,
	)
}

var _ = Describe("label selector checks", func() {
	It("should get pod and policy callbacks if both registered", func() {
		t := newTester()

		By("Registering for pod and policy callbacks")
		t.registerPodCallbacks()
		t.registerPolicyCallbacks()

		By("Adding a matching selector/label")
		t.l.UpdateSelector(policyID, "thing == 'yes'")
		t.l.UpdateLabels(podID, uniquelabels.Make(map[string]string{
			"thing": "yes",
		}), nil)
		Expect(t.policies.Equals(policySet)).To(BeTrue())
		Expect(t.pods.Equals(podSet)).To(BeTrue())

		By("Removing the match")
		t.l.UpdateSelector(policyID, "thing == 'no'")
		Expect(t.policies.Len()).To(BeZero())
		Expect(t.pods.Len()).To(BeZero())
	})

	It("should get pod callbacks if registered, but not policy", func() {
		t := newTester()

		By("Registering for pod callbacks")
		t.registerPodCallbacks()

		By("Adding a matching selector/label")
		t.l.UpdateSelector(policyID, "thing == 'boo'")
		t.l.UpdateLabels(podID, uniquelabels.Make(map[string]string{
			"thing": "boo",
		}), nil)
		Expect(t.policies.Len()).To(BeZero())
		Expect(t.pods.Equals(podSet)).To(BeTrue())

		By("Removing the match")
		t.l.UpdateLabels(podID, uniquelabels.Make(map[string]string{
			"thing": "foo",
		}), nil)
		Expect(t.policies.Len()).To(BeZero())
		Expect(t.pods.Len()).To(BeZero())
	})

	It("should get policy callbacks if registered, but not pod", func() {
		t := newTester()

		By("Registering for policy callbacks")
		t.registerPolicyCallbacks()

		By("Adding a matching selector/label")
		t.l.UpdateSelector(policyID, "thing == 'boo'")
		t.l.UpdateLabels(podID, uniquelabels.Make(map[string]string{
			"thing": "boo",
		}), nil)
		Expect(t.policies.Equals(policySet)).To(BeTrue())
		Expect(t.pods.Len()).To(BeZero())

		By("Removing the match")
		t.l.UpdateLabels(podID, uniquelabels.Make(map[string]string{
			"thing": "foo",
		}), nil)
		Expect(t.policies.Len()).To(BeZero())
		Expect(t.pods.Len()).To(BeZero())
	})

	It("should handle parent inheritance of labels", func() {
		t := newTester()

		By("Registering for policy callbacks")
		t.registerPolicyCallbacks()
		t.registerPodCallbacks()

		By("Adding a matching selector/label via parent")
		t.l.UpdateSelector(policyID, "thing == 'boo'")
		t.l.UpdateParentLabels("parent", map[string]string{
			"thing": "boo",
		})
		t.l.UpdateLabels(podID, uniquelabels.Nil, []string{"parent"})
		Expect(t.policies.Equals(policySet)).To(BeTrue())
		Expect(t.pods.Equals(podSet)).To(BeTrue())

		By("Removing the parent")
		t.l.UpdateLabels(podID, uniquelabels.Nil, []string{"afakeparent"})
		Expect(t.policies.Len()).To(BeZero())
		Expect(t.pods.Len()).To(BeZero())
	})
})
