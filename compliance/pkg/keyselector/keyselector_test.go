// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package keyselector

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	c1 = apiv3.ResourceID{
		TypeMeta: resources.TypeK8sEndpoints,
		Name:     "1",
	}
	c2 = apiv3.ResourceID{
		TypeMeta: resources.TypeK8sEndpoints,
		Name:     "2",
	}
	o1 = apiv3.ResourceID{
		TypeMeta: resources.TypeCalicoHostEndpoints,
		Name:     "1",
	}
	o2 = apiv3.ResourceID{
		TypeMeta: resources.TypeCalicoHostEndpoints,
		Name:     "2",
	}
)

type cb struct {
	owner     apiv3.ResourceID
	client    apiv3.ResourceID
	key       string
	firstLast bool
}

type tester struct {
	k            KeySelector
	matchStarted set.Set[cb]
	matchStopped set.Set[cb]
}

func newTester() *tester {
	t := &tester{
		k: New(),
	}
	t.k.RegisterCallbacks(
		[]metav1.TypeMeta{resources.TypeCalicoHostEndpoints, resources.TypeK8sEndpoints},
		t.onMatchStarted, t.onMatchStopped,
	)
	return t
}

func (t *tester) onMatchStarted(owner, client apiv3.ResourceID, key string, first bool) {
	t.matchStarted.Add(cb{owner, client, key, first})
}

func (t *tester) onMatchStopped(owner, client apiv3.ResourceID, key string, last bool) {
	t.matchStopped.Add(cb{owner, client, key, last})
}

func (t *tester) setClientKeys(client apiv3.ResourceID, keys set.Set[string]) {
	if client.TypeMeta != resources.TypeK8sEndpoints {
		panic("Error in test code, passing in wrong client type")
	}
	t.matchStarted = set.New[cb]()
	t.matchStopped = set.New[cb]()
	t.k.SetClientKeys(client, keys)
}

func (t *tester) setOwnerKeys(owner apiv3.ResourceID, keys set.Set[string]) {
	if owner.TypeMeta != resources.TypeCalicoHostEndpoints {
		panic("Error in test code, passing in wrong owner type")
	}
	t.matchStarted = set.New[cb]()
	t.matchStopped = set.New[cb]()
	t.k.SetOwnerKeys(owner, keys)
}

func (t *tester) deleteClient(client apiv3.ResourceID) {
	if client.TypeMeta != resources.TypeK8sEndpoints {
		panic("Error in test code, passing in wrong client type")
	}
	t.matchStarted = set.New[cb]()
	t.matchStopped = set.New[cb]()
	t.k.DeleteClient(client)
}

func (t *tester) deleteOwner(owner apiv3.ResourceID) {
	if owner.TypeMeta != resources.TypeCalicoHostEndpoints {
		panic("Error in test code, passing in wrong owner type")
	}
	t.matchStarted = set.New[cb]()
	t.matchStopped = set.New[cb]()
	t.k.DeleteOwner(owner)
}

func (t *tester) ExpectEmpty() {
	Expect(t.k.(*keySelector).clientsByKey).To(HaveLen(0))
	Expect(t.k.(*keySelector).keysByClient).To(HaveLen(0))
	Expect(t.k.(*keySelector).ownersByKey).To(HaveLen(0))
	Expect(t.k.(*keySelector).keysByOwner).To(HaveLen(0))
	Expect(t.k.(*keySelector).keysByOwnerClient).To(HaveLen(0))
}

var _ = Describe("label selector checks", func() {
	It("simple matches between client and owner and then remove owner", func() {
		t := newTester()

		By("Setting client1 key A")
		t.setClientKeys(c1, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(BeZero())

		By("Setting owner1 key A")
		t.setOwnerKeys(o1, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStarted.Contains(cb{o1, c1, "A", true})).To(BeTrue())

		By("Deleting owner1")
		t.deleteOwner(o1)
		Expect(t.matchStopped.Len()).To(Equal(1))
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Contains(cb{o1, c1, "A", true})).To(BeTrue())

		By("Deleting client1")
		t.deleteClient(c1)
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Len()).To(BeZero())

		By("Checking internal data")
		t.ExpectEmpty()
	})

	It("simple matches between client and owner and then remove owner", func() {
		t := newTester()

		By("Setting owner1 key A")
		t.setOwnerKeys(o1, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(BeZero())

		By("Setting client1 key A")
		t.setClientKeys(c1, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStarted.Contains(cb{o1, c1, "A", true})).To(BeTrue())

		By("Deleting client1")
		t.deleteClient(c1)
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Len()).To(Equal(1))
		Expect(t.matchStopped.Contains(cb{o1, c1, "A", true})).To(BeTrue())

		By("Deleting owner1")
		t.deleteOwner(o1)
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Len()).To(BeZero())

		By("Checking internal data")
		t.ExpectEmpty()
	})

	It("simple matches multiple clients to owner then remove owner", func() {
		t := newTester()

		By("Setting owner1 key A")
		t.setOwnerKeys(o1, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(BeZero())

		By("Setting client1 key A")
		t.setClientKeys(c1, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStarted.Contains(cb{o1, c1, "A", true})).To(BeTrue())

		By("Setting client2 key A")
		t.setClientKeys(c2, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStarted.Contains(cb{o1, c2, "A", true})).To(BeTrue())

		By("Deleting owner1")
		t.deleteOwner(o1)
		Expect(t.matchStopped.Len()).To(Equal(2))
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Contains(cb{o1, c1, "A", true})).To(BeTrue())
		Expect(t.matchStopped.Contains(cb{o1, c2, "A", true})).To(BeTrue())

		By("Deleting client1 and client2")
		t.deleteClient(c1)
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(BeZero())
		t.deleteClient(c2)
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(BeZero())

		By("Checking internal data")
		t.ExpectEmpty()
	})

	It("multi-way matches", func() {
		t := newTester()

		By("Setting owner1 key A")
		t.setOwnerKeys(o1, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(BeZero())

		By("Setting client1 keys A and B")
		t.setClientKeys(c1, set.From("A", "B"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStarted.Contains(cb{o1, c1, "A", true})).To(BeTrue())

		By("Setting owner2 keys A")
		t.setOwnerKeys(o2, set.From("A"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStarted.Contains(cb{o2, c1, "A", true})).To(BeTrue())

		By("Updating owner2 keys A and B")
		t.setOwnerKeys(o2, set.From("A", "B"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStarted.Contains(cb{o2, c1, "B", false})).To(BeTrue())

		By("Updating owner1 key B")
		t.setOwnerKeys(o1, set.From("B"))
		Expect(t.matchStopped.Len()).To(Equal(1))
		Expect(t.matchStarted.Len()).To(Equal(1))
		Expect(t.matchStopped.Contains(cb{o1, c1, "A", true})).To(BeTrue())
		Expect(t.matchStarted.Contains(cb{o1, c1, "B", true})).To(BeTrue())

		By("Setting client2 keys B")
		t.setClientKeys(c2, set.From("B"))
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(Equal(2))
		Expect(t.matchStarted.Contains(cb{o1, c2, "B", true})).To(BeTrue())
		Expect(t.matchStarted.Contains(cb{o2, c2, "B", true})).To(BeTrue())

		By("Updating client1 key B")
		t.setClientKeys(c1, set.From("B"))
		Expect(t.matchStopped.Len()).To(Equal(1))
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Contains(cb{o2, c1, "A", false})).To(BeTrue())

		By("Deleting client1")
		t.deleteClient(c1)
		Expect(t.matchStopped.Len()).To(Equal(2))
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Contains(cb{o1, c1, "B", true})).To(BeTrue())
		Expect(t.matchStopped.Contains(cb{o2, c1, "B", true})).To(BeTrue())

		By("Deleting owner1")
		t.deleteOwner(o1)
		Expect(t.matchStopped.Len()).To(Equal(1))
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Contains(cb{o1, c2, "B", true})).To(BeTrue())

		By("Deleting owner2")
		t.deleteOwner(o2)
		Expect(t.matchStopped.Len()).To(Equal(1))
		Expect(t.matchStarted.Len()).To(BeZero())
		Expect(t.matchStopped.Contains(cb{o2, c2, "B", true})).To(BeTrue())

		By("Deleting client2")
		t.deleteClient(c2)
		Expect(t.matchStopped.Len()).To(BeZero())
		Expect(t.matchStarted.Len()).To(BeZero())

		By("Checking internal data")
		t.ExpectEmpty()
	})
})
