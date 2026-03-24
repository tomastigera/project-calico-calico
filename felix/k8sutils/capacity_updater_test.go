// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package k8sutils

import (
	"context"
	"errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	clock "k8s.io/utils/clock/testing"

	"github.com/projectcalico/calico/felix/aws"
)

const (
	nodeName = "test-node"
)

var nodeGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "nodes",
}

func TestCapacityUpdater_Mainline(t *testing.T) {
	cu, fake, tearDown := setupAndStart(t)
	defer tearDown()

	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 22,
	})

	// Expect a read then a patch to add the new capacity.
	Eventually(fake.Kube.Actions).Should(HaveLen(2))
	Consistently(fake.Kube.Actions).Should(HaveLen(2))
	actions := fake.Kube.Actions()
	Expect(actions[0].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[0].(k8stesting.GetAction).GetName()).To(Equal(nodeName))
	Expect(actions[1].Matches("patch", "nodes")).To(BeTrue())
	Expect(actions[1].(k8stesting.PatchAction).GetName()).To(Equal(nodeName))
	Expect(string(actions[1].(k8stesting.PatchAction).GetPatch())).To(Equal(
		`{"status":{"capacity":{"projectcalico.org/aws-secondary-ipv4":"22"}}}`))

	// Expect the capacity update to stick.
	node, err := fake.Kube.Tracker().Get(nodeGVR, "", nodeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(node.(*v1.Node).Status.Capacity).To(Equal(v1.ResourceList{
		"projectcalico.org/aws-secondary-ipv4": resource.MustParse("22"),
	}))
}

func TestCapacityUpdater_ErrBackoffGet(t *testing.T) {
	cu, fake, tearDown := setupAndStart(t)
	defer tearDown()

	first := true
	fake.Kube.PrependReactor("get", "nodes", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		if first {
			first = false
			return true, nil, errors.New("surprise")
		}
		return false, nil, nil
	})

	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 22,
	})

	// Expect the read then backoff.
	Eventually(fake.Kube.Actions).Should(HaveLen(1))
	Consistently(fake.Kube.Actions).Should(HaveLen(1))
	actions := fake.Kube.Actions()
	Expect(actions[0].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[0].(k8stesting.GetAction).GetName()).To(Equal(nodeName))

	// Backoff should be between 1000 and 1100 ms due to jitter.
	Eventually(fake.Clock.HasWaiters).Should(BeTrue())
	fake.Clock.Step(999 * time.Millisecond)
	Consistently(fake.Kube.Actions).Should(HaveLen(1))
	fake.Clock.Step(102 * time.Millisecond)

	// When the backoff is done, we should get a fresh GET and PATCH.
	Eventually(fake.Kube.Actions).Should(HaveLen(3))
	Consistently(fake.Kube.Actions).Should(HaveLen(3))
	actions = fake.Kube.Actions()
	Expect(actions[1].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[1].(k8stesting.GetAction).GetName()).To(Equal(nodeName))
	Expect(actions[2].Matches("patch", "nodes")).To(BeTrue())
	Expect(actions[2].(k8stesting.PatchAction).GetName()).To(Equal(nodeName))

	// Expect the capacity update to be in place.
	node, err := fake.Kube.Tracker().Get(nodeGVR, "", nodeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(node.(*v1.Node).Status.Capacity).To(Equal(v1.ResourceList{
		"projectcalico.org/aws-secondary-ipv4": resource.MustParse("22"),
	}))
}

func TestCapacityUpdater_ErrBackoffPatch(t *testing.T) {
	cu, fake, tearDown := setupAndStart(t)
	defer tearDown()

	first := true
	fake.Kube.PrependReactor("patch", "nodes", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		if first {
			first = false
			return true, nil, errors.New("surprise")
		}
		return false, nil, nil
	})

	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 22,
	})

	// Expect the read then backoff.
	Eventually(fake.Kube.Actions).Should(HaveLen(2))
	Consistently(fake.Kube.Actions).Should(HaveLen(2))
	actions := fake.Kube.Actions()
	Expect(actions[1].Matches("patch", "nodes")).To(BeTrue())
	Expect(actions[1].(k8stesting.PatchAction).GetName()).To(Equal(nodeName))

	// Backoff should be between 1000 and 1100 ms due to jitter.
	Eventually(fake.Clock.HasWaiters).Should(BeTrue())
	fake.Clock.Step(999 * time.Millisecond)
	Consistently(fake.Kube.Actions).Should(HaveLen(2))
	fake.Clock.Step(102 * time.Millisecond)

	// When the backoff is done, we should get a fresh GET and PATCH.
	Eventually(fake.Kube.Actions).Should(HaveLen(4))
	Consistently(fake.Kube.Actions).Should(HaveLen(4))
	actions = fake.Kube.Actions()
	Expect(actions[2].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[2].(k8stesting.GetAction).GetName()).To(Equal(nodeName))
	Expect(actions[3].Matches("patch", "nodes")).To(BeTrue())
	Expect(actions[3].(k8stesting.PatchAction).GetName()).To(Equal(nodeName))

	// Expect the capacity update to be in place.
	node, err := fake.Kube.Tracker().Get(nodeGVR, "", nodeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(node.(*v1.Node).Status.Capacity).To(Equal(v1.ResourceList{
		"projectcalico.org/aws-secondary-ipv4": resource.MustParse("22"),
	}))
}

func TestCapacityUpdater_ErrBackoffInterruptedGet(t *testing.T) {
	cu, fake, tearDown := setupAndStart(t)
	defer tearDown()

	first := true
	fake.Kube.PrependReactor("get", "nodes", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		if first {
			first = false
			return true, nil, errors.New("surprise")
		}
		return false, nil, nil
	})

	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 22,
	})

	// Expect the read then backoff.
	Eventually(fake.Kube.Actions).Should(HaveLen(1))
	Consistently(fake.Kube.Actions).Should(HaveLen(1))
	actions := fake.Kube.Actions()
	Expect(actions[0].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[0].(k8stesting.GetAction).GetName()).To(Equal(nodeName))

	// Backoff should be between 1000 and 1100 ms due to jitter.
	Eventually(fake.Clock.HasWaiters).Should(BeTrue())
	fake.Clock.Step(999 * time.Millisecond)

	// Send fresh capacity update, should cancel backoff.
	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 42,
	})

	// Expect a fresh get and patch.
	Eventually(fake.Kube.Actions).Should(HaveLen(3))
	Consistently(fake.Kube.Actions).Should(HaveLen(3))
	actions = fake.Kube.Actions()
	Expect(actions[1].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[2].Matches("patch", "nodes")).To(BeTrue())

	// Expect the capacity update to be in place.
	node, err := fake.Kube.Tracker().Get(nodeGVR, "", nodeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(node.(*v1.Node).Status.Capacity).To(Equal(v1.ResourceList{
		"projectcalico.org/aws-secondary-ipv4": resource.MustParse("42"),
	}))
}

func TestCapacityUpdater_ErrBackoffInterruptedPatch(t *testing.T) {
	cu, fake, tearDown := setupAndStart(t)
	defer tearDown()

	first := true
	fake.Kube.PrependReactor("patch", "nodes", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		if first {
			first = false
			return true, nil, errors.New("surprise")
		}
		return false, nil, nil
	})

	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 22,
	})

	// Expect the read then backoff.
	Eventually(fake.Kube.Actions).Should(HaveLen(2))
	Consistently(fake.Kube.Actions).Should(HaveLen(2))
	actions := fake.Kube.Actions()
	Expect(actions[1].Matches("patch", "nodes")).To(BeTrue())
	Expect(actions[1].(k8stesting.PatchAction).GetName()).To(Equal(nodeName))

	// Backoff should be between 1000 and 1100 ms due to jitter.
	Eventually(fake.Clock.HasWaiters).Should(BeTrue())
	fake.Clock.Step(999 * time.Millisecond)

	// Send fresh capacity update, should cancel backoff.
	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 42,
	})

	// Expect a fresh get and patch.
	Eventually(fake.Kube.Actions).Should(HaveLen(4))
	Consistently(fake.Kube.Actions).Should(HaveLen(4))
	actions = fake.Kube.Actions()
	Expect(actions[2].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[3].Matches("patch", "nodes")).To(BeTrue())

	// Expect the capacity update to be in place.
	node, err := fake.Kube.Tracker().Get(nodeGVR, "", nodeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(node.(*v1.Node).Status.Capacity).To(Equal(v1.ResourceList{
		"projectcalico.org/aws-secondary-ipv4": resource.MustParse("42"),
	}))
}

func TestCapacityUpdater_PeriodicResync(t *testing.T) {
	cu, fake, tearDown := setupAndStart(t)
	defer tearDown()

	cu.OnCapacityChange(aws.SecondaryIfaceCapacities{
		MaxCalicoSecondaryIPs: 22,
	})

	// Expect the normal start-of-day resync.
	Eventually(fake.Kube.Actions).Should(HaveLen(2))
	node, err := fake.Kube.Tracker().Get(nodeGVR, "", nodeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(node.(*v1.Node).Status.Capacity).To(Equal(v1.ResourceList{
		"projectcalico.org/aws-secondary-ipv4": resource.MustParse("22"),
	}))

	// First periodic resync finds no problems...
	Eventually(fake.Clock.HasWaiters).Should(BeTrue())
	fake.Clock.Step(defaultRefreshInterval * 2)
	// No fourth action because the reread of the node should find that it's correct.
	Eventually(fake.Kube.Actions).Should(HaveLen(3))
	Consistently(fake.Kube.Actions).Should(HaveLen(3))
	actions := fake.Kube.Actions()
	Expect(actions[2].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[2].(k8stesting.GetAction).GetName()).To(Equal(nodeName))

	// Then we manually modify the capacity.
	{
		node := &v1.Node{}
		node.SetName(nodeName)
		node.Status.Capacity = v1.ResourceList{
			"projectcalico.org/aws-secondary-ipv4": resource.MustParse("10"),
		}
		err := fake.Kube.Tracker().Update(nodeGVR, node, "")
		Expect(err).NotTo(HaveOccurred())
	}

	// Second resync should find problem and fix it.
	Eventually(fake.Clock.HasWaiters).Should(BeTrue())
	fake.Clock.Step(defaultRefreshInterval * 2)
	Eventually(fake.Kube.Actions).Should(HaveLen(5))
	Consistently(fake.Kube.Actions).Should(HaveLen(5))
	actions = fake.Kube.Actions()
	Expect(actions[3].Matches("get", "nodes")).To(BeTrue())
	Expect(actions[4].Matches("patch", "nodes")).To(BeTrue())

	// Expect the capacity to be fixed.
	node, err = fake.Kube.Tracker().Get(nodeGVR, "", nodeName)
	Expect(err).NotTo(HaveOccurred())
	Expect(node.(*v1.Node).Status.Capacity).To(Equal(v1.ResourceList{
		"projectcalico.org/aws-secondary-ipv4": resource.MustParse("22"),
	}))
}

func setup(t *testing.T) (*CapacityUpdater, *cuTestFakes) {
	RegisterTestingT(t)

	theTime, err := time.Parse("2006-01-02 15:04:05.000", "2021-09-15 16:00:00.000")
	Expect(err).NotTo(HaveOccurred())
	fakeClock := clock.NewFakeClock(theTime)

	node := &v1.Node{}
	node.SetName(nodeName)
	fakeKube := fakek8s.NewClientset(node)

	cu := NewCapacityUpdater(
		nodeName,
		fakeKube.CoreV1(),
		OptClockOverride(fakeClock),
	)

	return cu, &cuTestFakes{
		Clock: fakeClock,
		Kube:  fakeKube,
	}
}

func setupAndStart(t *testing.T) (*CapacityUpdater, *cuTestFakes, func()) {
	cu, fake := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	doneC := cu.Start(ctx)
	return cu, fake, func() {
		cancel()
		Eventually(doneC).Should(BeClosed())
	}
}

type cuTestFakes struct {
	Clock *clock.FakeClock
	Kube  *fakek8s.Clientset
}
