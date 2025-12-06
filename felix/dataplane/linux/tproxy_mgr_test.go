//go:build !windows

// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package intdataplane

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/ipsets"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/tproxydefs"
)

var _ = Describe("TPROXYManager", func() {
	var (
		c   *iptablesEqualIPsChecker
		cfg Config

		ipv4sets, ipv6sets *mockIPSets
	)

	JustBeforeEach(func() {
		ipv4sets = newMockSets()
		ipv6sets = newMockSets()
		cfg.RulesConfig.TPROXYMode = "Enabled"
		c = newIptablesEqualIPsChecker(cfg, ipv4sets, ipv6sets)
	})

	onUpdate := func(ep string, v4, v6 []string) {
		c.OnWorkloadEndpointUpdate(wlUpdate(ep, v4, v6))
	}

	onRemove := func(ep string) {
		c.OnWorkloadEndpointRemove(wlRemove(ep))
	}

	verify := func(v4, v6 []string) {
		var v4tup, v6tup []string

		for _, m := range v4 {
			v4tup = append(v4tup, m+","+m)
		}

		for _, m := range v6 {
			v6tup = append(v6tup, m+","+m)
		}

		ipv4sets.Verify(tproxydefs.PodSelf, v4tup)
		ipv6sets.Verify(tproxydefs.PodSelf, v6tup)
	}

	It("Should should not fail if it sees delete first", func() {
		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)

		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)
	})

	It("Should should not fail if it sees delete first in the same batch", func() {
		onRemove("ep1")
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)
	})

	It("Should succeed with simple add and delete", func() {
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)
	})

	It("Should not add shared IP just once", func() {
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		onUpdate("ep2", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onRemove("ep2")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)
	})

	It("Should not add first address multiple times when second is added.", func() {
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onUpdate("ep1", []string{"1.1.1.1", "1.1.1.2"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1", "1.1.1.2"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)

		// And the same in the same batch
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		onUpdate("ep1", []string{"1.1.1.1", "1.1.1.2"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1", "1.1.1.2"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)
	})

	It("Should handle multiple adds and removes in a batch", func() {
		onUpdate("ep1", []string{"1.1.1.1", "1.1.1.2"}, nil)
		onRemove("ep1")
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		onUpdate("ep1", []string{"1.1.1.1", "1.1.1.2"}, nil)
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)
	})

	It("Should handle remove in update.", func() {
		onUpdate("ep1", []string{"1.1.1.1", "1.1.1.2"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1", "1.1.1.2"}, nil)

		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)

		// And the same in the same batch
		onUpdate("ep1", []string{"1.1.1.1", "1.1.1.2"}, nil)
		onUpdate("ep1", []string{"1.1.1.1"}, nil)
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)
	})

	It("Should should ignore ipv6 when not enabled", func() {
		onUpdate("ep1", []string{"1.1.1.1"}, []string{"0000:::::::0001"})
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify([]string{"1.1.1.1"}, nil)

		onRemove("ep1")
		Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
		verify(nil, nil)
	})

	Context("With ipv6 enabled", func() {
		BeforeEach(func() {
			cfg.IPv6Enabled = true
		})

		It("Should should handle ipv6 independently", func() {
			onUpdate("ep1", []string{"1.1.1.1"}, []string{"0000:::::::0001"})
			onUpdate("ep2", nil, []string{"0000:::::::0001"})
			Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
			verify([]string{"1.1.1.1"}, []string{"0000:::::::0001"})

			onRemove("ep1")
			Expect(c.CompleteDeferredWork()).NotTo(HaveOccurred())
			verify(nil, []string{"0000:::::::0001"})
		})
	})
})

type mockIPSet map[string]struct{}

type mockIPSets struct {
	sets map[string]mockIPSet
}

func newMockSets() *mockIPSets {
	return &mockIPSets{
		sets: make(map[string]mockIPSet),
	}
}

func (ips *mockIPSets) AddOrReplaceIPSet(meta ipsets.IPSetMetadata, members []string) {
	log.WithField("SetID", meta.SetID).Info("AddOrReplaceIPSet")
	s := make(mockIPSet)

	for _, m := range members {
		s[m] = struct{}{}
	}

	ips.sets[meta.SetID] = s
}

func (ips *mockIPSets) AddMembers(setID string, newMembers []string) {
	log.WithField("newMembers", newMembers).Info("AddMembers")
	s := ips.sets[setID]

	for _, m := range newMembers {
		s[m] = struct{}{}
	}
}

func (ips *mockIPSets) RemoveMembers(setID string, removedMembers []string) {
	log.WithField("removedMembers", removedMembers).Info("RemoveMembers")
	s := ips.sets[setID]

	for _, m := range removedMembers {
		delete(s, m)
	}
}

func (ips *mockIPSets) Verify(setID string, members []string) {
	s := ips.sets[setID]

	ExpectWithOffset(2, s).To(HaveLen(len(members)))

	for _, m := range members {
		ExpectWithOffset(2, s).To(HaveKey(m))
	}
}

func wlUpdate(id string, v4, v6 []string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			EndpointId: id,
		},
		Endpoint: &proto.WorkloadEndpoint{
			Ipv4Nets: v4,
			Ipv6Nets: v6,
		},
	}
}

func wlRemove(id string) *proto.WorkloadEndpointRemove {
	return &proto.WorkloadEndpointRemove{
		Id: &proto.WorkloadEndpointID{
			EndpointId: id,
		},
	}
}
