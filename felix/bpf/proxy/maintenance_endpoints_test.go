// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package proxy_test

import (
	"net/netip"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/felix/bpf/proxy"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/lib/std/ptr"
)

func makeDiscoveryEndpointSlice(namespace, svcName, sliceName string, endpoints ...discovery.Endpoint) *discovery.EndpointSlice {
	return &discovery.EndpointSlice{
		TypeMeta: metav1.TypeMeta{
			Kind:       "EndpointSlice",
			APIVersion: "discovery.k8s.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      sliceName,
			Namespace: namespace,
			Labels: map[string]string{
				discovery.LabelServiceName: svcName,
			},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints:   endpoints,
	}
}

func makeDiscoveryEndpoint(ip string, nodeName *string) discovery.Endpoint {
	return discovery.Endpoint{
		Addresses: []string{ip},
		NodeName:  nodeName,
	}
}

func hostMeta(hostname string, maintenance proto.LoadbalancerMaintenance) *proto.HostMetadataV4V6Update {
	return &proto.HostMetadataV4V6Update{
		Hostname:                hostname,
		LoadbalancerMaintenance: maintenance,
	}
}

var _ = Describe("MaintenanceEndpoints", func() {

	var (
		epTracker              *proxy.EndpointTracker
		hostMetadataByHostname map[string]*proto.HostMetadataV4V6Update
		me                     *proxy.MaintenanceEndpoints
	)

	BeforeEach(func() {
		epTracker = proxy.NewEndpointTracker()
		hostMetadataByHostname = make(map[string]*proto.HostMetadataV4V6Update)
		me = proxy.NewMaintenanceEndpoints()
	})

	Context("with no endpoints and no host metadata", func() {
		It("should produce an empty MaintenanceEndpoints set", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(0))
		})
	})

	Context("with endpoints but no maintenance annotation", func() {
		BeforeEach(func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
				makeDiscoveryEndpoint("10.0.0.2", ptr.ToPtr("node-b")),
			)
			epTracker.EndpointSliceUpdate(eps, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_NONE)
			hostMetadataByHostname["node-b"] = hostMeta("node-b", proto.LoadbalancerMaintenance_LB_MAINT_NONE)
		})

		It("should produce an empty MaintenanceEndpoints set", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(0))
		})
	})

	Context("with one node under maintenance", func() {
		BeforeEach(func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
				makeDiscoveryEndpoint("10.0.0.2", ptr.ToPtr("node-b")),
			)
			epTracker.EndpointSliceUpdate(eps, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
			hostMetadataByHostname["node-b"] = hostMeta("node-b", proto.LoadbalancerMaintenance_LB_MAINT_NONE)
		})

		It("should mark only the endpoint on the maintenance node", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(1))

			key := proxy.MaintenanceEndpointKey{
				ServiceName:  types.NamespacedName{Namespace: "default", Name: "my-svc"},
				EndpointAddr: netip.MustParseAddr("10.0.0.1"),
			}
			Expect(me.Contains(key)).To(BeTrue())
		})

		It("should not mark the endpoint on the healthy node", func() {
			me.Update(hostMetadataByHostname, epTracker)

			key := proxy.MaintenanceEndpointKey{
				ServiceName:  types.NamespacedName{Namespace: "default", Name: "my-svc"},
				EndpointAddr: netip.MustParseAddr("10.0.0.2"),
			}
			Expect(me.Contains(key)).To(BeFalse())
		})
	})

	Context("with all nodes under maintenance", func() {
		BeforeEach(func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
				makeDiscoveryEndpoint("10.0.0.2", ptr.ToPtr("node-b")),
			)
			epTracker.EndpointSliceUpdate(eps, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
			hostMetadataByHostname["node-b"] = hostMeta("node-b", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
		})

		It("should mark all endpoints", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(2))
		})
	})

	Context("with multiple services on the same maintenance node", func() {
		BeforeEach(func() {
			eps1 := makeDiscoveryEndpointSlice("default", "svc-a", "svc-a-slice",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
			)
			eps2 := makeDiscoveryEndpointSlice("default", "svc-b", "svc-b-slice",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
			)
			epTracker.EndpointSliceUpdate(eps1, false)
			epTracker.EndpointSliceUpdate(eps2, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
		})

		It("should mark endpoints for both services independently", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(2))

			keyA := proxy.MaintenanceEndpointKey{
				ServiceName:  types.NamespacedName{Namespace: "default", Name: "svc-a"},
				EndpointAddr: netip.MustParseAddr("10.0.0.1"),
			}
			keyB := proxy.MaintenanceEndpointKey{
				ServiceName:  types.NamespacedName{Namespace: "default", Name: "svc-b"},
				EndpointAddr: netip.MustParseAddr("10.0.0.1"),
			}
			Expect(me.Contains(keyA)).To(BeTrue())
			Expect(me.Contains(keyB)).To(BeTrue())
		})
	})

	Context("with an endpoint that has no NodeName", func() {
		BeforeEach(func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				makeDiscoveryEndpoint("10.0.0.1", nil), // no node name
			)
			epTracker.EndpointSliceUpdate(eps, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
		})

		It("should not mark the endpoint", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(0))
		})
	})

	Context("with an endpoint whose node has no host metadata", func() {
		BeforeEach(func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("unknown-node")),
			)
			epTracker.EndpointSliceUpdate(eps, false)
			// hostMetadataByHostname deliberately has no entry for "unknown-node"
		})

		It("should not mark the endpoint", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(0))
		})
	})

	Context("with an endpoint with no addresses", func() {
		BeforeEach(func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				discovery.Endpoint{
					NodeName: ptr.ToPtr("node-a"),
				},
			)
			epTracker.EndpointSliceUpdate(eps, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
		})

		It("should skip the endpoint without error", func() {
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(0))
		})
	})

	Context("when an endpoint slice is removed from the tracker", func() {
		It("should no longer include endpoints in the maintenance set", func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
				makeDiscoveryEndpoint("10.0.0.2", ptr.ToPtr("node-b")),
			)
			epTracker.EndpointSliceUpdate(eps, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
			hostMetadataByHostname["node-b"] = hostMeta("node-b", proto.LoadbalancerMaintenance_LB_MAINT_NONE)

			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(1))

			// Remove the endpoint slice from the tracker.
			epTracker.EndpointSliceUpdate(eps, true)

			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(0))
		})

		It("should only remove the targeted slice when multiple slices exist", func() {
			eps1 := makeDiscoveryEndpointSlice("default", "svc-a", "svc-a-slice",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
			)
			eps2 := makeDiscoveryEndpointSlice("default", "svc-b", "svc-b-slice",
				makeDiscoveryEndpoint("10.0.0.2", ptr.ToPtr("node-a")),
			)
			epTracker.EndpointSliceUpdate(eps1, false)
			epTracker.EndpointSliceUpdate(eps2, false)

			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)

			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(2))

			// Remove only the first slice.
			epTracker.EndpointSliceUpdate(eps1, true)

			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(1))

			key, _ := proxy.NewMaintenanceEndpointKey(types.NamespacedName{Namespace: "default", Name: "svc-a"}, "10.0.0.1")
			Expect(me.Contains(key)).To(BeFalse(), "Removed slice's endpoint should no longer be in the maintenance set")

			key, _ = proxy.NewMaintenanceEndpointKey(types.NamespacedName{Namespace: "default", Name: "svc-b"}, "10.0.0.2")
			Expect(me.Contains(key)).To(BeTrue(), "Remaining slice's endpoint should still be in the maintenance set")
		})
	})

	Context("re-update clears stale entries", func() {
		BeforeEach(func() {
			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_EXCLUDE_LOCAL_BACKENDS)
			hostMetadataByHostname["node-b"] = hostMeta("node-b", proto.LoadbalancerMaintenance_LB_MAINT_NONE)
		})

		It("should reflect the latest state after each Update call", func() {
			eps := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a")),
			)
			epTracker.EndpointSliceUpdate(eps, false)

			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(1))

			// Node comes out of maintenance.
			hostMetadataByHostname["node-a"] = hostMeta("node-a", proto.LoadbalancerMaintenance_LB_MAINT_NONE)
			me.Update(hostMetadataByHostname, epTracker)
			Expect(me.Len()).To(Equal(0))
		})

		It("should remain consistent when an endpoint moves from one service to another", func() {
			ep := makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a"))
			ep2 := makeDiscoveryEndpoint("10.0.0.2", ptr.ToPtr("node-b"))

			slice1 := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				ep,
				ep2,
			)
			epTracker.EndpointSliceUpdate(slice1, false)

			me.Update(hostMetadataByHostname, epTracker)
			expectedKey, _ := proxy.NewMaintenanceEndpointKey(types.NamespacedName{Namespace: "default", Name: "my-svc"}, "10.0.0.1")
			Expect(me.Slice()).To(ContainElement(expectedKey))
			Expect(me.Len()).To(Equal(1))

			// ep leaves slice 1.
			updatedSlice1 := makeDiscoveryEndpointSlice("default", "my-svc", "my-svc-abc",
				ep2,
			)
			// ... and is now matched to slice2.
			slice2 := makeDiscoveryEndpointSlice("default", "my-other-svc", "my-other-svc-abc",
				ep,
			)
			epTracker.EndpointSliceUpdate(slice2, false)
			epTracker.EndpointSliceUpdate(updatedSlice1, false)
			me.Update(hostMetadataByHostname, epTracker)

			expectedKey, _ = proxy.NewMaintenanceEndpointKey(types.NamespacedName{Namespace: "default", Name: "my-other-svc"}, "10.0.0.1")
			staleKey, _ := proxy.NewMaintenanceEndpointKey(types.NamespacedName{Namespace: "default", Name: "my-svc"}, "10.0.0.1")
			Expect(me.Slice()).To(ContainElement(expectedKey), "Maintenance Endpoints should contain the latest information about an endpoint which moved service")
			Expect(me.Slice()).NotTo(ContainElement(staleKey), "Maintenance Endpoints should not contain the stale information about an endpoint which moved service")
		})

		It("should adjust maintenance endpoints when an endpoint moves node", func() {
			ep := makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-a"))
			ep2 := makeDiscoveryEndpoint("10.0.0.2", ptr.ToPtr("node-b"))

			slice1 := makeDiscoveryEndpointSlice("default", "my-svc", "slice1",
				ep,
				ep2,
			)
			epTracker.EndpointSliceUpdate(slice1, false)

			me.Update(hostMetadataByHostname, epTracker)
			expectedKey, _ := proxy.NewMaintenanceEndpointKey(types.NamespacedName{Namespace: "default", Name: "my-svc"}, "10.0.0.1")
			Expect(me.Slice()).To(ContainElement(expectedKey))

			// ep leaves node-a and goes to node-b.
			ep = makeDiscoveryEndpoint("10.0.0.1", ptr.ToPtr("node-b"))
			slice1 = makeDiscoveryEndpointSlice("default", "my-svc", "slice1",
				ep,
				ep2,
			)

			epTracker.EndpointSliceUpdate(slice1, false)
			me.Update(hostMetadataByHostname, epTracker)

			staleKey, _ := proxy.NewMaintenanceEndpointKey(types.NamespacedName{Namespace: "default", Name: "my-svc"}, "10.0.0.1")
			Expect(me.Slice()).NotTo(ContainElement(expectedKey), "Maintenance Endpoints should contain the latest information about an endpoint which moved node")
			Expect(me.Slice()).NotTo(ContainElement(staleKey), "Maintenance Endpoints should not contain the stale information about an endpoint which moved node")
		})
	})
})
