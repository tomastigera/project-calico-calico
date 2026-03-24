// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package cache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/cache"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("WEP cache", func() {
	wepKey1 := model.WorkloadEndpointKey{
		Hostname:       "node1",
		OrchestratorID: "k8s",
		WorkloadID:     "test-dpiKey/pod1",
		EndpointID:     "eth0",
	}
	wepKey2 := model.WorkloadEndpointKey{
		Hostname:       "node2",
		OrchestratorID: "k8s",
		WorkloadID:     "test-dpiKey/pod2",
		EndpointID:     "eth0",
	}

	It("should retain IPs that stay across a WEP update", func() {
		c := cache.NewWEPCache()

		By("adding WEP with two IPs")
		c.Update(bapi.UpdateTypeKVNew, model.KVPair{
			Key: wepKey1,
			Value: &model.WorkloadEndpoint{
				IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"), mustParseNet("10.0.0.2/32")},
			},
		})
		ok, _, _ := c.Get("10.0.0.1")
		Expect(ok).Should(BeTrue())
		ok, _, _ = c.Get("10.0.0.2")
		Expect(ok).Should(BeTrue())

		By("updating WEP: keep first IP, replace second")
		c.Update(bapi.UpdateTypeKVUpdated, model.KVPair{
			Key: wepKey1,
			Value: &model.WorkloadEndpoint{
				IPv4Nets: []net.IPNet{mustParseNet("10.0.0.1/32"), mustParseNet("10.0.0.3/32")},
			},
		})
		ok, _, _ = c.Get("10.0.0.1")
		Expect(ok).Should(BeTrue(), "retained IP should still be resolvable")
		ok, _, _ = c.Get("10.0.0.3")
		Expect(ok).Should(BeTrue(), "new IP should be resolvable")
		ok, _, _ = c.Get("10.0.0.2")
		Expect(ok).Should(BeFalse(), "removed IP should no longer be resolvable")
	})

	It("should add/update/delete cached WEP and its IP", func() {
		c := cache.NewWEPCache()

		By("adding WEP to cache")
		c.Update(bapi.UpdateTypeKVNew, model.KVPair{
			Key: wepKey1,
			Value: &model.WorkloadEndpoint{
				IPv4Nets: []net.IPNet{mustParseNet("10.28.0.13/32")},
			},
		})
		ok, podName, ns := c.Get("10.28.0.13")
		Expect(ok).Should(BeTrue())
		Expect(podName).Should(Equal("pod1"))
		Expect(ns).Should(Equal("test-dpiKey"))

		c.Update(bapi.UpdateTypeKVNew, model.KVPair{
			Key: wepKey2,
			Value: &model.WorkloadEndpoint{
				IPv4Nets: []net.IPNet{mustParseNet("6.6.6.6/32")},
			},
		})
		ok, podName, ns = c.Get("6.6.6.6")
		Expect(ok).Should(BeTrue())
		Expect(podName).Should(Equal("pod2"))
		Expect(ns).Should(Equal("test-dpiKey"))

		By("updating WEP to cache")
		c.Update(bapi.UpdateTypeKVUpdated, model.KVPair{
			Key: wepKey1,
			Value: &model.WorkloadEndpoint{
				IPv4Nets: []net.IPNet{mustParseNet("10.30.30.30/32")},
			},
		})
		ok, podName, ns = c.Get("10.30.30.30")
		Expect(ok).Should(BeTrue())
		Expect(podName).Should(BeEquivalentTo("pod1"))
		Expect(ns).Should(BeEquivalentTo("test-dpiKey"))

		ok, _, _ = c.Get("10.28.0.13")
		Expect(ok).Should(BeFalse())

		By("deleting WEP from cache")
		c.Update(bapi.UpdateTypeKVDeleted, model.KVPair{Key: wepKey1})
		c.Update(bapi.UpdateTypeKVDeleted, model.KVPair{Key: wepKey2})
		ok, _, _ = c.Get("6.6.6.6")
		Expect(ok).Should(BeFalse())
		ok, _, _ = c.Get("10.30.30.30")
		Expect(ok).Should(BeFalse())
	})

})

func mustParseNet(n string) net.IPNet {
	_, cidr, err := net.ParseCIDR(n)
	Expect(err).ShouldNot(HaveOccurred())
	return *cidr
}
