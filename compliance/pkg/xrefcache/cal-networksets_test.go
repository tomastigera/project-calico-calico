// Copyright (c) 2019 Tigera, Inc. SelectAll rights reserved.
package xrefcache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/compliance/internal/testutils"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
)

var _ = Describe("Basic CRUD of network sets with no other resources present", func() {
	var tester *testutils.XrefCacheTester

	BeforeEach(func() {
		tester = testutils.NewXrefCacheTester()
		tester.OnStatusUpdate(syncer.NewStatusUpdateInSync())
	})

	// Ensure  the client resource list is in-sync with the resource helper.
	It("should handle basic CRUD and identify a network set with internet exposed", func() {
		By("applying a network set with no nets")
		tester.SetGlobalNetworkSet(testutils.Name1, testutils.NoLabels, 0)

		By("checking the cache settings")
		ns := tester.GetGlobalNetworkSet(testutils.Name1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("applying a network set with one public net")
		tester.SetGlobalNetworkSet(testutils.Name1, testutils.Label1, testutils.Public)

		By("checking the cache settings")
		ns = tester.GetGlobalNetworkSet(testutils.Name1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(Equal(xrefcache.CacheEntryInternetExposed))

		By("applying a network set with one private net")
		tester.SetGlobalNetworkSet(testutils.Name1, testutils.Label1, testutils.Private)

		By("checking the cache settings")
		ns = tester.GetGlobalNetworkSet(testutils.Name1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("applying a network set with one private and one public net")
		tester.SetGlobalNetworkSet(testutils.Name1, testutils.Label1, testutils.Public|testutils.Private)

		By("checking the cache settings")
		ns = tester.GetGlobalNetworkSet(testutils.Name1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(Equal(xrefcache.CacheEntryInternetExposed))

		By("applying another network set with no nets")
		tester.SetGlobalNetworkSet(testutils.Name2, testutils.NoLabels, 0)

		By("checking the cache settings")
		ns = tester.GetGlobalNetworkSet(testutils.Name1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(Equal(xrefcache.CacheEntryInternetExposed))
		ns = tester.GetGlobalNetworkSet(testutils.Name2)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("deleting the first network set")
		tester.DeleteGlobalNetworkSet(testutils.Name1)

		By("checking the cache settings")
		ns = tester.GetGlobalNetworkSet(testutils.Name1)
		Expect(ns).To(BeNil())
		ns = tester.GetGlobalNetworkSet(testutils.Name2)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("deleting the second network set")
		tester.DeleteGlobalNetworkSet(testutils.Name2)

		By("checking the cache settings")
		ns = tester.GetGlobalNetworkSet(testutils.Name1)
		Expect(ns).To(BeNil())
		ns = tester.GetGlobalNetworkSet(testutils.Name2)
		Expect(ns).To(BeNil())
	})

	// Ensure  the client resource list is in-sync with the resource helper.
	It("should handle basic CRUD and identify a namespaced network set with internet exposed", func() {
		By("applying a network set with no nets")
		tester.SetNetworkSet(testutils.Name1, testutils.Namespace1, testutils.NoLabels, 0)

		By("checking the cache settings")
		ns := tester.GetNetworkSet(testutils.Name1, testutils.Namespace1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("applying a namespaced network set with one public net")
		tester.SetNetworkSet(testutils.Name1, testutils.Namespace1, testutils.Label1, testutils.Public)

		By("checking the cache settings")
		ns = tester.GetNetworkSet(testutils.Name1, testutils.Namespace1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(Equal(xrefcache.CacheEntryInternetExposed))

		By("applying a network set with one private net")
		tester.SetNetworkSet(testutils.Name1, testutils.Namespace1, testutils.Label1, testutils.Private)

		By("checking the cache settings")
		ns = tester.GetNetworkSet(testutils.Name1, testutils.Namespace1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("applying a network set with one private and one public net")
		tester.SetNetworkSet(testutils.Name1, testutils.Namespace1, testutils.Label1, testutils.Public|testutils.Private)

		By("checking the cache settings")
		ns = tester.GetNetworkSet(testutils.Name1, testutils.Namespace1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(Equal(xrefcache.CacheEntryInternetExposed))

		By("applying another network set with no nets")
		tester.SetNetworkSet(testutils.Name2, testutils.Namespace1, testutils.NoLabels, 0)

		By("checking the cache settings")
		ns = tester.GetNetworkSet(testutils.Name1, testutils.Namespace1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(Equal(xrefcache.CacheEntryInternetExposed))
		ns = tester.GetNetworkSet(testutils.Name2, testutils.Namespace1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("deleting the first network set")
		tester.DeleteNetworkSet(testutils.Name1, testutils.Namespace1)

		By("checking the cache settings")
		ns = tester.GetNetworkSet(testutils.Name1, testutils.Namespace1)
		Expect(ns).To(BeNil())
		ns = tester.GetNetworkSet(testutils.Name2, testutils.Namespace1)
		Expect(ns).ToNot(BeNil())
		Expect(ns.Flags).To(BeZero())

		By("deleting the second network set")
		tester.DeleteNetworkSet(testutils.Name2, testutils.Namespace1)

		By("checking the cache settings")
		ns = tester.GetNetworkSet(testutils.Name1, testutils.Namespace1)
		Expect(ns).To(BeNil())
		ns = tester.GetNetworkSet(testutils.Name2, testutils.Namespace1)
		Expect(ns).To(BeNil())
	})
})
