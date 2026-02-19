// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package cache_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/cache"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

var _ = Describe("SelectorAndLabelCache", func() {
	var dpiKey1, dpiKey2 model.Key
	var dpiSelector1, dpiSelector2 *selector.Selector
	var wepKey1, wepKey2 model.WorkloadEndpointKey
	var wepLabel1, wepLabel2 uniquelabels.Map
	var err error
	var c cache.SelectorAndLabelCache
	var onMatchStartedCount, onMatchStoppedCount int

	BeforeEach(func() {
		dpiKey1 = model.ResourceKey{Namespace: "test-dpi-ns", Name: "test-dpi-1", Kind: "DeepPacketInspection"}
		dpiKey2 = model.ResourceKey{Namespace: "test-dpi-ns", Name: "test-dpi-2", Kind: "DeepPacketInspection"}
		dpiSelector1, err = selector.Parse("label == 'a'")
		Expect(err).ShouldNot(HaveOccurred())
		dpiSelector2, err = selector.Parse("label == 'b'")
		Expect(err).ShouldNot(HaveOccurred())
		wepKey1 = model.WorkloadEndpointKey{WorkloadID: "wep1"}
		wepKey2 = model.WorkloadEndpointKey{WorkloadID: "wep2"}
		wepLabel1 = uniquelabels.Make(map[string]string{
			"label":                       "a",
			"projectcalico.org/namespace": "default",
		})
		wepLabel2 = uniquelabels.Make(map[string]string{
			"label":                       "b",
			"projectcalico.org/namespace": "default",
		})

		onMatchStartedCount = 0
		onMatchStoppedCount = 0
	})

	Context("UpdateSelector", func() {
		It("Adds the selector to the cache", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey1))
				Expect(wepKey).Should(BeEquivalentTo(wepKey1))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding first selector to cache")
			c.UpdateSelector(dpiKey1, dpiSelector1)
			Expect(onMatchStartedCount).To(Equal(0))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("Adding labels matching the selector")
			c.UpdateLabels(wepKey1, wepLabel1)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))
		})

		It("Updates the existing cached selector", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding first selector to cache")
			c.UpdateSelector(dpiKey2, dpiSelector2)
			c.UpdateLabels(wepKey2, wepLabel2)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("updating the selector to exclude previous labels")
			c.UpdateSelector(dpiKey2, dpiSelector1)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(1))

			By("updating the selector to include valid labels")
			c.UpdateSelector(dpiKey2, dpiSelector2)
			Expect(onMatchStartedCount).To(Equal(2))
			Expect(onMatchStoppedCount).To(Equal(1))
		})

		It("Handles multiple WEP that matches the selector", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeElementOf([]model.WorkloadEndpointKey{wepKey1, wepKey2}))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeElementOf([]model.WorkloadEndpointKey{wepKey1, wepKey2}))
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding multiple WEP")
			c.UpdateLabels(wepKey1, wepLabel2)
			c.UpdateLabels(wepKey2, wepLabel2)

			By("Adding selector to cache that selects all WEP")
			c.UpdateSelector(dpiKey2, dpiSelector2)
			Expect(onMatchStartedCount).To(Equal(2))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("updating the selector to exclude previous labels")
			c.UpdateSelector(dpiKey2, dpiSelector1)
			Expect(onMatchStartedCount).To(Equal(2))
			Expect(onMatchStoppedCount).To(Equal(2))

			By("updating the selector to include valid labels")
			c.UpdateSelector(dpiKey2, dpiSelector2)
			Expect(onMatchStartedCount).To(Equal(4))
			Expect(onMatchStoppedCount).To(Equal(2))
		})
	})

	Context("UpdateLabels", func() {
		It("Adds the label to the cache", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey1))
				Expect(wepKey).Should(BeEquivalentTo(wepKey1))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding first label to cache")
			c.UpdateLabels(wepKey1, wepLabel1)
			Expect(onMatchStartedCount).To(Equal(0))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("Adding selector matching the label")
			c.UpdateSelector(dpiKey1, dpiSelector1)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))
		})

		It("Updates the existing cached labels", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding first label to cache")
			c.UpdateLabels(wepKey2, wepLabel2)
			c.UpdateSelector(dpiKey2, dpiSelector2)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("updating the labels to exclude previous selector")
			c.UpdateLabels(wepKey2, wepLabel1)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(1))

			By("updating the labels to include valid selector")
			c.UpdateLabels(wepKey2, wepLabel2)
			Expect(onMatchStartedCount).To(Equal(2))
			Expect(onMatchStoppedCount).To(Equal(1))
		})

		It("Handles multiple DPI that matches the label", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeElementOf([]model.Key{dpiKey1, dpiKey2}))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
				Expect(dpiKey).Should(BeElementOf([]model.Key{dpiKey1, dpiKey2}))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding multiple DPI selectors")
			c.UpdateSelector(dpiKey1, dpiSelector2)
			c.UpdateSelector(dpiKey2, dpiSelector2)
			Expect(onMatchStartedCount).To(Equal(0))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("updating the labels to include all previous selector")
			c.UpdateLabels(wepKey2, wepLabel2)
			Expect(onMatchStartedCount).To(Equal(2))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("updating the labels to exclude all previous selector")
			c.UpdateLabels(wepKey2, wepLabel1)
			Expect(onMatchStartedCount).To(Equal(2))
			Expect(onMatchStoppedCount).To(Equal(2))

			By("updating the labels to include valid selector")
			c.UpdateLabels(wepKey2, wepLabel2)
			Expect(onMatchStartedCount).To(Equal(4))
			Expect(onMatchStoppedCount).To(Equal(2))
		})
	})

	Context("DeleteSelector", func() {
		It("Deletes the selector from cache", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding selector to cache")
			c.UpdateSelector(dpiKey2, dpiSelector2)
			c.UpdateLabels(wepKey2, wepLabel2)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("deleting non-existing selector from cache")
			c.DeleteSelector(dpiKey1)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("deleting existing selector from cache")
			c.DeleteSelector(dpiKey2)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(1))
		})
	})

	Context("DeleteLabel", func() {
		It("Deletes the label from cache", func() {
			OnMatchStarted := func(dpiKey, wepKey interface{}) {
				onMatchStartedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			OnMatchStopped := func(dpiKey, wepKey interface{}) {
				onMatchStoppedCount++
				Expect(dpiKey).Should(BeEquivalentTo(dpiKey2))
				Expect(wepKey).Should(BeEquivalentTo(wepKey2))
			}
			c = cache.NewSelectorAndLabelCache(OnMatchStarted, OnMatchStopped)

			By("Adding labels to cache")
			c.UpdateLabels(wepKey2, wepLabel2)
			c.UpdateSelector(dpiKey2, dpiSelector2)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("deleting non-existing label from cache")
			c.DeleteLabel(wepKey1)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(0))

			By("deleting existing label from cache")
			c.DeleteLabel(wepKey2)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(1))

			By("deleting existing selector from cache that has no matching label")
			c.DeleteSelector(dpiKey2)
			Expect(onMatchStartedCount).To(Equal(1))
			Expect(onMatchStoppedCount).To(Equal(1))
		})
	})
})
