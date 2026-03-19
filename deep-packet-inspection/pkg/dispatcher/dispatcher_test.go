// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package dispatcher_test

import (
	"context"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/alert"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/cache"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/config"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/dispatcher"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/dpiupdater"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/eventgenerator"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/exec"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/file"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/processor"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const nodeName = "127.0.0.1"

var _ = Describe("Resource Dispatcher", func() {
	dpiName1 := "dpiKey-test-1"
	dpiName2 := "dpiKey-test-2"
	dpiNs := "test-ns"
	ifaceName1 := "wepKey1-iface"
	ifaceName2 := "random-califace"
	dpiKey1 := model.ResourceKey{
		Name:      dpiName1,
		Namespace: dpiNs,
		Kind:      "DeepPacketInspection",
	}
	dpiKey2 := model.ResourceKey{
		Name:      dpiName2,
		Namespace: dpiNs,
		Kind:      "DeepPacketInspection",
	}
	wepKey1 := model.WorkloadEndpointKey{
		Hostname:       nodeName,
		OrchestratorID: "k8s",
		WorkloadID:     "test-dpiKey/pod1",
		EndpointID:     "eth0",
	}
	// matchingLabels satisfies both the namespace selector appended by the dispatcher
	// and the k8s-app=='dpiKey' selector used in several tests.
	matchingLabels := map[string]string{
		"projectcalico.org/namespace": dpiNs,
		"k8s-app":                     "dpiKey",
	}

	It("Adds, updates and deletes DPI and WEP resource", func() {
		mockProcessor1 := &processor.MockProcessor{}
		mockProcessor2 := &processor.MockProcessor{}
		mockDPIUpdater := &dpiupdater.MockDPIStatusUpdater{}
		mockFileMaintainer := &file.MockFileMaintainer{}
		mockSnortProcessor := func(ctx context.Context, dpiKey model.ResourceKey, nodeName string, snortExecFn exec.Snort, snortAlertFileBasePath string, snortAlertFileSize int, dpiUpdater dpiupdater.DPIStatusUpdater) processor.Processor {
			if reflect.DeepEqual(dpiKey, dpiKey1) {
				return mockProcessor1
			}
			return mockProcessor2
		}

		mockGenerator := &eventgenerator.MockEventGenerator{}
		mockEventGenerator := func(cfg *config.Config,
			esForwarder alert.Forwarder,
			dpiUpdater dpiupdater.DPIStatusUpdater,
			dpiKey model.ResourceKey,
			wepCache cache.WEPCache) eventgenerator.EventGenerator {
			return mockGenerator
		}

		ctx := context.Background()
		cfg := &config.Config{NodeName: nodeName}
		hndler := dispatcher.NewDispatcher(cfg, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		// Allow alertFileMaintainer calls throughout — exact paths are implementation details.
		mockFileMaintainer.On("Maintain", mock.Anything).Return().Maybe()
		mockFileMaintainer.On("Stop", mock.Anything).Return().Maybe()

		By("adding a new WorkLoadEndpoint doesn't call snortProcessor")
		// No DPI selectors registered yet, so no match callbacks fire.
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, matchingLabels)

		By("adding a new DeepPacketInspection resource with WEP that has matching label")
		// DPI1 selector matches wepKey1 → startDPIOnWEP
		mockProcessor1.On("Add", ctx, wepKey1, ifaceName1).Return().Times(1)
		mockGenerator.On("GenerateEventsForWEP", wepKey1).Return().Maybe()
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Add", ctx, wepKey1, ifaceName1)).To(BeTrue())

		By("adding a second DeepPacketInspection resource that selects all WEPs")
		// DPI2 selector all() also matches wepKey1 → startDPIOnWEP
		mockProcessor2.On("Add", ctx, wepKey1, ifaceName1).Return().Times(1)
		updateDPIResource(ctx, hndler, dpiKey2, dpiName2, dpiNs, "all()")
		Expect(mockProcessor2.AssertCalled(GinkgoT(), "Add", ctx, wepKey1, ifaceName1)).To(BeTrue())

		By("update existing DeepPacketInspection resource to not select any WEPs")
		// DPI1 selector changes to k8s-app=='none' → match stops → stopDPIOnWEP
		mockProcessor1.On("Remove", wepKey1).Return().Times(1)
		mockGenerator.On("StopGeneratingEventsForWEP", wepKey1).Return().Maybe()
		mockProcessor1.On("WEPInterfaceCount").Return(0).Maybe()
		mockProcessor1.On("Close").Return().Times(1)
		mockGenerator.On("Close").Return().Maybe()
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='none'")
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Remove", wepKey1)).To(BeTrue())
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Close")).To(BeTrue())

		By("update existing WorkLoadEndpoint resource's interface name")
		// Interface changes → ifaceUpdated → stop DPI2 on old iface, restart on new iface
		mockProcessor2.On("Remove", wepKey1).Return().Maybe()
		mockProcessor2.On("Add", ctx, wepKey1, ifaceName2).Return().Times(1)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName2, matchingLabels)
		Expect(mockProcessor2.AssertCalled(GinkgoT(), "Add", ctx, wepKey1, ifaceName2)).To(BeTrue())

		By("delete WorkLoadEndpoint resource")
		// WEP deleted → match stops for DPI2 → stopDPIOnWEP → stopDPI
		mockProcessor2.On("WEPInterfaceCount").Return(0).Maybe()
		mockProcessor2.On("Close").Return().Times(1)
		deleteResource(ctx, hndler, wepKey1)
		Expect(mockProcessor2.AssertCalled(GinkgoT(), "Close")).To(BeTrue())
	})

	It("Adds DPI resource before WEP resource", func() {
		mockProcessor1 := &processor.MockProcessor{}
		mockDPIUpdater := &dpiupdater.MockDPIStatusUpdater{}
		mockFileMaintainer := &file.MockFileMaintainer{}
		mockGenerator := &eventgenerator.MockEventGenerator{}
		mockEventGenerator := func(cfg *config.Config,
			esForwarder alert.Forwarder,
			dpiUpdater dpiupdater.DPIStatusUpdater,
			dpiKey model.ResourceKey,
			wepCache cache.WEPCache) eventgenerator.EventGenerator {
			return mockGenerator
		}
		mockSnortProcessor := func(ctx context.Context, dpiKey model.ResourceKey, nodeName string, snortExecFn exec.Snort, snortAlertFileBasePath string, snortAlertFileSize int, dpiUpdater dpiupdater.DPIStatusUpdater) processor.Processor {
			return mockProcessor1
		}
		ctx := context.Background()
		cfg := &config.Config{NodeName: nodeName}
		hndler := dispatcher.NewDispatcher(cfg, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockFileMaintainer.On("Maintain", mock.Anything).Return().Maybe()
		mockFileMaintainer.On("Stop", mock.Anything).Return().Maybe()

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that matches the DPI selector")
		mockProcessor1.On("Add", ctx, wepKey1, ifaceName1).Return().Times(1)
		mockGenerator.On("GenerateEventsForWEP", wepKey1).Return().Maybe()
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, matchingLabels)
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Add", ctx, wepKey1, ifaceName1)).To(BeTrue())
	})

	It("Deletes DPI resource before WEP resource", func() {
		mockProcessor1 := &processor.MockProcessor{}
		mockDPIUpdater := &dpiupdater.MockDPIStatusUpdater{}
		mockFileMaintainer := &file.MockFileMaintainer{}
		mockGenerator := &eventgenerator.MockEventGenerator{}
		mockEventGenerator := func(cfg *config.Config,
			esForwarder alert.Forwarder,
			dpiUpdater dpiupdater.DPIStatusUpdater,
			dpiKey model.ResourceKey,
			wepCache cache.WEPCache) eventgenerator.EventGenerator {
			return mockGenerator
		}

		mockSnortProcessor := func(ctx context.Context, dpiKey model.ResourceKey, nodeName string, snortExecFn exec.Snort, snortAlertFileBasePath string, snortAlertFileSize int, dpiUpdater dpiupdater.DPIStatusUpdater) processor.Processor {
			return mockProcessor1
		}
		ctx := context.Background()
		cfg := &config.Config{NodeName: nodeName}
		hndler := dispatcher.NewDispatcher(cfg, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockFileMaintainer.On("Maintain", mock.Anything).Return().Maybe()
		mockFileMaintainer.On("Stop", mock.Anything).Return().Maybe()

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that matches the DPI selector")
		mockProcessor1.On("Add", ctx, wepKey1, ifaceName1).Return().Times(1)
		mockGenerator.On("GenerateEventsForWEP", wepKey1).Return().Maybe()
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, matchingLabels)

		By("deleting a DPI resource that has snort running")
		mockProcessor1.On("Remove", wepKey1).Return().Times(1)
		mockGenerator.On("StopGeneratingEventsForWEP", wepKey1).Return().Maybe()
		mockProcessor1.On("WEPInterfaceCount").Return(0).Times(1)
		mockProcessor1.On("Close").Return().Times(1)
		mockGenerator.On("Close").Return().Maybe()
		deleteResource(ctx, hndler, dpiKey1)
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Remove", wepKey1)).To(BeTrue())
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Close")).To(BeTrue())
	})

	It("Deletes non-existing/non-cached DPI and WEP resource", func() {
		// This scenario might happen if the dpi pods starts after delete DPI/WEP resource is initiated.
		mockDPIUpdater := &dpiupdater.MockDPIStatusUpdater{}
		mockFileMaintainer := &file.MockFileMaintainer{}
		mockGenerator := &eventgenerator.MockEventGenerator{}
		mockEventGenerator := func(cfg *config.Config,
			esForwarder alert.Forwarder,
			dpiUpdater dpiupdater.DPIStatusUpdater,
			dpiKey model.ResourceKey,
			wepCache cache.WEPCache) eventgenerator.EventGenerator {
			return mockGenerator
		}

		mockSnortProcessor := func(ctx context.Context, dpiKey model.ResourceKey, nodeName string, snortExecFn exec.Snort, snortAlertFileBasePath string, snortAlertFileSize int, dpiUpdater dpiupdater.DPIStatusUpdater) processor.Processor {
			return &processor.MockProcessor{}
		}
		ctx := context.Background()
		cfg := &config.Config{NodeName: nodeName}
		hndler := dispatcher.NewDispatcher(cfg, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		By("deleting a DPI resource that doesn't have a snortProcessor")
		deleteResource(ctx, hndler, dpiKey1)
		// No calls are made to the mockProcessor
	})

	It("Deletes and adds the same DPI and WEP resource", func() {
		mockProcessor1 := &processor.MockProcessor{}
		mockDPIUpdater := &dpiupdater.MockDPIStatusUpdater{}
		mockFileMaintainer := &file.MockFileMaintainer{}
		mockGenerator := &eventgenerator.MockEventGenerator{}
		mockEventGenerator := func(cfg *config.Config,
			esForwarder alert.Forwarder,
			dpiUpdater dpiupdater.DPIStatusUpdater,
			dpiKey model.ResourceKey,
			wepCache cache.WEPCache) eventgenerator.EventGenerator {
			return mockGenerator
		}

		mockSnortProcessor := func(ctx context.Context, dpiKey model.ResourceKey, nodeName string, snortExecFn exec.Snort, snortAlertFileBasePath string, snortAlertFileSize int, dpiUpdater dpiupdater.DPIStatusUpdater) processor.Processor {
			return mockProcessor1
		}
		ctx := context.Background()
		cfg := &config.Config{NodeName: nodeName}
		hndler := dispatcher.NewDispatcher(cfg, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockFileMaintainer.On("Maintain", mock.Anything).Return().Maybe()
		mockFileMaintainer.On("Stop", mock.Anything).Return().Maybe()

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that matches the DPI selector")
		mockProcessor1.On("Add", ctx, wepKey1, ifaceName1).Return().Times(1)
		mockGenerator.On("GenerateEventsForWEP", wepKey1).Return().Maybe()
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, matchingLabels)

		By("updating the same WorkLoadEndpoint with a new interface")
		// wepKey1 interface changes from ifaceName1 → ifaceName2 → stop + restart
		mockProcessor1.On("Remove", wepKey1).Return().Maybe()
		mockGenerator.On("StopGeneratingEventsForWEP", wepKey1).Return().Maybe()
		mockProcessor1.On("Add", ctx, wepKey1, ifaceName2).Return().Times(1)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName2, matchingLabels)
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Add", ctx, wepKey1, ifaceName2)).To(BeTrue())

		By("deleting the WorkLoadEndpoint resource")
		mockProcessor1.On("WEPInterfaceCount").Return(0).Maybe()
		mockProcessor1.On("Close").Return().Times(1)
		mockGenerator.On("Close").Return().Maybe()
		deleteResource(ctx, hndler, wepKey1)
		Expect(mockProcessor1.AssertCalled(GinkgoT(), "Close")).To(BeTrue())
	})

	It("Doesn't start snort on WEP in a different namespace", func() {
		mockDPIUpdater := &dpiupdater.MockDPIStatusUpdater{}
		mockFileMaintainer := &file.MockFileMaintainer{}
		mockGenerator := &eventgenerator.MockEventGenerator{}
		mockEventGenerator := func(cfg *config.Config,
			esForwarder alert.Forwarder,
			dpiUpdater dpiupdater.DPIStatusUpdater,
			dpiKey model.ResourceKey,
			wepCache cache.WEPCache) eventgenerator.EventGenerator {
			return mockGenerator
		}

		mockSnortProcessor := func(ctx context.Context, dpiKey model.ResourceKey, nodeName string, snortExecFn exec.Snort, snortAlertFileBasePath string, snortAlertFileSize int, dpiUpdater dpiupdater.DPIStatusUpdater) processor.Processor {
			return &processor.MockProcessor{}
		}
		ctx := context.Background()
		cfg := &config.Config{NodeName: nodeName}
		hndler := dispatcher.NewDispatcher(cfg, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that belongs to different namespace")
		// WEP has the wrong namespace, so the combined DPI selector does not match.
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, map[string]string{"projectcalico.org/namespace": "randomNs"})
		// No calls are made to the snortProcessor or event generator.
	})

})

func deleteResource(ctx context.Context, hndler dispatcher.Dispatcher, key model.Key) {
	hndler.Dispatch(ctx, []dispatcher.CacheRequest{
		{
			UpdateType: bapi.UpdateTypeKVDeleted,
			KVPair: model.KVPair{
				Key: key,
			},
		},
	})
}

func updateWEPResource(ctx context.Context, hndler dispatcher.Dispatcher, wepKey model.WorkloadEndpointKey, ifaceName string, labels map[string]string) {
	hndler.Dispatch(ctx, []dispatcher.CacheRequest{
		{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key: wepKey,
				Value: &model.WorkloadEndpoint{
					Name:   ifaceName,
					Labels: uniquelabels.Make(labels),
				},
			},
		},
	})
}

func updateDPIResource(ctx context.Context, hndler dispatcher.Dispatcher, dpiKey1 model.ResourceKey, dpiName string, ns string, selector string) {
	hndler.Dispatch(ctx, []dispatcher.CacheRequest{
		{
			UpdateType: bapi.UpdateTypeKVNew,
			KVPair: model.KVPair{
				Key: dpiKey1,
				Value: &v3.DeepPacketInspection{
					ObjectMeta: metav1.ObjectMeta{Name: dpiName, Namespace: ns},
					Spec:       v3.DeepPacketInspectionSpec{Selector: selector},
				},
			},
		},
	})
}
