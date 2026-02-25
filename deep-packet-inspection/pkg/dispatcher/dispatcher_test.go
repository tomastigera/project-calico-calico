// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package dispatcher_test

import (
	"context"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
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
		Hostname:       "127.0.0.1",
		OrchestratorID: "k8s",
		WorkloadID:     "test-dpiKey/pod1",
		EndpointID:     "eth0",
	}
	wepKey2 := model.WorkloadEndpointKey{
		Hostname:       "127.0.0.1",
		OrchestratorID: "k8s",
		WorkloadID:     "test-dpiKey/pod2",
		EndpointID:     "eth0",
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
		hndler := dispatcher.NewDispatcher(&config.Config{}, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)
		mockGenerator.On("UpdateCache", mock.Anything, mock.Anything).Return(nil)

		By("adding a new WorkLoadEndpoint doesn't call snortProcessor")
		// during Dispatch, no calls are made to porocessor as there is no matching selector
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, map[string]string{"projectcalico.org/namespace": dpiNs})

		By("adding a new DeepPacketInspection resource with WEP that has matching label")
		mockProcessor1.On("Maintain", ctx, wepKey1, ifaceName1).Return(nil).Times(1)
		mockGenerator.On("GenerateEventsForWEP", dpiKey1, wepKey1).Return(nil)
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a second DeepPacketInspection resource that selects all WEPs")
		mockProcessor2.On("Maintain", ctx, wepKey1, ifaceName1).Return(nil).Times(1)
		mockGenerator.On("GenerateEventsForWEP", dpiKey2, wepKey1).Return(nil)
		updateDPIResource(ctx, hndler, dpiKey2, dpiName1, dpiNs, "all()")

		By("update existing DeepPacketInspection resource no not select any WEPs")
		// Stops snort and removes interfaces that are no longer valid
		mockProcessor1.On("Remove", wepKey1).Return(nil).Times(1)
		mockGenerator.On("StopGeneratingEventsForWEP", dpiKey1, wepKey1).Return(nil)
		mockProcessor1.On("WEPInterfaceCount").Return(0)
		mockProcessor1.On("Close").Return(nil)
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='none'")

		By("update existing WorkLoadEndpoint resource's interface name")
		// if WEP interface changes, the old interface is removed and newer one are be added.
		mockProcessor2.On("Maintain", ctx, wepKey1, ifaceName2, mock.Anything).Return(nil).Times(1)
		mockProcessor2.On("Remove", wepKey1).Return(nil).Times(2)
		mockGenerator.On("StopGeneratingEventsForWEP", dpiKey1, wepKey1).Return(nil)
		mockProcessor2.On("WEPInterfaceCount").Return(0)
		mockProcessor2.On("Close").Return(nil)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName2, map[string]string{"projectcalico.org/namespace": dpiNs})

		By("delete WorkLoadEndpoint resource")
		deleteResource(ctx, hndler, wepKey1)
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
		hndler := dispatcher.NewDispatcher(&config.Config{}, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockGenerator.On("UpdateCache", mock.Anything, mock.Anything).Return(nil)

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that matches the DPI selector")
		mockProcessor1.On("Maintain", ctx, wepKey1, ifaceName1).Return(nil).Times(1)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, map[string]string{"projectcalico.org/namespace": dpiNs})
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
		hndler := dispatcher.NewDispatcher(&config.Config{}, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockGenerator.On("UpdateCache", mock.Anything, mock.Anything).Return(nil)

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that matches the DPI selector")
		mockProcessor1.On("Maintain", ctx, wepKey1, ifaceName1).Return(nil).Times(1)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, map[string]string{"projectcalico.org/namespace": dpiNs})

		By("deleting a DPI resource that has snort running")
		mockProcessor1.On("Remove", wepKey1).Return(nil).Times(1)
		mockProcessor1.On("WEPInterfaceCount").Return(0).Times(1)
		mockProcessor1.On("Close").Return(nil).Times(1)
		deleteResource(ctx, hndler, dpiKey1)
	})

	It("Deletes non-existing/non-cached DPI and WEP resource", func() {
		// This scenario might happen if the dpi pods starts after delete DPI/WEP resource is initiated.
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
		hndler := dispatcher.NewDispatcher(&config.Config{}, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockGenerator.On("UpdateCache", mock.Anything, mock.Anything).Return(nil)

		By("deleting a DPI resource that doesn't have a snortProcessor")
		deleteResource(ctx, hndler, dpiKey1)
		//	No calls are made to the mockProcessor
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
		hndler := dispatcher.NewDispatcher(&config.Config{}, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockGenerator.On("UpdateCache", mock.Anything, mock.Anything).Return(nil)

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that matches the DPI selector")
		mockProcessor1.On("Maintain", ctx, wepKey1, ifaceName1).Return(nil).Times(1)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, map[string]string{"projectcalico.org/namespace": dpiNs})

		By("adding another WorkLoadEndpoint that matches the DPI selector")
		mockProcessor1.On("Maintain", ctx, wepKey2, ifaceName2).Return(nil).Times(1)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName2, map[string]string{"projectcalico.org/namespace": dpiNs})

		By("deleting a DPI resource that has snort running")
		mockProcessor1.On("Remove", wepKey1).Return(nil).Times(2)
		totalCall := 2
		mockProcessor1.On("WEPInterfaceCount").Run(func(args mock.Arguments) {
			for _, c := range mockProcessor1.ExpectedCalls {
				// After the first call to "Remove" there must be one interface left and zero after second call
				totalCall--
				c.ReturnArguments = mock.Arguments{totalCall}
			}
		}).Times(2)
		mockProcessor1.On("Close").Return(nil).Times(1)
		deleteResource(ctx, hndler, wepKey1)
	})

	It("Doesn't start snort on WEP in a different namespace", func() {
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
		hndler := dispatcher.NewDispatcher(&config.Config{}, mockSnortProcessor, mockEventGenerator, nil, mockDPIUpdater, mockFileMaintainer)

		mockGenerator.On("UpdateCache", mock.Anything, mock.Anything).Return(nil)

		By("adding a new DeepPacketInspection doesn't call snortProcessor")
		updateDPIResource(ctx, hndler, dpiKey1, dpiName1, dpiNs, "k8s-app=='dpiKey'")

		By("adding a new WorkLoadEndpoint that belongs to different namespace")
		mockProcessor1.On("Maintain", ctx, wepKey1, ifaceName1).Return(nil).Times(1)
		updateWEPResource(ctx, hndler, wepKey1, ifaceName1, map[string]string{"projectcalico.org/namespace": "randomNs"})
		// No calls are made to the snortProcessor
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
