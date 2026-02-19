// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.

package intdataplane

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/calico/felix/capture"
	"github.com/projectcalico/calico/felix/ifacemonitor"
	"github.com/projectcalico/calico/felix/proto"
)

// Mocked Captures
type myMockedCaptures struct {
	mock.Mock
}

func (m *myMockedCaptures) Contains(key capture.Key) (bool, capture.Specification) {
	args := m.Called(key)
	return args.Bool(0), args.Get(1).(capture.Specification)
}

func (m *myMockedCaptures) Remove(key capture.Key) capture.Specification {
	args := m.Called(key)
	return args.Get(0).(capture.Specification)
}

func (m *myMockedCaptures) RemoveAndClean(key capture.Key) (capture.Specification, error) {
	args := m.Called(key)
	return args.Get(0).(capture.Specification), args.Error(1)
}

func (m *myMockedCaptures) Add(key capture.Key, spec capture.Specification) error {
	args := m.Called(key, spec)
	return args.Error(0)
}

var _ = Describe("PacketCapture Manager", func() {
	type output struct {
		key                    capture.Key
		specification          capture.Specification
		err                    error
		shouldCheckForContains bool
		wasPreviouslyAdded     bool
	}

	emptySpecification := &proto.PacketCaptureSpecification{
		StartTime: timestamppb.New(time.Time{}),
		EndTime:   timestamppb.New(time.Time{}),
	}

	DescribeTable("Buffers packet captures until interfaces are up",
		func(updateBatches [][]interface{}, expectedAdditions []output, expectedRemovals []output, expectedRemovalsAndClean []output) {
			var mockedCaptures = myMockedCaptures{}

			// Mock Add to return the expectedAdditions output
			// We expect Add to be called only with these values
			var expectedContainsCalls = 0
			for _, v := range expectedAdditions {
				if v.shouldCheckForContains {
					expectedContainsCalls++
					mockedCaptures.On("Contains", v.key).Return(v.wasPreviouslyAdded, v.specification).Once()
				}
				mockedCaptures.On("Add", v.key, v.specification).Return(v.err)
			}
			// Mock Removal to return the expectedRemovals output
			// We expect Removal to be called only with these values
			for _, v := range expectedRemovals {
				mockedCaptures.On("Remove", v.key).Return(v.specification)
			}

			// Mock RemovalAndClean to return the expectedRemovalsAndClean output
			// We expect RemovalAndClean to be called only with these values
			for _, v := range expectedRemovalsAndClean {
				mockedCaptures.On("RemoveAndClean", v.key).Return(v.specification, v.err)
			}

			var captureMgr = newCaptureManager(&mockedCaptures, []string{"cali"})

			// Feed updateBatches
			for _, batch := range updateBatches {
				for _, update := range batch {
					captureMgr.OnUpdate(update)
				}
				// Call CompleteDeferredWork to produce an output
				// for each processing batch
				_ = captureMgr.CompleteDeferredWork()
			}

			mockedCaptures.AssertNumberOfCalls(GinkgoT(), "Add", len(expectedAdditions))
			mockedCaptures.AssertNumberOfCalls(GinkgoT(), "Contains", expectedContainsCalls)
			mockedCaptures.AssertNumberOfCalls(GinkgoT(), "Remove", len(expectedRemovals))
			mockedCaptures.AssertExpectations(GinkgoT())
		},
		Entry("1 capture after endpoints and interfaces are up", [][]interface{}{
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
		}, []output{
			// Expect packet capture to start
			{
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
		}, []output{}, []output{}),
		Entry("1 capture before interfaces and endpoints are up", [][]interface{}{
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
		}, []output{}, []output{}),
		Entry("1 capture before endpoints and interfaces are up", [][]interface{}{
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
			{
				// Expect the second call to start to error out
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture", WorkloadEndpointId: "default/sample-pod",
				},
				specification: capture.Specification{DeviceName: "cali123"},
				err:           fmt.Errorf("cannot start twice"),
			},
		}, []output{}, []output{}),
		Entry("multiple captures for different endpoints", [][]interface{}{
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod-1",
					},
					Specification: emptySpecification,
				},
			},
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-2",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod-2",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod-1",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali456",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod-2",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali456",
					},
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod-1",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-2", WorkloadEndpointId: "default/sample-pod-2",
				},
				specification:          capture.Specification{DeviceName: "cali456"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
		}, []output{}, []output{}),
		Entry("overlapping captures for the same endpoint", [][]interface{}{
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-2",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
			},
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-2", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
		}, []output{}, []output{}),
		Entry("start/stop for the same endpoint", [][]interface{}{
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// capture removal will be processed in a single batch
				&proto.PacketCaptureRemove{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
		}, []output{}, []output{
			{
				// Expect packet capture to stop and clean
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				err: nil,
			},
		}),
		Entry("matches only cali interfaces", [][]interface{}{
			{
				// all updates will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
				&ifaceStateUpdate{
					Name:  "eth0",
					State: ifacemonitor.StateUp,
				},
				&ifaceStateUpdate{
					Name:  "lo",
					State: ifacemonitor.StateUp,
				},
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
			{
				// Expect call to start to error out
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification: capture.Specification{DeviceName: "cali123"},
				err:           fmt.Errorf("cannot start twice"),
			},
		}, []output{}, []output{}),
		Entry("interface down stops a capture", [][]interface{}{
			{
				// wep update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateDown,
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
		}, []output{
			{
				// Expect packet capture to stop
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification: capture.Specification{DeviceName: "cali123"},
				err:           nil,
			},
		}, []output{}),
		Entry("interface deleted stops a capture", [][]interface{}{
			{
				// wep update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateNotPresent,
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
		}, []output{
			{
				// Expect packet capture to stop
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification: capture.Specification{DeviceName: "cali123"},
				err:           nil,
			},
		}, []output{}),
		Entry("start after an interface went down", [][]interface{}{
			{
				// wep update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateDown,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification: capture.Specification{DeviceName: "cali123"},
				err:           nil,
			},
		}, []output{
			{
				// Expect packet capture to stop
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture-1", WorkloadEndpointId: "default/sample-pod",
				},
				specification: capture.Specification{DeviceName: "cali123"},
				err:           nil,
			},
		}, []output{}),
		Entry("start/stop for the same endpoint in the same batch does not produce output", [][]interface{}{
			{
				// all updates will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
				&proto.PacketCaptureRemove{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
				},
			},
		}, []output{}, []output{}, []output{}),
		Entry("interface up/down in the same batch does not produce output", [][]interface{}{
			{
				// all updates will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture-1",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateDown,
				},
			},
		}, []output{}, []output{}, []output{}),
		Entry("1 capture update after the capture started", [][]interface{}{
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: emptySpecification,
				},
			},
			{
				// interface update will be processed in a single batch
				&ifaceStateUpdate{
					Name:  "cali123",
					State: ifacemonitor.StateUp,
				},
			},
			{
				// wep update will be processed in a single batch
				&proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Endpoint: &proto.WorkloadEndpoint{
						State: "up",
						Name:  "cali123",
					},
				},
			},
			{
				// capture update will be processed in a single batch
				&proto.PacketCaptureUpdate{
					Id: &proto.PacketCaptureID{
						Name:      "packet-capture",
						Namespace: "default",
					},
					Endpoint: &proto.WorkloadEndpointID{
						WorkloadId: "default/sample-pod",
					},
					Specification: &proto.PacketCaptureSpecification{
						BpfFilter: "anyfilter",
						StartTime: timestamppb.New(time.Time{}),
						EndTime:   timestamppb.New(time.Time{}),
					},
				},
			},
		}, []output{
			{
				// Expect packet capture to start
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     false,
			},
			{
				// Expect packet capture to be updated
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture", WorkloadEndpointId: "default/sample-pod",
				},
				specification:          capture.Specification{DeviceName: "cali123", BPFFilter: "anyfilter"},
				err:                    nil,
				shouldCheckForContains: true,
				wasPreviouslyAdded:     true,
			},
		}, []output{
			{
				// Expect packet capture to stop after receiving the update
				key: capture.Key{
					Namespace: "default", CaptureName: "packet-capture", WorkloadEndpointId: "default/sample-pod",
				},
				specification: capture.Specification{DeviceName: "cali123"},
			},
		}, []output{}),
	)
})
