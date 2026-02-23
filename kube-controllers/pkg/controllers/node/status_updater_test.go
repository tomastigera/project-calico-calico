// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package node

import (
	"fmt"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	dpiName  = "dpiRes-name"
	dpiNs    = "dpiRes-ns"
	pcapName = "pcapRes-name"
	pcapNs   = "pcapRes-ns"
)

var (
	dpiRes = &v3.DeepPacketInspection{
		ObjectMeta: metav1.ObjectMeta{Name: dpiName, Namespace: dpiNs},
		Status: v3.DeepPacketInspectionStatus{Nodes: []v3.DPINode{
			{Node: "node-0", Active: v3.DPIActive{Success: true}},
		}},
	}
	pcapRes = &v3.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{Namespace: pcapNs, Name: pcapName},
		Status: v3.PacketCaptureStatus{Files: []v3.PacketCaptureFile{
			{Node: "node-0", Directory: "/random-dir", FileNames: []string{"file-01"}},
		}},
	}
)

func getDPINodes() v3.DeepPacketInspection {
	return v3.DeepPacketInspection{
		ObjectMeta: metav1.ObjectMeta{Name: dpiName, Namespace: dpiNs},
		Status: v3.DeepPacketInspectionStatus{Nodes: []v3.DPINode{
			{Node: "node-0", Active: v3.DPIActive{Success: true}},
		}},
	}
}

func getPCAPNodes() v3.PacketCapture {
	return v3.PacketCapture{
		ObjectMeta: metav1.ObjectMeta{Namespace: pcapNs, Name: pcapName},
		Status: v3.PacketCaptureStatus{Files: []v3.PacketCaptureFile{
			{Node: "node-0", Directory: "/random-dir", FileNames: []string{"file-01"}},
		}},
	}
}

var _ = Describe("DPI status on node create or delete", func() {
	var cli *FakeCalicoClient
	var mockDPIClient *MockDeepPacketInspectionInterface
	var mockPCAPClient *MockPacketCaptureInterface
	var expectedDPIUpdateStatusCallCounter, actualDPIUpdateStatusCallCounter int
	var expectedPCAPUpdateStatusCallCounter, actualPCAPUpdateStatusCallCounter int
	var stopCh chan struct{}
	var newCtrl func() *statusUpdateController
	var nodeList []string
	var nodeCacheCount int
	var dataLock sync.Mutex

	setNodes := func(nodes ...string) {
		dataLock.Lock()
		defer dataLock.Unlock()
		nodeList = nodes
	}

	getNodeCacheCount := func() int {
		dataLock.Lock()
		defer dataLock.Unlock()
		return nodeCacheCount
	}

	getActualDPIUpdateStatusCallCounter := func() int {
		dataLock.Lock()
		defer dataLock.Unlock()
		return actualDPIUpdateStatusCallCounter
	}

	getActualPCAPUpdateStatusCallCounter := func() int {
		dataLock.Lock()
		defer dataLock.Unlock()
		return actualPCAPUpdateStatusCallCounter
	}

	BeforeEach(func() {
		cli = NewFakeCalicoClient()
		stopCh = make(chan struct{})
		nodeList = nil
		nodeCacheCount = 0
		newCtrl = func() *statusUpdateController {
			return &statusUpdateController{
				calicoClient: cli,
				nodeCacheFn: func() []string {
					dataLock.Lock()
					defer dataLock.Unlock()
					nodeCacheCount++
					return nodeList
				},
				reconcilerPeriod: 30 * time.Second,
				syncChan:         make(chan any),
			}
		}

		mockDPIClient = &MockDeepPacketInspectionInterface{}
		mockDPIClient.AssertExpectations(GinkgoT())
		cli.On("DeepPacketInspections").Return(mockDPIClient)

		mockPCAPClient = &MockPacketCaptureInterface{}
		mockPCAPClient.AssertExpectations(GinkgoT())
		cli.On("PacketCaptures").Return(mockPCAPClient)

		mockDPIClient.On("List", mock.Anything, mock.Anything).Return(&v3.DeepPacketInspectionList{
			TypeMeta: metav1.TypeMeta{},
			ListMeta: metav1.ListMeta{},
			Items:    []v3.DeepPacketInspection{getDPINodes()},
		}, nil)
		mockPCAPClient.On("List", mock.Anything, mock.Anything).Return(&v3.PacketCaptureList{
			TypeMeta: metav1.TypeMeta{},
			ListMeta: metav1.ListMeta{},
			Items:    []v3.PacketCapture{getPCAPNodes()},
		}, nil)

		expectedDPIUpdateStatusCallCounter = 0
		actualDPIUpdateStatusCallCounter = 0
		expectedPCAPUpdateStatusCallCounter = 0
		actualPCAPUpdateStatusCallCounter = 0
	})

	AfterEach(func() {
		close(stopCh)
	})

	It("should update DPI & PCAP resource if there are no nodes cached", func() {
		expectedDPIUpdateStatusCallCounter = 1
		expectedPCAPUpdateStatusCallCounter = 1

		mockDPIClient.On("UpdateStatus", mock.Anything, mock.Anything, mock.Anything).Return(dpiRes, nil).Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualDPIUpdateStatusCallCounter++
				dpiRes = args.Get(1).(*v3.DeepPacketInspection)
				Expect(len(dpiRes.Status.Nodes)).Should(Equal(0))
			})
		mockPCAPClient.On("Update", mock.Anything, mock.Anything, mock.Anything).Return(pcapRes, nil).Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualPCAPUpdateStatusCallCounter++
				pcapRes = args.Get(1).(*v3.PacketCapture)
				Expect(len(pcapRes.Status.Files)).Should(Equal(0))
			})
		ctrl := newCtrl()
		ctrl.Start(stopCh)
		Eventually(getNodeCacheCount, 5*time.Second).Should(Equal(2))
		Eventually(getActualDPIUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedDPIUpdateStatusCallCounter))
		Eventually(getActualPCAPUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedPCAPUpdateStatusCallCounter))
	})

	It("should update DPI & PCAP resource status when an existing node is deleted via notification", func() {
		setNodes("node-0")

		expectedDPIUpdateStatusCallCounter = 1
		expectedPCAPUpdateStatusCallCounter = 1
		mockDPIClient.On("UpdateStatus", mock.Anything, mock.Anything, mock.Anything).
			Return(dpiRes, nil).Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualDPIUpdateStatusCallCounter++
				dpiRes = args.Get(1).(*v3.DeepPacketInspection)
				Expect(len(dpiRes.Status.Nodes)).Should(Equal(0))
			})
		mockPCAPClient.On("Update", mock.Anything, mock.Anything, mock.Anything).
			Return(pcapRes, nil).Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualPCAPUpdateStatusCallCounter++
				pcapRes = args.Get(1).(*v3.PacketCapture)
				Expect(len(pcapRes.Status.Files)).Should(Equal(0))
			})

		ctrl := newCtrl()
		ctrl.Start(stopCh)
		Eventually(getNodeCacheCount, 5*time.Second).Should(Equal(2))
		setNodes()
		ctrl.OnKubernetesNodeDeleted(nil)
		Eventually(getNodeCacheCount, 5*time.Second).Should(BeNumerically(">", 2))
		Eventually(getActualDPIUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedDPIUpdateStatusCallCounter))
		Eventually(getActualPCAPUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedPCAPUpdateStatusCallCounter))
	})

	It("should update DPI & PCAP resource status when an existing node is deleted via polling", func() {
		setNodes("node-0")

		expectedDPIUpdateStatusCallCounter = 1
		expectedPCAPUpdateStatusCallCounter = 1
		mockDPIClient.On("UpdateStatus", mock.Anything, mock.Anything, mock.Anything).
			Return(dpiRes, nil).Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualDPIUpdateStatusCallCounter++
				dpiRes = args.Get(1).(*v3.DeepPacketInspection)
				Expect(len(dpiRes.Status.Nodes)).Should(Equal(0))
			})
		mockPCAPClient.On("Update", mock.Anything, mock.Anything, mock.Anything).
			Return(pcapRes, nil).Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualPCAPUpdateStatusCallCounter++
				pcapRes = args.Get(1).(*v3.PacketCapture)
				Expect(len(pcapRes.Status.Files)).Should(Equal(0))
			})

		ctrl := newCtrl()
		ctrl.reconcilerPeriod = 1 * time.Second
		ctrl.Start(stopCh)
		Eventually(getNodeCacheCount, 1*time.Second).Should(BeNumerically(">=", 2))
		setNodes()
		Eventually(getActualDPIUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedDPIUpdateStatusCallCounter))
		Eventually(getActualPCAPUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedPCAPUpdateStatusCallCounter))
	})

	It("should retry status update on conflict", func() {
		expectedDPIUpdateStatusCallCounter = 3
		expectedPCAPUpdateStatusCallCounter = 3

		mockDPIClient.On("Get", mock.Anything, dpiNs, dpiName, mock.Anything).
			Return(func() *v3.DeepPacketInspection { op := getDPINodes(); return &op }(), nil).Times(2)
		mockPCAPClient.On("Get", mock.Anything, pcapNs, pcapName, mock.Anything).
			Return(func() *v3.PacketCapture { op := getPCAPNodes(); return &op }(), nil, nil).Times(2)

		// UpdateStatus returns conflict during the first 2 tries
		mockDPIClient.On("UpdateStatus", mock.Anything, mock.Anything, mock.Anything).
			Return().Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualDPIUpdateStatusCallCounter++
				actualDPIRes := args.Get(1).(*v3.DeepPacketInspection)
				Expect(len(actualDPIRes.Status.Nodes)).Should(Equal(0))
				for _, c := range mockDPIClient.ExpectedCalls {
					if c.Method == "UpdateStatus" {
						if actualDPIUpdateStatusCallCounter <= 2 {
							c.ReturnArguments = mock.Arguments{nil, errors.NewConflict(schema.GroupResource{
								Group:    "projectcalico.org/v3",
								Resource: v3.KindDeepPacketInspection,
							}, dpiName, fmt.Errorf("randomerr"))}
						} else {
							c.ReturnArguments = mock.Arguments{dpiRes, nil}
						}
					}
				}
			})
		mockPCAPClient.On("Update", mock.Anything, mock.Anything, mock.Anything).
			Return().Run(
			func(args mock.Arguments) {
				dataLock.Lock()
				defer dataLock.Unlock()
				actualPCAPUpdateStatusCallCounter++
				actualPCAPRes := args.Get(1).(*v3.PacketCapture)
				Expect(len(actualPCAPRes.Status.Files)).Should(Equal(0))
				for _, c := range mockPCAPClient.ExpectedCalls {
					if c.Method == "Update" {
						if actualPCAPUpdateStatusCallCounter <= 2 {
							c.ReturnArguments = mock.Arguments{nil, errors.NewConflict(schema.GroupResource{
								Group:    "projectcalico.org/v3",
								Resource: v3.KindPacketCapture,
							}, pcapName, fmt.Errorf("randomerr"))}
						} else {
							c.ReturnArguments = mock.Arguments{pcapRes, nil}
						}
					}
				}
			})

		ctrl := &statusUpdateController{
			calicoClient:     cli,
			nodeCacheFn:      func() []string { return []string{} },
			reconcilerPeriod: 5 * time.Second,
		}
		ctrl.Start(stopCh)
		Eventually(getActualDPIUpdateStatusCallCounter, 30*time.Second).Should(Equal(expectedDPIUpdateStatusCallCounter))
		Eventually(getActualPCAPUpdateStatusCallCounter, 30*time.Second).Should(Equal(expectedPCAPUpdateStatusCallCounter))
	})

	It("should not update DPI or PCAP status for existing nodes", func() {
		setNodes("node-0")

		expectedDPIUpdateStatusCallCounter = 0
		expectedPCAPUpdateStatusCallCounter = 0
		ctrl := newCtrl()
		ctrl.Start(stopCh)
		Eventually(getActualDPIUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedDPIUpdateStatusCallCounter))
		Eventually(getActualPCAPUpdateStatusCallCounter, 10*time.Second).Should(Equal(expectedPCAPUpdateStatusCallCounter))
	})
})
