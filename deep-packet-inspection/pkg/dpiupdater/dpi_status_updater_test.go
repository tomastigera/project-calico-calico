package dpiupdater_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/dpiupdater"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/processor"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("DPI status updater", func() {
	var mockCalicoClient *processor.MockClientInterface
	var mockDPIInterface *processor.MockDeepPacketInspectionInterface
	var ctx context.Context
	var dpiRes *v3.DeepPacketInspection

	dpiName := "dpi-name"
	dpiNs := "dpi-ns"
	dpiKey := model.ResourceKey{
		Name:      dpiName,
		Namespace: dpiNs,
		Kind:      "DeepPacketInspection",
	}
	dpiRes = &v3.DeepPacketInspection{
		ObjectMeta: metav1.ObjectMeta{Name: dpiName, Namespace: dpiNs},
		Spec:       v3.DeepPacketInspectionSpec{Selector: "k8s-app=='dpi'"},
	}

	BeforeEach(func() {
		ctx = context.Background()
		mockCalicoClient = &processor.MockClientInterface{}
		mockDPIInterface = &processor.MockDeepPacketInspectionInterface{}
		mockDPIInterface.AssertExpectations(GinkgoT())
		mockCalicoClient.On("DeepPacketInspections").Return(mockDPIInterface)
	})

	It("should update status", func() {
		mockDPIInterface.On("Get", mock.Anything, dpiKey.Namespace, dpiKey.Name, mock.Anything).Return(dpiRes, nil).Times(1)
		mockDPIInterface.On("UpdateStatus", mock.Anything, dpiRes, mock.Anything).Return(dpiRes, nil).Times(1)
		updater := dpiupdater.NewDPIStatusUpdater(mockCalicoClient, "node-0")
		updater.UpdateStatus(ctx, dpiKey, true)
		Eventually(func() int { return len(mockDPIInterface.Calls) }, 5*time.Second).Should(Equal(2))
	})

	It("should retry status update on conflict", func() {
		mockDPIInterface.On("Get", mock.Anything, dpiKey.Namespace, dpiKey.Name, mock.Anything).Return(dpiRes, nil).Times(4)
		numberOfCallsToUpdate := 0
		mockDPIInterface.On("UpdateStatus", mock.Anything, dpiRes, mock.Anything).Return().Run(
			func(args mock.Arguments) {
				numberOfCallsToUpdate++
				for _, c := range mockDPIInterface.ExpectedCalls {
					if c.Method == "UpdateStatus" {
						if numberOfCallsToUpdate <= 3 {
							c.ReturnArguments = mock.Arguments{nil, errors.NewConflict(schema.GroupResource{
								Group:    "projectcalico.org/v3",
								Resource: v3.KindDeepPacketInspection,
							}, dpiName, fmt.Errorf("randomerr"))}
						} else {
							c.ReturnArguments = mock.Arguments{dpiRes, nil}
						}
					}
				}
			}).Times(4)
		updater := dpiupdater.NewDPIStatusUpdater(mockCalicoClient, "node-0")
		updater.UpdateStatus(ctx, dpiKey, true)
		Eventually(func() int { return len(mockDPIInterface.Calls) }, 5*time.Second).Should(Equal(8))
	})

	It("should not retry status update on other error", func() {
		mockDPIInterface.On("Get", mock.Anything, dpiKey.Namespace, dpiKey.Name, mock.Anything).Return(dpiRes, nil).Times(1)
		mockDPIInterface.On("UpdateStatus", mock.Anything, dpiRes, mock.Anything).Return(nil, errors.NewBadRequest("ramdom-error")).Times(1)
		updater := dpiupdater.NewDPIStatusUpdater(mockCalicoClient, "node-0")
		updater.UpdateStatus(ctx, dpiKey, true)
		Eventually(func() int { return len(mockDPIInterface.Calls) }, 5*time.Second).Should(Equal(2))
	})

	It("should add error to new node", func() {
		dpiRes2 := &v3.DeepPacketInspection{
			ObjectMeta: metav1.ObjectMeta{Name: dpiName, Namespace: dpiNs},
			Spec:       v3.DeepPacketInspectionSpec{Selector: "k8s-app=='dpi'"},
			Status: v3.DeepPacketInspectionStatus{Nodes: []v3.DPINode{
				{Node: "node-1", Active: v3.DPIActive{Success: true}},
			}},
		}
		mockDPIInterface.On("Get", mock.Anything, dpiKey.Namespace, dpiKey.Name, mock.Anything).Return(dpiRes2, nil).Times(1)
		mockDPIInterface.On("UpdateStatus", mock.Anything, mock.Anything, mock.Anything).Return().Run(
			func(args mock.Arguments) {
				actualRes := args.Get(1).(*v3.DeepPacketInspection)
				Expect(len(actualRes.Status.Nodes)).Should(Equal(2))
				for _, c := range mockDPIInterface.ExpectedCalls {
					if c.Method == "UpdateStatus" {
						c.ReturnArguments = mock.Arguments{dpiRes2, nil}
					}
				}
			}).Times(1)
		updater := dpiupdater.NewDPIStatusUpdater(mockCalicoClient, "node-0")
		updater.UpdateStatus(ctx, dpiKey, true)
		Eventually(func() int { return len(mockDPIInterface.Calls) }, 5*time.Second).Should(Equal(2))
	})

	It("should retain only latest 10 error on each node", func() {
		dpiRes2 := &v3.DeepPacketInspection{
			ObjectMeta: metav1.ObjectMeta{Name: dpiName, Namespace: dpiNs},
			Spec:       v3.DeepPacketInspectionSpec{Selector: "k8s-app=='dpi'"},
			Status: v3.DeepPacketInspectionStatus{Nodes: []v3.DPINode{
				{
					Node: "node-0", Active: v3.DPIActive{Success: false},
					ErrorConditions: []v3.DPIErrorCondition{
						{Message: "error-1"},
						{Message: "error-2"},
						{Message: "error-3"},
						{Message: "error-4"},
						{Message: "error-5"},
						{Message: "error-6"},
						{Message: "error-7"},
						{Message: "error-8"},
						{Message: "error-9"},
						{Message: "error-10"},
					},
				},
				{Node: "node-1", Active: v3.DPIActive{Success: false}},
				{Node: "node-2", Active: v3.DPIActive{Success: true}},
			}},
		}
		mockDPIInterface.On("Get", mock.Anything, dpiKey.Namespace, dpiKey.Name, mock.Anything).Return(dpiRes2, nil).Times(1)
		mockDPIInterface.On("UpdateStatus", mock.Anything, mock.Anything, mock.Anything).Return().Run(
			func(args mock.Arguments) {
				actualRes := args.Get(1).(*v3.DeepPacketInspection)
				Expect(len(actualRes.Status.Nodes)).Should(Equal(3))
				for _, n := range actualRes.Status.Nodes {
					if n.Node == "node-0" {
						Expect(len(n.ErrorConditions)).Should(Equal(10))
						Expect(n.ErrorConditions[9].Message).Should(Equal("error-11"))
						break
					}
				}
				for _, c := range mockDPIInterface.ExpectedCalls {
					if c.Method == "UpdateStatus" {
						c.ReturnArguments = mock.Arguments{dpiRes2, nil}
					}
				}
			}).Times(1)
		updater := dpiupdater.NewDPIStatusUpdater(mockCalicoClient, "node-0")
		updater.UpdateStatusWithError(ctx, dpiKey, true, "error-11")
		Eventually(func() int { return len(mockDPIInterface.Calls) }, 5*time.Second).Should(Equal(2))
	})

	It("should append error on correct node", func() {
		dpiRes2 := &v3.DeepPacketInspection{
			ObjectMeta: metav1.ObjectMeta{Name: dpiName, Namespace: dpiNs},
			Spec:       v3.DeepPacketInspectionSpec{Selector: "k8s-app=='dpi'"},
			Status: v3.DeepPacketInspectionStatus{Nodes: []v3.DPINode{
				{
					Node: "node-0", Active: v3.DPIActive{Success: false},
					ErrorConditions: []v3.DPIErrorCondition{
						{Message: "error-1"},
						{Message: "error-2"},
					},
				},
				{Node: "node-1", Active: v3.DPIActive{Success: false}},
				{Node: "node-2", Active: v3.DPIActive{Success: true}},
			}},
		}
		mockDPIInterface.On("Get", mock.Anything, dpiKey.Namespace, dpiKey.Name, mock.Anything).Return(dpiRes2, nil).Times(1)
		mockDPIInterface.On("UpdateStatus", mock.Anything, mock.Anything, mock.Anything).Return().Run(
			func(args mock.Arguments) {
				actualRes := args.Get(1).(*v3.DeepPacketInspection)
				Expect(len(actualRes.Status.Nodes)).Should(Equal(3))
				for _, n := range actualRes.Status.Nodes {
					if n.Node == "node-0" {
						Expect(len(n.ErrorConditions)).Should(Equal(3))
						Expect(n.ErrorConditions[2].Message).Should(Equal("error-3"))
						Expect(n.Active.Success).Should(BeTrue())
						break
					}
				}
				for _, c := range mockDPIInterface.ExpectedCalls {
					if c.Method == "UpdateStatus" {
						c.ReturnArguments = mock.Arguments{dpiRes2, nil}
					}
				}
			}).Times(1)
		updater := dpiupdater.NewDPIStatusUpdater(mockCalicoClient, "node-0")
		updater.UpdateStatusWithError(ctx, dpiKey, true, "error-3")
		Eventually(func() int { return len(mockDPIInterface.Calls) }, 5*time.Second).Should(Equal(2))
	})
})
