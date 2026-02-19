// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package snapshot

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/list"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	lmalist "github.com/projectcalico/calico/lma/pkg/list"
)

// Use a fixed "now" to prevent crossing over into the next hour mid-test.
var now = time.Now()

var _ = Describe("Snapshot", func() {
	var (
		cfg                 *config.Config
		mockSource          *list.MockSource
		mockListDestination *api.MockListDestination
		healthy             func(bool)
		isHealthy           bool
	)

	BeforeEach(func() {
		cfg = &config.Config{}
		mockSource = new(list.MockSource)
		mockListDestination = new(api.MockListDestination)
		healthy = func(h bool) { isHealthy = h }
	})

	AfterEach(func() {
		mockSource.AssertExpectations(GinkgoT())
		mockListDestination.AssertExpectations(GinkgoT())
	})

	It("should decide that it is not yet time to make a snapshot", func() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-time.After(time.Second)
			cancel()
		}()
		By("Taking a snapshot 2hrs ago")
		destTime := now.Add(-2 * time.Hour)

		for _, helper := range resources.GetAllResourceHelpers() {
			resList := resourceListFromHelper(helper)

			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(
				newTimeStampedResourceList(resList, destTime, destTime), nil)
		}

		By("Configuring the snapshot hour to be the next hour")
		cfg.SnapshotHour = now.Add(time.Hour).Hour()

		By("Starting the snapshotter")
		_ = Run(ctx, cfg, mockSource, mockListDestination, healthy)
		Expect(isHealthy).To(BeTrue())
	})

	It("should decide that it is time to make a snapshot but fail because src is empty", func() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-time.After(time.Second)
			cancel()
		}()

		for _, helper := range resources.GetAllResourceHelpers() {
			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).
				Return(nil, errors.ErrorResourceDoesNotExist{})
			mockSource.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).
				Return(nil, errors.ErrorResourceDoesNotExist{})
		}

		_ = Run(ctx, cfg, mockSource, mockListDestination, healthy)
		Expect(isHealthy).To(BeFalse())
	})

	It("should decide that it is time to make a snapshot and successfully store list from src to dest", func() {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-time.After(2 * time.Second)
			cancel()
		}()
		By("Taking a snapshot 2hrs ago")
		dstTime := now.Add(-2 * time.Hour)

		for _, helper := range resources.GetAllResourceHelpers() {
			resList := resourceListFromHelper(helper)

			mockListDestination.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(
				newTimeStampedResourceList(resList, dstTime, dstTime), nil)

			srcList := newTimeStampedResourceList(resList, now, now)
			mockSource.On("RetrieveList", helper.TypeMeta(), mock.Anything, mock.Anything, mock.Anything).Return(srcList, nil)
			mockListDestination.On("StoreList", helper.TypeMeta(), srcList).Return(nil)
		}

		By("Configuring the snapshot hour to be the current hour")
		cfg.SnapshotHour = now.Hour()

		By("Starting the snapshotter")
		_ = Run(ctx, cfg, mockSource, mockListDestination, healthy)
		Expect(isHealthy).To(BeTrue())
	})
})

func resourceListFromHelper(helper resources.ResourceHelper) resources.ResourceList {
	resList := helper.NewResourceList()
	tm := helper.TypeMeta()
	resList.GetObjectKind().SetGroupVersionKind((&tm).GroupVersionKind())
	return resList
}

func newTimeStampedResourceList(resourceList resources.ResourceList, startTime, completedTime time.Time) *lmalist.TimestampedResourceList {
	return &lmalist.TimestampedResourceList{
		ResourceList:              resourceList,
		RequestStartedTimestamp:   metav1.Time{Time: startTime},
		RequestCompletedTimestamp: metav1.Time{Time: completedTime},
	}
}
