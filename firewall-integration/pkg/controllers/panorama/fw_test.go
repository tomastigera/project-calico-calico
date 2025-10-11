// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package panorama

import (
	"context"
	"errors"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	"github.com/projectcalico/calico/firewall-integration/pkg/config"
)

var (
	mockDatastoreClientSet datastore.ClientSet
	getTier                func(ctx context.Context, name string, opts v1.GetOptions) (*v3.Tier, error)
	createTier             func(ctx context.Context, tier *v3.Tier, opts v1.CreateOptions) (*v3.Tier, error)
	updateTier             func(ctx context.Context, tier *v3.Tier, opts v1.UpdateOptions) (*v3.Tier, error)

	createCalled bool
	updateCalled bool
)

type mockTierInterface struct {
	clientv3.TierInterface
}

func (t mockTierInterface) Get(ctx context.Context, name string, opts v1.GetOptions) (*v3.Tier, error) {
	return getTier(ctx, name, opts)
}

func (t mockTierInterface) Create(ctx context.Context, tier *v3.Tier, opts v1.CreateOptions) (*v3.Tier, error) {
	createCalled = true
	return createTier(ctx, tier, opts)
}

func (t mockTierInterface) Update(ctx context.Context, tier *v3.Tier, opts v1.UpdateOptions) (*v3.Tier, error) {
	updateCalled = true
	return updateTier(ctx, tier, opts)
}

type mockCalicoClientset struct {
	datastore.ClientSet
}

func (c mockCalicoClientset) Tiers() clientv3.TierInterface {
	return mockTierInterface{}
}

var _ = Describe("Tests fwIntegrate", func() {

	Context("Tests createUpdateTierForPanorama", func() {

		mockConfig := &config.Config{
			TSTierPrefix: "Test-Tier",
			TSTierOrder:  "101",
		}

		BeforeEach(func() {
			mockDatastoreClientSet = mockCalicoClientset{}
			createCalled = false
			updateCalled = false

		})

		It("updates a Tier workload if one does not exist on the calico datastore", func() {

			var tierLabelResult map[string]string
			var tierOrder *float64
			var tierName string

			getTier = func(ctx context.Context, name string, opts v1.GetOptions) (*v3.Tier, error) {
				existingTier := &v3.Tier{}
				existingTier.Name = name

				return existingTier, nil
			}

			updateTier = func(ctx context.Context, tier *v3.Tier, opts v1.UpdateOptions) (*v3.Tier, error) {
				tierLabelResult = tier.Labels
				tierOrder = tier.Spec.Order
				tierName = tier.Name

				return tier, nil
			}

			err := createUpdateTierForPanorama(mockDatastoreClientSet, mockConfig)

			Expect(err).To(BeNil())
			Expect(updateCalled).To(BeTrue())
			Expect(createCalled).To(BeFalse())
			Expect(tierName).To(Equal(mockConfig.TSTierPrefix))
			Expect(tierLabelResult[SystemTierLabel]).To(Equal("true"))
			expectedOrder, _ := strconv.ParseFloat(mockConfig.TSTierOrder, 64)
			Expect(*tierOrder).To(Equal(expectedOrder))
		})

		It("creates a Tier workload if one does not exist on the calico datastore", func() {

			var tierLabelResult map[string]string
			var tierOrder *float64
			var tierName string

			getTier = func(ctx context.Context, name string, opts v1.GetOptions) (*v3.Tier, error) {
				return nil, errors.New(name + "notfound")
			}

			createTier = func(ctx context.Context, tier *v3.Tier, opts v1.CreateOptions) (*v3.Tier, error) {
				tierLabelResult = tier.Labels
				tierOrder = tier.Spec.Order
				tierName = tier.Name

				return tier, nil
			}

			err := createUpdateTierForPanorama(mockDatastoreClientSet, mockConfig)
			Expect(err).To(BeNil())
			Expect(updateCalled).To(BeFalse())
			Expect(createCalled).To(BeTrue())
			Expect(tierName).To(Equal(mockConfig.TSTierPrefix))
			Expect(tierLabelResult[SystemTierLabel]).To(Equal("true"))
			expectedOrder, _ := strconv.ParseFloat(mockConfig.TSTierOrder, 64)
			Expect(*tierOrder).To(Equal(expectedOrder))
		})
	})

})
