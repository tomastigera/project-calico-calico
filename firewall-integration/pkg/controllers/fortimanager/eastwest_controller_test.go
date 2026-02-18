package fortimanager

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientv3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	mockClientSet clientv3.ProjectcalicoV3Interface
	getTier       func(ctx context.Context, name string, opts v1.GetOptions) (*v3.Tier, error)
	updateTier    func(ctx context.Context, tier *v3.Tier, opts v1.UpdateOptions) (*v3.Tier, error)

	updateCalled bool
)

type mockTierInterface struct {
	clientv3.TierInterface
}

func (t mockTierInterface) Get(ctx context.Context, name string, opts v1.GetOptions) (*v3.Tier, error) {
	return getTier(ctx, name, opts)
}

func (t mockTierInterface) Update(ctx context.Context, tier *v3.Tier, opts v1.UpdateOptions) (*v3.Tier, error) {
	updateCalled = true
	return updateTier(ctx, tier, opts)
}

type mockCalicoClientset struct {
	clientv3.ProjectcalicoV3Interface
}

func (c mockCalicoClientset) Tiers() clientv3.TierInterface {
	return mockTierInterface{}
}

var _ = Describe("Tests East West Controller", func() {

	Context("Tests createUpdateTierForFortimanager", func() {

		mockTierName := "Test-Tier"

		BeforeEach(func() {
			mockClientSet = mockCalicoClientset{}
			updateCalled = false

		})

		It("updates a Tier workload if one does not exist on the calico datastore", func() {

			var tierLabelResult map[string]string

			getTier = func(ctx context.Context, name string, opts v1.GetOptions) (*v3.Tier, error) {
				existingTier := &v3.Tier{}
				existingTier.Name = name

				return existingTier, nil
			}

			updateTier = func(ctx context.Context, tier *v3.Tier, opts v1.UpdateOptions) (*v3.Tier, error) {
				tierLabelResult = tier.Labels

				return tier, nil
			}

			err := createUpdateTierForFortimanager(mockClientSet, mockTierName)

			Expect(err).To(BeNil())
			Expect(updateCalled).To(BeTrue())
			Expect(tierLabelResult[SystemTierLabel]).To(Equal("true"))

		})
	})
})
