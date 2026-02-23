package calico

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("BFD resolver", func() {
	var nodeLabelManager *nodeLabelManager
	var bfdResolver *bfdResolver
	testNode := "test-node"

	BeforeEach(func() {
		nodeLabelManager = newNodeLabelManager()
		bfdResolver = newBFDResolver(testNode, nodeLabelManager)
	})

	It("should resolve to nothing when there is no configuration", func() {
		cfg, err := bfdResolver.Resolve()
		Expect(err).NotTo(HaveOccurred())
		Expect(cfg).To(BeNil())
	})

	Context("with a BFDConfiguration", func() {
		var bfdConfig *apiv3.BFDConfiguration
		bfdConfigKey := model.ResourceKey{Name: "test-bfd", Kind: apiv3.KindBFDConfiguration}
		BeforeEach(func() {
			bfdConfig = &apiv3.BFDConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bfd"},
				Spec:       apiv3.BFDConfigurationSpec{NodeSelector: "all()"},
			}
			kvp := model.KVPair{
				Key:   bfdConfigKey,
				Value: bfdConfig,
			}

			// All BFD configuration updates are considered relevant.
			relevant := bfdResolver.OnUpdate(api.Update{KVPair: kvp})
			Expect(relevant).To(BeTrue())

			cfg, err := bfdResolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(Equal(bfdConfig))
		})

		It("should resolve to nothing when the only BFDConfiguration is deleted", func() {
			kvp := model.KVPair{Key: bfdConfigKey}

			// All BFD configuration updates are considered relevant.
			relevant := bfdResolver.OnUpdate(api.Update{KVPair: kvp})
			Expect(relevant).To(BeTrue())

			cfg, err := bfdResolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("should resolve to nothing when no BFDConfiguration selects this node", func() {
			bfdConfigNoSelect := &apiv3.BFDConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bfd"},
				Spec:       apiv3.BFDConfigurationSpec{NodeSelector: "has(label)"},
			}
			kvp := model.KVPair{
				Key:   bfdConfigKey,
				Value: bfdConfigNoSelect,
			}

			// All BFD configuration updates are considered relevant.
			relevant := bfdResolver.OnUpdate(api.Update{KVPair: kvp})
			Expect(relevant).To(BeTrue())

			cfg, err := bfdResolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(BeNil())
		})

		It("should handle overlapping BFDConfigurations by selecing one of them", func() {
			By("Resolving to the first configuration")
			cfg, err := bfdResolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(Equal(bfdConfig))

			By("Adding a second configuration")
			bfdConfig2 := &apiv3.BFDConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bfd-2"},
				Spec:       apiv3.BFDConfigurationSpec{NodeSelector: "all()"},
			}
			kvp2 := model.KVPair{
				Key:   model.ResourceKey{Name: "test-bfd-2", Kind: apiv3.KindBFDConfiguration},
				Value: bfdConfig2,
			}
			relevant := bfdResolver.OnUpdate(api.Update{KVPair: kvp2})
			Expect(relevant).To(BeTrue())

			// Should select bfdConfig because the arbitrary selection is deterministic based on lexicographic order.
			By("Still resolving to the first configuration")
			cfg, err = bfdResolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(Equal(bfdConfig))

			// Delete the resolved configuration - should now resolve to the other one.
			By("Deleting the first configuration")
			kvp := model.KVPair{Key: bfdConfigKey}
			relevant = bfdResolver.OnUpdate(api.Update{KVPair: kvp})
			Expect(relevant).To(BeTrue())

			By("Resolving to the other configuration")
			cfg, err = bfdResolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(Equal(bfdConfig2))

			By("Re-adding the original configuration")
			kvp.Value = bfdConfig
			relevant = bfdResolver.OnUpdate(api.Update{KVPair: kvp})
			Expect(relevant).To(BeTrue())

			By("Resolving to the original configuration")
			cfg, err = bfdResolver.Resolve()
			Expect(err).NotTo(HaveOccurred())
			Expect(cfg).To(Equal(bfdConfig))
		})
	})

	It("should skip updates for other nodes", func() {
		kvp := model.KVPair{
			Key: model.ResourceKey{Name: "test-bfd", Kind: internalapi.KindNode},
		}
		relevant := bfdResolver.OnUpdate(api.Update{KVPair: kvp})
		Expect(relevant).To(BeFalse())
	})

	It("should not skip updates for the local node", func() {
		kvp := model.KVPair{
			Key: model.ResourceKey{Name: testNode, Kind: internalapi.KindNode},
		}
		relevant := bfdResolver.OnUpdate(api.Update{KVPair: kvp})
		Expect(relevant).To(BeTrue())
	})
})
