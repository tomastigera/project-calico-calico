// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.
package client

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	v3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/api"
)

// mocks api.Node
var (
	testCachedQuery *cachedQuery

	getResource       func() api.Resource
	getEndpointCounts func() api.EndpointCounts

	expectedDispatchKinds = []string{
		apiv3.KindGlobalNetworkPolicy,
		model.KindKubernetesAdminNetworkPolicy,
		model.KindKubernetesBaselineAdminNetworkPolicy,
		model.KindKubernetesNetworkPolicy,
		apiv3.KindNetworkPolicy,
		apiv3.KindStagedGlobalNetworkPolicy,
		apiv3.KindStagedNetworkPolicy,
		apiv3.KindStagedKubernetesNetworkPolicy,
		apiv3.KindTier,
		v3.KindWorkloadEndpoint,
		apiv3.KindHostEndpoint,
		apiv3.KindProfile,
		v3.KindNode,
		apiv3.KindGlobalNetworkSet,
		apiv3.KindNetworkSet,
	}
)

// mocks api.Node
type mockAPINode struct{}

func (n *mockAPINode) GetEndpointCounts() api.EndpointCounts {
	return getEndpointCounts()
}

func (n *mockAPINode) GetName() string {
	return "mockApiNode"
}

func (n *mockAPINode) GetResource() api.Resource {
	return getResource()
}

var _ = Describe("Tests QueryNodeReq", func() {

	Context("Tests apiNodeToQueryNode", func() {

		const LocalIPV4Address = "127.0.0.1"
		const LocalIPV6Address = "0:0:0:0:0:0:0:1"

		BeforeEach(func() {
			testCachedQuery = &cachedQuery{}

			getEndpointCounts = func() api.EndpointCounts {
				return api.EndpointCounts{
					NumHostEndpoints:     1,
					NumWorkloadEndpoints: 1,
				}
			}
		})

		It("Populates Node.Addresses with NodeSpec.Addresses when they are received from API", func() {
			localNodeAddresses := []v3.NodeAddress{
				{Address: LocalIPV4Address},
				{Address: LocalIPV6Address},
			}

			getResource = func() api.Resource {
				n := v3.NewNode()
				n.Spec = v3.NodeSpec{
					Addresses: localNodeAddresses,
				}
				return n
			}

			nodeWithBGPIPs := &mockAPINode{}
			result := testCachedQuery.apiNodeToQueryNode(nodeWithBGPIPs)
			Expect(result.Addresses).To(HaveLen(2))
			Expect(result.Addresses).To(ContainElement(LocalIPV4Address))
			Expect(result.Addresses).To(ContainElement(LocalIPV6Address))
		})

		It("Populates Node.BGPIPAddresses with NodeSpec.BGPIAddresses when they are received from API", func() {
			getResource = func() api.Resource {
				n := v3.NewNode()
				n.Spec = v3.NodeSpec{
					BGP: &v3.NodeBGPSpec{
						IPv4Address: LocalIPV4Address,
						IPv6Address: LocalIPV6Address,
					},
				}
				return n
			}

			nodeWithBGPIPs := &mockAPINode{}
			result := testCachedQuery.apiNodeToQueryNode(nodeWithBGPIPs)
			Expect(result.BGPIPAddresses).To(HaveLen(2))
			Expect(result.BGPIPAddresses).To(ContainElement(LocalIPV4Address))
			Expect(result.BGPIPAddresses).To(ContainElement(LocalIPV6Address))
		})

		It("Gets the list of dispatchers and verifies its contents", func() {
			By("Getting the dispatchers")
			cq := &cachedQuery{}
			dispatchers := getDispachers(cq)

			By("Testing that the dispatcher kinds are the expected")
			for i, dis := range dispatchers {
				Expect(dis.Kind).To(Equal(expectedDispatchKinds[i]))
			}
		})
	})
})
