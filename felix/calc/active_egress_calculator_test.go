// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package calc

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/proto"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

var _ = Describe("ActiveEgressCalculator", func() {

	var (
		aec *ActiveEgressCalculator
		cbs *testCallbacks
	)

	we1Key := model.WorkloadEndpointKey{WorkloadID: "we1"}
	we1Value1 := &model.WorkloadEndpoint{
		Name:           "we1",
		EgressSelector: "black == 'white'",
	}
	we1Value2 := &model.WorkloadEndpoint{
		Name:           "we1",
		EgressSelector: "black == 'red'",
	}
	we1ValueWithPolicy1 := &model.WorkloadEndpoint{
		Name:                "we1",
		EgressGatewayPolicy: "egw-policy1",
	}
	we1ValueWithPolicy2 := &model.WorkloadEndpoint{
		Name:                "we1",
		EgressGatewayPolicy: "egw-policy2",
	}
	we1ValueWithPolicy3 := &model.WorkloadEndpoint{
		Name:                "we1",
		EgressGatewayPolicy: "egw-policy3",
	}

	we2Key := model.WorkloadEndpointKey{WorkloadID: "we2"}

	egwp1Key := model.ResourceKey{
		Kind: v3.KindEgressGatewayPolicy,
		Name: "egw-policy1",
	}
	preferenceNone := v3.GatewayPreferenceNone
	preferNodeLocal := v3.GatewayPreferenceNodeLocal
	egwp1Value := &v3.EgressGatewayPolicy{
		Spec: v3.EgressGatewayPolicySpec{
			Rules: []v3.EgressGatewayRule{
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "10.0.0.0/8",
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "11.0.0.0/8",
					},
					Gateway: &v3.EgressSpec{
						Selector: "black == 'green'",
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Gateway: &v3.EgressSpec{
						Selector: "black == 'blue'",
					},
					GatewayPreference: &preferenceNone,
				},
			},
		},
	}

	egwp2Key := model.ResourceKey{
		Kind: v3.KindEgressGatewayPolicy,
		Name: "egw-policy2",
	}
	egwp2Value := &v3.EgressGatewayPolicy{
		Spec: v3.EgressGatewayPolicySpec{
			Rules: []v3.EgressGatewayRule{
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "111.0.0.0/8",
					},
					Gateway: &v3.EgressSpec{
						Selector: "black == 'sky'",
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "110.0.0.0/8",
					},
					GatewayPreference: &preferenceNone,
				},
				{
					Gateway: &v3.EgressSpec{
						Selector: "black == 'ocean'",
					},
					GatewayPreference: &preferenceNone,
				},
			},
		},
	}

	egwp3Key := model.ResourceKey{
		Kind: v3.KindEgressGatewayPolicy,
		Name: "egw-policy3",
	}
	egwp3Value := &v3.EgressGatewayPolicy{
		Spec: v3.EgressGatewayPolicySpec{
			Rules: []v3.EgressGatewayRule{
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "111.0.0.0/8",
					},
					Gateway: &v3.EgressSpec{
						Selector: "black == 'sky'",
					},
					GatewayPreference: &preferNodeLocal,
				},
				{
					Destination: &v3.EgressGatewayPolicyDestinationSpec{
						CIDR: "110.0.0.0/8",
					},
					GatewayPreference: &preferenceNone,
				},
			},
		},
	}

	BeforeEach(func() {
		aec = NewActiveEgressCalculator("EnabledPerNamespaceOrPerPod", &EgressSelectorPool{})
		cbs = &testCallbacks{}
		aec.OnIPSetActive = cbs.OnIPSetActive
		aec.OnIPSetInactive = cbs.OnIPSetInactive
		aec.OnEndpointComputedDataUpdate = cbs.OnEndpointComputedDataUpdate
		aec.OnDatamodelStatus(api.InSync)
	})

	It("generates expected callbacks for a single WorkloadEndpoint", func() {

		By("creating a WorkloadEndpoint with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1Value1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.Flush()

		// Expect IPSetActive and EgressIPSetIDUpdate.
		ipSetID1 := cbs.ExpectActive()
		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID1}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("changing WorkloadEndpoint's egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1Value2,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})
		aec.Flush()

		// Expect IPSetInactive for old selector.
		cbs.ExpectInactive(ipSetID1)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		ipSetID2 := cbs.ExpectActive()
		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID2}},
		})
		cbs.ExpectNoMoreCallbacks()
		Expect(ipSetID2).NotTo(Equal(ipSetID1))

		By("deleting WorkloadEndpoint")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})
		aec.Flush()

		// Expect IPSetInactive for old selector.
		cbs.ExpectInactive(ipSetID2)
		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for a single WorkloadEndpoint with egress gateway policy", func() {

		By("creating a WorkloadEndpoint with egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		cbs.ExpectNoMoreCallbacks()

		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1ValueWithPolicy1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect IPSetActive and EgressIPSetIDUpdate.
		aec.Flush()

		ipSetID1 := cbs.ExpectActive()
		ipSetID2 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("changing WorkloadEndpoint's egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp2Key,
				Value: egwp2Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1ValueWithPolicy2,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID1)
		cbs.ExpectInactive(ipSetID2)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		ipSetID3 := cbs.ExpectActive()
		ipSetID4 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: ipSetID3, CIDR: "111.0.0.0/8"},
				{IpSetID: "", CIDR: "110.0.0.0/8"},
				{IpSetID: ipSetID4, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()
		Expect(ipSetID3).NotTo(Equal(ipSetID1))
		Expect(ipSetID4).NotTo(Equal(ipSetID2))

		By("setting local Egress gateway preference to PreferLocal")

		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp3Key,
				Value: egwp3Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1ValueWithPolicy3,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: ipSetID3, CIDR: "111.0.0.0/8", PreferLocalGW: true},
				{IpSetID: "", CIDR: "110.0.0.0/8"},
			},
		})

		cbs.ExpectInactive(ipSetID4)
		cbs.ExpectNoMoreCallbacks()

		By("deleting egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp2Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp3Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID3)

		blockIPSet := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		aec.Flush()

		cbs.ExpectInactive(blockIPSet)

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()
	})

	It("should prioritise egress gateway policy but not ignore egress selectors", func() {

		By("creating a workload with egress selector and none existing egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:                "we1",
					EgressSelector:      "black == 'brown'",
					EgressGatewayPolicy: "egw-policy1",
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		blockIPSet := cbs.ExpectActive()
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("creating the egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		aec.Flush()

		cbs.ExpectInactive(blockIPSet)

		// Expect IPSetActive and EgressIPSetIDUpdate.
		ipSetID2 := cbs.ExpectActive()
		ipSetID3 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID3, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting egress gateway policy should block workload traffic")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID2)
		cbs.ExpectInactive(ipSetID3)

		blockIPSet1 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet1}},
		})
		Expect(blockIPSet1).To(Equal(blockIPSet))
		cbs.ExpectNoMoreCallbacks()

		By("removing egress gateway policy from workload, workload should use egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:           "we1",
					EgressSelector: "black == 'brown'",
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		aec.Flush()

		cbs.ExpectInactive(blockIPSet1)

		ipSetID4 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID4}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID4)

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for two WorkloadEndpoints with same selector", func() {

		By("creating two WorkloadEndpoints with the same egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1Value1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: we1Value1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect 1 IPSetActive and 2 EgressIPSetIDUpdates.
		aec.Flush()

		ipSetID := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID}},
		})

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #1")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect EgressUpdate for that endpoint.
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #2")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, nil)

		cbs.ExpectInactive(ipSetID)
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for two WorkloadEndpoints with same egress gateway policy #1", func() {

		By("creating two WorkloadEndpoints with the same egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		cbs.ExpectNoMoreCallbacks()

		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1ValueWithPolicy1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: we1ValueWithPolicy1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect 2 IPSetActive and 2 EgressIPSetIDUpdates.
		aec.Flush()

		ipSetID1 := cbs.ExpectActive()

		ipSetID2 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #1")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect EgressUpdate for that endpoint.
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #2")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, nil)

		cbs.ExpectInactive(ipSetID1)

		cbs.ExpectInactive(ipSetID2)
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for two WorkloadEndpoints with same egress gateway policy #2", func() {

		By("creating two WorkloadEndpoints with the same egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		cbs.ExpectNoMoreCallbacks()

		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1ValueWithPolicy1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: we1ValueWithPolicy1,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect 2 IPSetActive and 2 EgressIPSetIDUpdates.
		aec.Flush()

		ipSetID1 := cbs.ExpectActive()

		ipSetID2 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		blockIPSet := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet}},
		})

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet}},
		})
		aec.Flush()

		cbs.ExpectInactive(ipSetID1)

		cbs.ExpectInactive(ipSetID2)
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for WorkloadEndpoint with profile", func() {

		By("creating WorkloadEndpoint with profile ID but no egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:       "we1",
					ProfileIDs: []string{"webclient"},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		cbs.ExpectNoMoreCallbacks()

		By("adding Profile with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'bump'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect IPSetActive and EgressIPSetIDUpdate.
		aec.Flush()

		ipSetID1 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID1}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("updating Profile with different selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'wire'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID1)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		ipSetID2 := cbs.ExpectActive()
		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID2}},
		})
		cbs.ExpectNoMoreCallbacks()
		Expect(ipSetID2).NotTo(Equal(ipSetID1))

		By("updating WorkloadEndpoint with its own egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:           "we1",
					ProfileIDs:     []string{"webclient"},
					EgressSelector: "black == 'red'",
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID2)

		// Expect IPSetActive and EgressIPSetIDUpdate for new WE selector.
		ipSetID3 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID3}},
		})
		cbs.ExpectNoMoreCallbacks()
		Expect(ipSetID3).NotTo(Equal(ipSetID1))
		Expect(ipSetID3).NotTo(Equal(ipSetID2))

		By("updating WorkloadEndpoint with no egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:       "we1",
					ProfileIDs: []string{"webclient"},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old (WE) selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID3)

		// Expect IPSetActive and EgressIPSetIDUpdate for new (profile) selector.
		Expect(cbs.ExpectActive()).To(Equal(ipSetID2))

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID2}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("updating Profile with no egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old (profile) selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID2)

		// Expect EgressIPSetIDUpdate with IP set ID "".
		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()

		By("deleting the WorkloadEndpoint")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting the Profile")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		})
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for WorkloadEndpoint with profile and egress gateway policy", func() {

		By("creating WorkloadEndpoint with profile ID but no egress selector nor egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					ProfileIDs: []string{"webclient"},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		cbs.ExpectNoMoreCallbacks()

		By("adding Profile with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'bump'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect IPSetActive and EgressIPSetIDUpdate.
		aec.Flush()

		ipSetID1 := cbs.ExpectActive()
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID1}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("updating Profile with non-existing egress gateway policy selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'wire'",
							},
							Policy: "egw-policy1",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID1)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		blockIPSet := cbs.ExpectActive()
		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("removing non-existing egress gateway policy from profile")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'wire'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(blockIPSet)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		ipSetID2 := cbs.ExpectActive()
		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID2}},
		})
		cbs.ExpectNoMoreCallbacks()
		Expect(ipSetID2).NotTo(Equal(ipSetID1))

		By("updating WorkloadEndpoint with its own egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:           "we1",
					ProfileIDs:     []string{"webclient"},
					EgressSelector: "black == 'red'",
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID2)

		// Expect IPSetActive and EgressIPSetIDUpdate for new WE selector.
		ipSetID3 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID3}},
		})
		cbs.ExpectNoMoreCallbacks()
		Expect(ipSetID3).NotTo(Equal(ipSetID1))
		Expect(ipSetID3).NotTo(Equal(ipSetID2))

		By("updating WorkloadEndpoint with non-existing egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:                "we1",
					ProfileIDs:          []string{"webclient"},
					EgressSelector:      "black == 'red'",
					EgressGatewayPolicy: "egw-policy1",
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID3)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		blockIPSet1 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet1}},
		})
		Expect(blockIPSet1).To(Equal(blockIPSet))
		cbs.ExpectNoMoreCallbacks()

		By("updating Profile with non-existing egress gateway policy selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'wire'",
							},
							Policy: "egw-policy2",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		cbs.ExpectNoMoreCallbacks()

		By("create profile egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp2Key,
				Value: egwp2Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		aec.Flush()

		cbs.ExpectInactive(blockIPSet1)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		ipSetID4 := cbs.ExpectActive()
		ipSetID5 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: ipSetID4, CIDR: "111.0.0.0/8"},
				{IpSetID: "", CIDR: "110.0.0.0/8"},
				{IpSetID: ipSetID5, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("create WorkloadEndpoint's egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		aec.Flush()

		cbs.ExpectInactive(ipSetID4)

		cbs.ExpectInactive(ipSetID5)

		// Expect IPSetActive and EgressIPSetIDUpdate.
		ipSetID6 := cbs.ExpectActive()
		ipSetID7 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID6, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID7, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting workload's egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID6)

		cbs.ExpectInactive(ipSetID7)

		// Expect IPSetActive and EgressIPSetIDUpdate with new ID.
		ipSetID8 := cbs.ExpectActive()
		ipSetID9 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: ipSetID8, CIDR: "111.0.0.0/8"},
				{IpSetID: "", CIDR: "110.0.0.0/8"},
				{IpSetID: ipSetID9, CIDR: ""},
			},
		})
		Expect(ipSetID8).To(Equal(ipSetID4))
		Expect(ipSetID9).To(Equal(ipSetID5))
		Expect(ipSetID8).NotTo(Equal(ipSetID6))
		Expect(ipSetID9).NotTo(Equal(ipSetID7))
		cbs.ExpectNoMoreCallbacks()

		By("deleting profiles's egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp2Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectInactive(ipSetID8)

		cbs.ExpectInactive(ipSetID9)

		// Expect IPSetActive and EgressIPSetIDUpdate for new WE selector.
		blockIPSet2 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet2}},
		})
		Expect(blockIPSet2).To(Equal(blockIPSet1))
		cbs.ExpectNoMoreCallbacks()

		By("updating WorkloadEndpoint with no egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:                "we1",
					ProfileIDs:          []string{"webclient"},
					EgressGatewayPolicy: "egw-policy2",
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		cbs.ExpectNoMoreCallbacks()

		By("updating Profile with no egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		cbs.ExpectNoMoreCallbacks()

		By("deleting the Profile")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting the WorkloadEndpoint")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		})

		aec.Flush()

		cbs.ExpectInactive(blockIPSet2)

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()

	})

	It("generates expected callbacks for multiple WorkloadEndpoints and Profiles", func() {

		By("creating 5 WEs with profile A, 5 WEs with profile B")
		for _, profile := range []string{"a", "b"} {
			for i := range 5 {
				name := fmt.Sprintf("we%v-%v", i, profile)
				aec.OnUpdate(api.Update{
					KVPair: model.KVPair{
						Key: model.WorkloadEndpointKey{WorkloadID: name},
						Value: &model.WorkloadEndpoint{
							Name:       name,
							ProfileIDs: []string{profile},
						},
					},
					UpdateType: api.UpdateTypeKVNew,
				})
			}
		}
		cbs.ExpectNoMoreCallbacks()

		By("creating profile A with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'a'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.Flush()

		// Expect Active for that selector and EgressIPSetIDUpdate for the 5 using WEs.
		ipSetA := cbs.ExpectActive()
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)
			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, &ComputedEgressEP{
				Rules: []EpEgressData{{IpSetID: ipSetA}},
			})
		}
		cbs.ExpectNoMoreCallbacks()

		By("changing profile A’s selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'aprime'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect Inactive for old, Active for new, EgressIPSetIDUpdate for the 5 using WEs.
		aec.Flush()

		cbs.ExpectInactive(ipSetA)
		ipSetAPrime := cbs.ExpectActive()
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)
			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, &ComputedEgressEP{
				Rules: []EpEgressData{{IpSetID: ipSetAPrime}},
			})
		}
		cbs.ExpectNoMoreCallbacks()

		By("creating profile B with different egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "b"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'b'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.Flush()

		// Expect Active for that selector and EgressIPSetIDUpdate for the 5 using WEs.
		ipSetB := cbs.ExpectActive()
		for i := range 5 {
			name := fmt.Sprintf("we%v-b", i)
			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, &ComputedEgressEP{
				Rules: []EpEgressData{{IpSetID: ipSetB}},
			})
		}
		cbs.ExpectNoMoreCallbacks()

		By("deleting profile A")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		})

		// Expect Inactive for its selector and EgressIPSetIDUpdate ““ for the 5 using WEs.
		aec.Flush()

		cbs.ExpectInactive(ipSetAPrime)
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)

			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, nil)
		}
		cbs.ExpectNoMoreCallbacks()

		By("deleting the endpoints using profile A")
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)
			aec.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key:   model.WorkloadEndpointKey{WorkloadID: name},
					Value: nil,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			})
		}
		cbs.ExpectNoMoreCallbacks()

		By("deleting the endpoints using profile B")
		for i := range 5 {
			name := fmt.Sprintf("we%v-b", i)
			aec.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key:   model.WorkloadEndpointKey{WorkloadID: name},
					Value: nil,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			})
		}

		// Expect Inactive for its selector and EgressIPSetIDUpdate ““ for the 5 using WEs.
		aec.Flush()

		cbs.ExpectInactive(ipSetB)
		for i := range 5 {
			name := fmt.Sprintf("we%v-b", i)

			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, nil)
		}
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for multiple WorkloadEndpoints and Profiles with egress gateway policy", func() {

		By("creating 5 WEs with profile A, 5 WEs with profile B")
		for _, profile := range []string{"a", "b"} {
			for i := range 5 {
				name := fmt.Sprintf("we%v-%v", i, profile)
				aec.OnUpdate(api.Update{
					KVPair: model.KVPair{
						Key: model.WorkloadEndpointKey{WorkloadID: name},
						Value: &model.WorkloadEndpoint{
							Name:       name,
							ProfileIDs: []string{profile},
						},
					},
					UpdateType: api.UpdateTypeKVNew,
				})
			}
		}

		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp2Key,
				Value: egwp2Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		cbs.ExpectNoMoreCallbacks()

		By("creating profile A with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Policy: "egw-policy1",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect Active for that selector and EgressIPSetIDUpdate for the 5 using WEs.
		aec.Flush()

		ipSetIDA1 := cbs.ExpectActive()
		ipSetIDA2 := cbs.ExpectActive()
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)

			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, &ComputedEgressEP{
				Rules: []EpEgressData{
					{IpSetID: "", CIDR: "10.0.0.0/8"},
					{IpSetID: ipSetIDA1, CIDR: "11.0.0.0/8"},
					{IpSetID: ipSetIDA2, CIDR: ""},
				},
			})
		}
		cbs.ExpectNoMoreCallbacks()

		By("changing profile A’s selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Policy: "egw-policy2",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect Inactive for old, Active for new, EgressIPSetIDUpdate for the 5 using WEs.
		aec.Flush()

		cbs.ExpectInactive(ipSetIDA1)
		cbs.ExpectInactive(ipSetIDA2)

		ipSetIDA3 := cbs.ExpectActive()
		ipSetIDA4 := cbs.ExpectActive()
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)
			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, &ComputedEgressEP{
				Rules: []EpEgressData{
					{IpSetID: ipSetIDA3, CIDR: "111.0.0.0/8"},
					{IpSetID: "", CIDR: "110.0.0.0/8"},
					{IpSetID: ipSetIDA4, CIDR: ""},
				},
			})

		}
		cbs.ExpectNoMoreCallbacks()

		By("creating profile B with different egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "b"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Policy: "egw-policy1",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect Active for that selector and EgressIPSetIDUpdate for the 5 using WEs.
		aec.Flush()

		ipSetIDB1 := cbs.ExpectActive()
		ipSetIDB2 := cbs.ExpectActive()
		for i := range 5 {
			name := fmt.Sprintf("we%v-b", i)

			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, &ComputedEgressEP{
				Rules: []EpEgressData{
					{IpSetID: "", CIDR: "10.0.0.0/8"},
					{IpSetID: ipSetIDB1, CIDR: "11.0.0.0/8"},
					{IpSetID: ipSetIDB2, CIDR: ""},
				},
			})
		}
		cbs.ExpectNoMoreCallbacks()

		By("deleting profile A")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVDeleted,
		})

		// Expect Inactive for its selector and EgressIPSetIDUpdate ““ for the 5 using WEs.
		aec.Flush()

		cbs.ExpectInactive(ipSetIDA3)
		cbs.ExpectInactive(ipSetIDA4)
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)

			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, nil)
		}
		cbs.ExpectNoMoreCallbacks()

		By("deleting the endpoints using profile A")
		for i := range 5 {
			name := fmt.Sprintf("we%v-a", i)
			aec.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key:   model.WorkloadEndpointKey{WorkloadID: name},
					Value: nil,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			})
		}
		cbs.ExpectNoMoreCallbacks()

		By("deleting the endpoints using profile B")
		for i := range 5 {
			name := fmt.Sprintf("we%v-b", i)
			aec.OnUpdate(api.Update{
				KVPair: model.KVPair{
					Key:   model.WorkloadEndpointKey{WorkloadID: name},
					Value: nil,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			})
		}

		// Expect Inactive for its selector and EgressIPSetIDUpdate ““ for the 5 using WEs.
		aec.Flush()

		cbs.ExpectInactive(ipSetIDB1)
		cbs.ExpectInactive(ipSetIDB2)
		for i := range 5 {
			name := fmt.Sprintf("we%v-b", i)

			cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: name}, EPCompDataKindEgressGateway, nil)
		}
		cbs.ExpectNoMoreCallbacks()
	})

	It("ignores unexpected update", func() {
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: libapiv3.KindNode, Name: "a"},
				Value: &libapiv3.Node{
					Spec: libapiv3.NodeSpec{},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})
		cbs.ExpectNoMoreCallbacks()

		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.HostConfigKey{
					Hostname: "myhost",
					Name:     "IPv4VXLANTunnelAddr",
				},
				Value: "10.0.0.0",
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})
		cbs.ExpectNoMoreCallbacks()
	})

	It("handles when profile is defined before endpoint", func() {

		By("defining profile A with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'a'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		cbs.ExpectNoMoreCallbacks()

		By("defining an endpoint that uses that profile")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{WorkloadID: "we1"},
				Value: &model.WorkloadEndpoint{
					Name:       "we1",
					ProfileIDs: []string{"a"},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.Flush()

		ipSetID := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: "we1"}, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("updating profile with same selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'a'",
							},
						},
						LabelsToApply: map[string]string{"a": "b"},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})
		cbs.ExpectNoMoreCallbacks()

	})

	It("handles when profile using egress gateway policy is defined before endpoint", func() {

		By("defining profile A with egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Policy: "egw-policy1",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		cbs.ExpectNoMoreCallbacks()

		By("defining an endpoint that uses that profile")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.WorkloadEndpointKey{WorkloadID: "we1"},
				Value: &model.WorkloadEndpoint{
					Name:       "we1",
					ProfileIDs: []string{"a"},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.Flush()

		ipSetID1 := cbs.ExpectActive()
		ipSetID2 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(model.WorkloadEndpointKey{WorkloadID: "we1"}, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("updating profile with same selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "a"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Policy: "egw-policy1",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		cbs.ExpectNoMoreCallbacks()
	})

	It("handles when WorkloadEndpoint and profile both specify selectors", func() {

		By("creating WorkloadEndpoint with profile ID and egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:           "we1",
					ProfileIDs:     []string{"webclient"},
					EgressSelector: "black == 'red'",
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		ipSetWE := cbs.ExpectActive()
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetWE}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("adding Profile with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'bump'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect no change.
		cbs.ExpectNoMoreCallbacks()

		By("updating Profile with different selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'wire'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect no change.
		cbs.ExpectNoMoreCallbacks()

		By("defining 2nd WorkloadEndpoint with no selector and different profile")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we2Key,
				Value: &model.WorkloadEndpoint{
					Name:       "we2",
					ProfileIDs: []string{"other"},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect no callbacks.
		cbs.ExpectNoMoreCallbacks()

		By("changing first profile not to have egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect no change.
		cbs.ExpectNoMoreCallbacks()
	})

	It("handles when WorkloadEndpoint and profile both specify egress gateway policy", func() {

		By("creating WorkloadEndpoint with profile ID and egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we1Key,
				Value: &model.WorkloadEndpoint{
					Name:                "we1",
					ProfileIDs:          []string{"webclient"},
					EgressGatewayPolicy: "egw-policy1",
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		aec.Flush()

		blockIPSet := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: blockIPSet}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("creating the egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		aec.Flush()

		cbs.ExpectInactive(blockIPSet)

		ipSetID1 := cbs.ExpectActive()
		ipSetID2 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("adding Profile with egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Gateway: &v3.EgressSpec{
								Selector: "server == 'bump'",
							},
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect no change.
		cbs.ExpectNoMoreCallbacks()

		By("updating Profile with egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{
						EgressGateway: &v3.EgressGatewaySpec{
							Policy: "egw-polic2",
						},
					},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp2Key,
				Value: egwp2Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect no change.
		cbs.ExpectNoMoreCallbacks()

		By("defining 2nd WorkloadEndpoint with no selector and different profile")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: we2Key,
				Value: &model.WorkloadEndpoint{
					Name:       "we2",
					ProfileIDs: []string{"other"},
				},
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect no callbacks.
		cbs.ExpectNoMoreCallbacks()

		By("changing first profile not to have egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key: model.ResourceKey{Kind: v3.KindProfile, Name: "webclient"},
				Value: &v3.Profile{
					Spec: v3.ProfileSpec{},
				},
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect no change.
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for two WorkloadEndpoints with different but equivalent selector", func() {

		we1Value := &model.WorkloadEndpoint{
			Name:           "we1",
			EgressSelector: `black == "red"`,
		}
		we2Value := &model.WorkloadEndpoint{
			Name:           "we1",
			EgressSelector: "black == 'red'",
		}

		By("creating two WorkloadEndpoints with similar egress selector")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: we2Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect 1 IPSetActive and 2 EgressIPSetIDUpdates.
		aec.Flush()

		ipSetID := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID}},
		})

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{{IpSetID: ipSetID}},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #1")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect EgressUpdate for that endpoint.
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #2")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, nil)

		cbs.ExpectInactive(ipSetID)
		cbs.ExpectNoMoreCallbacks()
	})

	It("generates expected callbacks for two WorkloadEndpoints with different but equivalent egress gateway policy", func() {

		we1Value := &model.WorkloadEndpoint{
			Name:                "we1",
			EgressGatewayPolicy: "egw-policy1",
		}
		we2Value := &model.WorkloadEndpoint{
			Name:                "we1",
			EgressGatewayPolicy: "egw-policy1",
		}

		By("creating two WorkloadEndpoints with similar egress gateway policy")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   egwp1Key,
				Value: egwp1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: we1Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: we2Value,
			},
			UpdateType: api.UpdateTypeKVNew,
		})

		// Expect 2 IPSetActive and 2 EgressIPSetIDUpdates.
		aec.Flush()

		ipSetID1 := cbs.ExpectActive()

		ipSetID2 := cbs.ExpectActive()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, &ComputedEgressEP{
			Rules: []EpEgressData{
				{IpSetID: "", CIDR: "10.0.0.0/8"},
				{IpSetID: ipSetID1, CIDR: "11.0.0.0/8"},
				{IpSetID: ipSetID2, CIDR: ""},
			},
		})
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #1")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we1Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect EgressUpdate for that endpoint.
		aec.Flush()

		cbs.ExpectComputedUpdate(we1Key, EPCompDataKindEgressGateway, nil)
		cbs.ExpectNoMoreCallbacks()

		By("deleting WorkloadEndpoint #2")
		aec.OnUpdate(api.Update{
			KVPair: model.KVPair{
				Key:   we2Key,
				Value: nil,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		})

		// Expect IPSetInactive for old selector.
		aec.Flush()

		cbs.ExpectComputedUpdate(we2Key, EPCompDataKindEgressGateway, nil)

		cbs.ExpectInactive(ipSetID1)

		cbs.ExpectInactive(ipSetID2)
		cbs.ExpectNoMoreCallbacks()
	})
})

type testCallbacks struct {
	activeCalls         []*IPSetData
	inactiveCalls       []*IPSetData
	computedUpdateKeys  []model.WorkloadEndpointKey
	computedUpdateKinds []EndpointComputedDataKind
	computedUpdateDatas []EndpointComputedData
}

func (tc *testCallbacks) OnIPSetActive(ipSet *IPSetData) {
	tc.activeCalls = append(tc.activeCalls, ipSet)
}

func (tc *testCallbacks) OnIPSetInactive(ipSet *IPSetData) {
	tc.inactiveCalls = append(tc.inactiveCalls, ipSet)
}

func (tc *testCallbacks) OnEndpointComputedDataUpdate(key model.WorkloadEndpointKey, kind EndpointComputedDataKind, computedData EndpointComputedData) {
	tc.computedUpdateKeys = append(tc.computedUpdateKeys, key)
	tc.computedUpdateKinds = append(tc.computedUpdateKinds, kind)
	tc.computedUpdateDatas = append(tc.computedUpdateDatas, computedData)
}

func (tc *testCallbacks) ExpectActive() string {
	ExpectWithOffset(1, len(tc.activeCalls)).To(BeNumerically(">=", 1), "Expected OnIPSetActive call")
	ExpectWithOffset(1, tc.activeCalls[0].IsEgressSelector).To(BeTrue(), "Expected IP set for an egress selector")
	ipSetID := tc.activeCalls[0].cachedUID
	ExpectWithOffset(1, ipSetID).To(HavePrefix("e:"))
	tc.activeCalls = tc.activeCalls[1:]
	return ipSetID
}

func (tc *testCallbacks) ExpectInactive(id string) {
	ExpectWithOffset(1, len(tc.inactiveCalls)).To(BeNumerically(">=", 1), "Expected OnIPSetInactive call")
	ExpectWithOffset(1, tc.inactiveCalls[0].IsEgressSelector).To(BeTrue(), "Expected IP set for an egress selector")
	ExpectWithOffset(1, tc.inactiveCalls[0].cachedUID).To(Equal(id))
	tc.inactiveCalls = tc.inactiveCalls[1:]
}

func (tc *testCallbacks) ExpectComputedUpdate(key model.WorkloadEndpointKey, kind EndpointComputedDataKind, computedData EndpointComputedData) {
	ExpectWithOffset(1, tc.computedUpdateKeys).To(ContainElement(key), "Expected OnEndpointComputedDataUpdate call")
	keyPos := -1
	for i, uk := range tc.computedUpdateKeys {
		if uk == key {
			ExpectWithOffset(1, tc.computedUpdateKinds[i]).To(Equal(kind))
			if computedData == nil {
				ExpectWithOffset(1, tc.computedUpdateDatas[i]).To(BeNil())
			} else {
				ExpectWithOffset(1, tc.computedUpdateDatas[i]).To(Equal(computedData))
			}
			keyPos = i
			break
		}
	}
	Expect(keyPos).NotTo(Equal(-1))
	tc.computedUpdateKeys = append(tc.computedUpdateKeys[:keyPos], tc.computedUpdateKeys[keyPos+1:]...)
	tc.computedUpdateKinds = append(tc.computedUpdateKinds[:keyPos], tc.computedUpdateKinds[keyPos+1:]...)
	tc.computedUpdateDatas = append(tc.computedUpdateDatas[:keyPos], tc.computedUpdateDatas[keyPos+1:]...)
}

func (tc *testCallbacks) ExpectNoMoreCallbacks() {
	ExpectWithOffset(1, len(tc.activeCalls)).To(BeZero(), "Expected no more OnIPSetActive calls")
	ExpectWithOffset(1, len(tc.inactiveCalls)).To(BeZero(), "Expected no more OnIPSetInactive calls")
	ExpectWithOffset(1, len(tc.computedUpdateKeys)).To(BeZero(), "Expected no more OnEndpointComputedDataUpdate calls")
	ExpectWithOffset(1, len(tc.computedUpdateKinds)).To(BeZero(), "Expected no more OnEndpointComputedDataUpdate calls")
	ExpectWithOffset(1, len(tc.computedUpdateDatas)).To(BeZero(), "Expected no more OnEndpointComputedDataUpdate calls")
}

var _ = Describe("ComputedEgressEP.ApplyTo", func() {
	var wep *proto.WorkloadEndpoint

	BeforeEach(func() {
		wep = &proto.WorkloadEndpoint{
			Name: "test-wep",
		}
	})

	It("should set IsEgressGateway to true when workload is an egress gateway", func() {
		computed := &ComputedEgressEP{
			IsEgressGateway: true,
			HealthPort:      8080,
		}

		computed.ApplyTo(wep)

		Expect(wep.IsEgressGateway).To(BeTrue())
		Expect(wep.EgressGatewayHealthPort).To(Equal(int32(8080)))
		Expect(wep.EgressGatewayRules).To(BeEmpty())
	})

	It("should not add egress gateway rules when workload is an egress gateway", func() {
		computed := &ComputedEgressEP{
			IsEgressGateway: true,
			HealthPort:      8080,
			Rules: []EpEgressData{
				{IpSetID: "ipset1", MaxNextHops: 5, CIDR: "10.0.0.0/8"},
			},
		}

		computed.ApplyTo(wep)

		Expect(wep.IsEgressGateway).To(BeTrue())
		Expect(wep.EgressGatewayHealthPort).To(Equal(int32(8080)))
		Expect(wep.EgressGatewayRules).To(BeEmpty(), "Rules should not be added when IsEgressGateway is true")
	})

	It("should add egress gateway rules when workload is not an egress gateway", func() {
		computed := &ComputedEgressEP{
			IsEgressGateway: false,
			Rules: []EpEgressData{
				{IpSetID: "ipset1", MaxNextHops: 5, CIDR: "10.0.0.0/8", PreferLocalGW: false},
				{IpSetID: "ipset2", MaxNextHops: 10, CIDR: "192.168.0.0/16", PreferLocalGW: true},
			},
		}

		computed.ApplyTo(wep)

		Expect(wep.IsEgressGateway).To(BeFalse())
		Expect(wep.EgressGatewayHealthPort).To(Equal(int32(0)))
		Expect(wep.EgressGatewayRules).To(HaveLen(2))

		Expect(wep.EgressGatewayRules[0].IpSetId).To(Equal("ipset1"))
		Expect(wep.EgressGatewayRules[0].MaxNextHops).To(Equal(int32(5)))
		Expect(wep.EgressGatewayRules[0].Destination).To(Equal("10.0.0.0/8"))
		Expect(wep.EgressGatewayRules[0].PreferLocalEgressGateway).To(BeFalse())

		Expect(wep.EgressGatewayRules[1].IpSetId).To(Equal("ipset2"))
		Expect(wep.EgressGatewayRules[1].MaxNextHops).To(Equal(int32(10)))
		Expect(wep.EgressGatewayRules[1].Destination).To(Equal("192.168.0.0/16"))
		Expect(wep.EgressGatewayRules[1].PreferLocalEgressGateway).To(BeTrue())
	})

	It("should handle rules with empty IpSetID and CIDR", func() {
		computed := &ComputedEgressEP{
			IsEgressGateway: false,
			Rules: []EpEgressData{
				{IpSetID: "", MaxNextHops: 0, CIDR: "10.0.0.0/8"},
				{IpSetID: "ipset1", MaxNextHops: 3, CIDR: ""},
			},
		}

		computed.ApplyTo(wep)

		Expect(wep.EgressGatewayRules).To(HaveLen(2))

		Expect(wep.EgressGatewayRules[0].IpSetId).To(Equal(""))
		Expect(wep.EgressGatewayRules[0].MaxNextHops).To(Equal(int32(0)))
		Expect(wep.EgressGatewayRules[0].Destination).To(Equal("10.0.0.0/8"))

		Expect(wep.EgressGatewayRules[1].IpSetId).To(Equal("ipset1"))
		Expect(wep.EgressGatewayRules[1].MaxNextHops).To(Equal(int32(3)))
		Expect(wep.EgressGatewayRules[1].Destination).To(Equal(""))
	})

	It("should handle empty Rules slice", func() {
		computed := &ComputedEgressEP{
			IsEgressGateway: false,
			Rules:           []EpEgressData{},
		}

		computed.ApplyTo(wep)

		Expect(wep.IsEgressGateway).To(BeFalse())
		Expect(wep.EgressGatewayRules).To(BeEmpty())
	})

	It("should handle nil Rules slice", func() {
		computed := &ComputedEgressEP{
			IsEgressGateway: false,
			Rules:           nil,
		}

		computed.ApplyTo(wep)

		Expect(wep.IsEgressGateway).To(BeFalse())
		Expect(wep.EgressGatewayRules).To(BeNil())
	})

	It("should set health port correctly when workload is egress gateway", func() {
		computed := &ComputedEgressEP{
			IsEgressGateway: true,
			HealthPort:      uint16(9090),
		}

		computed.ApplyTo(wep)

		Expect(wep.EgressGatewayHealthPort).To(Equal(int32(9090)))
	})

	It("should preserve existing workload endpoint fields", func() {
		wep.Name = "test-wep"
		wep.ProfileIds = []string{"profile1", "profile2"}
		wep.Ipv4Nets = []string{"192.168.1.10/32"}

		computed := &ComputedEgressEP{
			IsEgressGateway: false,
			Rules: []EpEgressData{
				{IpSetID: "ipset1", MaxNextHops: 5, CIDR: "10.0.0.0/8"},
			},
		}

		computed.ApplyTo(wep)

		Expect(wep.Name).To(Equal("test-wep"))
		Expect(wep.ProfileIds).To(Equal([]string{"profile1", "profile2"}))
		Expect(wep.Ipv4Nets).To(Equal([]string{"192.168.1.10/32"}))
		Expect(wep.EgressGatewayRules).To(HaveLen(1))
	})

	It("should handle multiple ApplyTo calls (appending rules)", func() {
		computed1 := &ComputedEgressEP{
			IsEgressGateway: false,
			Rules: []EpEgressData{
				{IpSetID: "ipset1", MaxNextHops: 5, CIDR: "10.0.0.0/8"},
			},
		}

		computed2 := &ComputedEgressEP{
			IsEgressGateway: false,
			Rules: []EpEgressData{
				{IpSetID: "ipset2", MaxNextHops: 10, CIDR: "192.168.0.0/16"},
			},
		}

		computed1.ApplyTo(wep)
		computed2.ApplyTo(wep)

		Expect(wep.EgressGatewayRules).To(HaveLen(2))
		Expect(wep.EgressGatewayRules[0].IpSetId).To(Equal("ipset1"))
		Expect(wep.EgressGatewayRules[1].IpSetId).To(Equal("ipset2"))
	})
})
