// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
package rbac_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/rbac"
)

var _ = Describe("FlowHelper tests", func() {
	var mockAuthorizer *auth.MockRBACAuthorizer
	BeforeEach(func() {
		mockAuthorizer = new(auth.MockRBACAuthorizer)
	})
	It("caches unauthorized results", func() {
		usr := &user.DefaultInfo{}
		rh := rbac.NewCachedFlowHelper(usr, mockAuthorizer)
		mockAuthorizer.On("Authorize", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Times(4)

		By("checking permissions requiring 4 lookups")
		Expect(rh.CanListHostEndpoints()).To(BeFalse())
		Expect(rh.CanListNetworkSets("ns1")).To(BeFalse())
		Expect(rh.CanListPods("ns1")).To(BeFalse())
		Expect(rh.CanListGlobalNetworkSets()).To(BeFalse())

		By("checking the same permissions with cached results")
		Expect(rh.CanListHostEndpoints()).To(BeFalse())
		Expect(rh.CanListNetworkSets("ns1")).To(BeFalse())
		Expect(rh.CanListPods("ns1")).To(BeFalse())
		Expect(rh.CanListGlobalNetworkSets()).To(BeFalse())

		mockAuthorizer.AssertExpectations(GinkgoT())
	})

	DescribeTable(
		"CanListPolicy with global network policies",
		func(expectedCan bool, expectedCalls func(mockAuthorizer *auth.MockRBACAuthorizer)) {
			ph, err := api.PolicyHitFromFlowLogPolicyString("0|tier1|tier1.gnp|allow", 0)
			Expect(err).ShouldNot(HaveOccurred())

			expectedCalls(mockAuthorizer)
			rh := rbac.NewCachedFlowHelper(&user.DefaultInfo{}, mockAuthorizer)
			Expect(rh.CanListPolicy(ph)).To(Equal(expectedCan))
		},
		Entry("Returns false without get access to tiers",
			false,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(false, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to specific tier",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(true, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "tier.globalnetworkpolicies"},
					mock.Anything).Return(false, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "tier.globalnetworkpolicies", Name: "tier1.*"},
					mock.Anything).Return(true, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to tiers",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(true, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "tier.globalnetworkpolicies"},
					mock.Anything).Return(true, nil)
			},
		),
	)

	DescribeTable(
		"CanListPolicy with staged global network policies",
		func(expectedCan bool, expectedCalls func(mockAuthorizer *auth.MockRBACAuthorizer)) {
			ph, err := api.PolicyHitFromFlowLogPolicyString("0|tier1|staged:tier1.gnp|allow|0", 0)
			Expect(err).ShouldNot(HaveOccurred())

			expectedCalls(mockAuthorizer)
			rh := rbac.NewCachedFlowHelper(&user.DefaultInfo{}, mockAuthorizer)
			Expect(rh.CanListPolicy(ph)).To(Equal(expectedCan))
		},
		Entry("Returns false without get access to tiers",
			false,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(false, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to specific tier",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(true, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "tier.stagedglobalnetworkpolicies"},
					mock.Anything).Return(false, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "tier.stagedglobalnetworkpolicies", Name: "tier1.*"},
					mock.Anything).Return(true, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to tiers",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(true, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "tier.stagedglobalnetworkpolicies"},
					mock.Anything).Return(true, nil)
			},
		),
	)

	DescribeTable(
		"CanListPolicy with network policies",
		func(expectedCan bool, expectedCalls func(mockAuthorizer *auth.MockRBACAuthorizer)) {
			ph, err := api.PolicyHitFromFlowLogPolicyString("0|tier1|ns1/tier1.np|allow", 0)
			Expect(err).ShouldNot(HaveOccurred())

			expectedCalls(mockAuthorizer)
			rh := rbac.NewCachedFlowHelper(&user.DefaultInfo{}, mockAuthorizer)
			Expect(rh.CanListPolicy(ph)).To(Equal(expectedCan))
		},
		Entry("Returns false without get access to tiers",
			false,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(false, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to specific tier",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(true, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Namespace: "ns1", Verb: "list", Group: "projectcalico.org", Resource: "tier.networkpolicies"},
					mock.Anything).Return(false, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Namespace: "ns1", Verb: "list", Group: "projectcalico.org", Resource: "tier.networkpolicies", Name: "tier1.*"},
					mock.Anything).Return(true, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to tiers",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Verb: "get", Group: "projectcalico.org", Resource: "tiers", Name: "tier1"},
					mock.Anything).Return(true, nil)
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Namespace: "ns1", Verb: "list", Group: "projectcalico.org", Resource: "tier.networkpolicies"},
					mock.Anything).Return(true, nil)
			},
		),
	)

	DescribeTable(
		"CanListPolicy with kubernetes network policies",
		func(expectedCan bool, expectedCalls func(mockAuthorizer *auth.MockRBACAuthorizer)) {
			ph, err := api.PolicyHitFromFlowLogPolicyString("0|default|ns1/knp.default.np|allow|0", 0)
			Expect(err).ShouldNot(HaveOccurred())

			expectedCalls(mockAuthorizer)
			rh := rbac.NewCachedFlowHelper(&user.DefaultInfo{}, mockAuthorizer)
			Expect(rh.CanListPolicy(ph)).To(Equal(expectedCan))
		},
		Entry("Returns false without get access to tiers",
			false,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Namespace: "ns1", Verb: "list", Group: "networking.k8s.io", Resource: "networkpolicies"},
					mock.Anything).Return(false, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to specific tier",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Namespace: "ns1", Verb: "list", Group: "networking.k8s.io", Resource: "networkpolicies"},
					mock.Anything).Return(true, nil)
			},
		),
	)

	DescribeTable(
		"CanListPolicy with staged kubernetes network policies",
		func(expectedCan bool, expectedCalls func(mockAuthorizer *auth.MockRBACAuthorizer)) {
			ph, err := api.PolicyHitFromFlowLogPolicyString("0|default|ns1/staged:knp.default.np|allow|0", 0)
			Expect(err).ShouldNot(HaveOccurred())

			expectedCalls(mockAuthorizer)
			rh := rbac.NewCachedFlowHelper(&user.DefaultInfo{}, mockAuthorizer)
			Expect(rh.CanListPolicy(ph)).To(Equal(expectedCan))
		},
		Entry("Returns false without get access to tiers",
			false,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Namespace: "ns1", Verb: "list", Group: "projectcalico.org", Resource: "stagedkubernetesnetworkpolicies"},
					mock.Anything).Return(false, nil)
			},
		),
		Entry("Returns true with get access to tiers and list access to specific tier",
			true,
			func(mockAuthorizer *auth.MockRBACAuthorizer) {
				mockAuthorizer.On("Authorize", mock.Anything,
					&authzv1.ResourceAttributes{Namespace: "ns1", Verb: "list", Group: "projectcalico.org", Resource: "stagedkubernetesnetworkpolicies"},
					mock.Anything).Return(true, nil)
			},
		),
	)

	DescribeTable(
		"CanListEndpoint",
		func(endpointType api.EndpointType, namespace string, expectResourceAttrs *authzv1.ResourceAttributes) {
			mockAuthorizer.On("Authorize", mock.Anything, expectResourceAttrs, mock.Anything).Return(true, nil)

			rh := rbac.NewCachedFlowHelper(&user.DefaultInfo{}, mockAuthorizer)
			_, _ = rh.CanListEndpoint(endpointType, namespace)
		},
		Entry(
			"requests authorization to list a GlobalNetworkSets",
			api.EndpointTypeNs, api.GlobalEndpointType,
			&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "globalnetworksets"},
		),
		Entry(
			"requests authorization to list NetworkSets in all namespaces",
			api.EndpointTypeNs, "",
			&authzv1.ResourceAttributes{Verb: "list", Group: "projectcalico.org", Resource: "networksets"},
		),
	)
})
