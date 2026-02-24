// Copyright (c) 2019, 2022 Tigera, Inc. All rights reserved.
package policyrec_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientsetfake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/lma/pkg/api"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/lma/pkg/policyrec"
)

const defaultTier = "default"

// flowWithError is a convenience type for passing in a flow along
// with whether it is processed successfully or not.
type flowWithError struct {
	flow        api.Flow
	shouldError bool
}

var _ = Describe("Policy Recommendation Engine", func() {
	var (
		re                  policyrec.RecommendationEngine
		err                 error
		mockLmaK8sClientSet *lmak8s.MockClientSet
		req                 *http.Request
	)

	BeforeEach(func() {
		req = &http.Request{Header: http.Header{}}
	})

	DescribeTable("Recommend policies for matching flows and endpoint",
		// endpointName and endpointNamespace are params for which recommended policies should be generated for.
		// They are used to configure the recommendation engine.
		// matchingFlows is the input flows that are passed to ProcessFlows.
		// expectedPolicies is a slice of StagedNetworkPolicy or StagedGlobalNetworkPolicy.
		func(
			namespace1, namespace2 *corev1.Namespace,
			endpointName, endpointNamespace, policyTier string, policyOrder *float64,
			matchingFlows []flowWithError, expectedPolicies any) {

			// Define the kubernetes interface
			mockLmaK8sClientSet = &lmak8s.MockClientSet{}
			mockLmaK8sClientSet.On("ProjectcalicoV3").Return(
				clientsetfake.NewSimpleClientset().ProjectcalicoV3(),
			)
			coreV1 := fake.NewSimpleClientset().CoreV1()
			_, err = coreV1.Namespaces().Create(req.Context(), namespace1Object, metav1.CreateOptions{})
			Expect(err).To(BeNil())
			_, err = coreV1.Namespaces().Create(req.Context(), namespace2Object, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			appV1 := fake.NewSimpleClientset().AppsV1()
			batchV1 := fake.NewSimpleClientset().BatchV1()
			batchV1Beta1 := fake.NewSimpleClientset().BatchV1beta1()

			// Define the return methods called by this test.
			mockLmaK8sClientSet.On("CoreV1").Return(coreV1)
			mockLmaK8sClientSet.On("AppsV1").Return(appV1)
			mockLmaK8sClientSet.On("BatchV1").Return(batchV1)
			mockLmaK8sClientSet.On("BatchV1beta1").Return(batchV1Beta1)

			By("Initializing a recommendation engine with namespace and name")
			re = policyrec.NewEndpointRecommendationEngine(mockLmaK8sClientSet, endpointName, endpointNamespace, policyTier, policyOrder)

			for _, flow := range matchingFlows {
				By("Processing matching flow")
				err = re.ProcessFlow(flow.flow)
				if flow.shouldError {
					Expect(err).ToNot(BeNil())
				} else {
					Expect(err).To(BeNil())
				}
			}

			By("Once all matched flows have been input for matching endpoint and getting recommended flows")
			recommendation, err := re.Recommend()
			Expect(err).To(BeNil())
			if policyrec.IsEmptyNamespace(endpointName) && !policyrec.IsEmptyNamespace(endpointNamespace) {
				// Expect only StagedGlobalNetworkPolicies.
				policies := expectedPolicies.([]*v3.StagedNetworkPolicy)
				// We loop through each expected policy and check instead of using ConsistsOf() matcher so that
				// we can use our custom MatchPolicy() Gomega matcher.
				for _, expectedPolicy := range policies {
					Expect(recommendation.NetworkPolicies).To(ContainElement(policyrec.MatchPolicy(expectedPolicy)))
				}
			} else if policyrec.IsEmptyNamespace(endpointNamespace) {
				// Expect only StagedGlobalNetworkPolicies.
				policies := expectedPolicies.([]*v3.StagedGlobalNetworkPolicy)
				// We loop through each expected policy and check instead of using ConsistsOf() matcher so that
				// we can use our custom MatchPolicy() Gomega matcher.
				for _, expectedPolicy := range policies {
					Expect(recommendation.GlobalNetworkPolicies).To(ContainElement(policyrec.MatchPolicy(expectedPolicy)))
				}
			} else {
				// Expect only StagedNetworkPolicies if a namespace is defined.
				policies := expectedPolicies.([]*v3.StagedNetworkPolicy)
				// We loop through each expected policy and check instead of using ConsistsOf() matcher so that
				// we can use our custom MatchPolicy() Gomega matcher.
				for _, expectedPolicy := range policies {
					Expect(recommendation.NetworkPolicies).To(ContainElement(policyrec.MatchPolicy(expectedPolicy)))
				}
			}
		},
		Entry("recommend a policy with egress rule for a flow between 2 endpoints and matching source endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod1Aggr, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, true},
			},
			[]*v3.StagedNetworkPolicy{networkPolicyNamespace1Pod1BlueToPod2}),
		Entry("recommend a policy with egress rule for a flow between 2 endpoints with a non overlapping label - and matching source endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod1Aggr, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, true},
				{flowPod1RedToPod2Allow443ReporterSource, false},
				{flowPod1RedToPod2Allow443ReporterDestination, true},
			},
			[]*v3.StagedNetworkPolicy{egressNetworkPolicyNamespace1Pod1ToPod2}),
		Entry("recommend a policy with ingress rule for a flow between 2 endpoints with a non overlapping label - and matching source endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod2Aggr, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, true},
				{flowPod1BlueToPod2Allow443ReporterDestination, false},
				{flowPod1RedToPod2Allow443ReporterSource, true},
				{flowPod1RedToPod2Allow443ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{ingressNetworkPolicyNamespace1Pod1ToPod2}),
		Entry("recommend a policy with egress rule for a flow between 2 endpoints and external network and matching source endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod1Aggr, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, true},
				{flowPod1BlueToExternalAllow53ReporterSource, false},
			},
			[]*v3.StagedNetworkPolicy{networkPolicyNamespace1Pod1BlueToPod2AndExternalNet}),
		Entry("recommend a policy with egress rule for a flow between 2 endpoints and matching source endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod1Aggr, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, true},
				{flowPod1BlueToPod3Allow5432ReporterSource, false},
				{flowPod1BlueToPod3Allow5432ReporterDestination, true},
				{flowPod1RedToPod3Allow8080ReporterSource, false},
				{flowPod1RedToPod3Allow8080ReporterDestination, true},
			},
			[]*v3.StagedNetworkPolicy{networkPolicyNamespace1Pod1ToPod2AndPod3}),
		Entry("recommend a policy with ingress and egress rules for a flow between 2 endpoints and matching source and destination endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod2Aggr, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, true},
				{flowPod1BlueToPod2Allow443ReporterDestination, false},
				{flowPod2ToPod3Allow5432ReporterSource, false},
				{flowPod2ToPod3Allow5432ReporterDestination, true},
			},
			[]*v3.StagedNetworkPolicy{networkPolicyNamespace1Pod2}),
		Entry("recommend a policy with ingress rule for flows and matching destination endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod3Aggr, namespace2, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod3Allow5432ReporterSource, true},
				{flowPod1BlueToPod3Allow5432ReporterDestination, false},
				{flowPod1RedToPod3Allow8080ReporterSource, true},
				{flowPod1RedToPod3Allow8080ReporterDestination, false},
				{flowPod2ToPod3Allow5432ReporterSource, true},
				{flowPod2ToPod3Allow5432ReporterDestination, false},
				{flowGlobalNetworkSet1ToPod3Allow5432ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{networkPolicyNamespace1Pod3}),
		Entry("recommend a policy with ingress rule for a flow between 3 endpoints with no intersecting label - and matching destination endpoint",
			&corev1.Namespace{}, &corev1.Namespace{}, pod3Aggr, namespace2, defaultTier, nil,
			[]flowWithError{
				{flowPod4Rs1ToPod3Allow5432ReporterDestination, false},
				{flowPod4Rs2ToPod3Allow5432ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{ingressNetworkPolicyToNamespace2Pod3FromPod4Port5432}),
		Entry("recommend a policy with ingress rule for a flow between 3 endpoints with no intersecting label - and matching destination endpoint and 2 ports",
			&corev1.Namespace{}, &corev1.Namespace{}, pod3Aggr, namespace2, defaultTier, nil,
			[]flowWithError{
				{flowPod4Rs1ToPod3Allow5432ReporterDestination, false},
				{flowPod4Rs2ToPod3Allow5432ReporterDestination, false},
				{flowPod4Rs1ToPod3Allow8080ReporterDestination, false},
				{flowPod4Rs2ToPod3Allow8080ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{ingressNetworkPolicyToNamespace2Pod3FromPod4Port5432And8080}),
		Entry("recommend a namespace policy with egress rule for a flow between 2 endpoints and matching source endpoint",
			namespace1Object, namespace2Object, emptyEndpoint, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{namespaceNetworkPolicyNamespace1Pod1BlueToPod2}),
		Entry("recommend a policy namespace with egress rule for a flow between 2 endpoints with a non overlapping label - and matching source endpoint",
			namespace1Object, namespace2Object, emptyEndpoint, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, false},
				{flowPod1RedToPod2Allow443ReporterSource, false},
				{flowPod1RedToPod2Allow443ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{namespaceEgressNetworkPolicyNamespace1Pod1ToPod2}),
		Entry("recommend a policy namespace with egress rule for a flow between 2 endpoints and external network and matching source endpoint",
			namespace1Object, namespace2Object, emptyEndpoint, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, false},
				{flowPod1BlueToExternalAllow53ReporterSource, false},
			},
			[]*v3.StagedNetworkPolicy{namespaceNetworkPolicyNamespace1Pod1BlueToPod2AndExternalNet}),
		Entry("recommend a policy namespace with egress rule for a flow between 2 endpoints and matching source endpoint",
			namespace1Object, namespace2Object, emptyEndpoint, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, false},
				{flowPod1BlueToPod3Allow5432ReporterSource, false},
				{flowPod1BlueToPod3Allow5432ReporterDestination, true},
				{flowPod1RedToPod3Allow8080ReporterSource, false},
				{flowPod1RedToPod3Allow8080ReporterDestination, true},
			},
			[]*v3.StagedNetworkPolicy{namespaceNetworkPolicyNamespace1Pod1ToPod2AndPod3}),
		Entry("recommend a policy namespace with ingress and egress rules for a flow between 2 endpoints and matching source and destination endpoint",
			namespace1Object, namespace2Object, emptyEndpoint, namespace1, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod2Allow443ReporterSource, false},
				{flowPod1BlueToPod2Allow443ReporterDestination, false},
				{flowPod2ToPod3Allow5432ReporterSource, false},
				{flowPod2ToPod3Allow5432ReporterDestination, true},
			},
			[]*v3.StagedNetworkPolicy{namespaceNetworkPolicyNamespace1Pod2}),
		Entry("recommend a policy namespace with ingress rule for flows and matching destination endpoint",
			namespace1Object, namespace2Object, emptyEndpoint, namespace2, defaultTier, nil,
			[]flowWithError{
				{flowPod1BlueToPod3Allow5432ReporterSource, true},
				{flowPod1BlueToPod3Allow5432ReporterDestination, false},
				{flowPod1RedToPod3Allow8080ReporterSource, true},
				{flowPod1RedToPod3Allow8080ReporterDestination, false},
				{flowPod2ToPod3Allow5432ReporterSource, true},
				{flowPod2ToPod3Allow5432ReporterDestination, false},
				{flowGlobalNetworkSet1ToPod3Allow5432ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{namespaceNetworkPolicyNamespace1Pod3}),
		Entry("recommend a policy namespace with ingress rule for a flow between 3 endpoints with no intersecting label - and matching destination endpoint",
			namespace1Object, namespace2Object, emptyEndpoint, namespace2, defaultTier, nil,
			[]flowWithError{
				{flowPod4Rs1ToPod3Allow5432ReporterDestination, false},
				{flowPod4Rs2ToPod3Allow5432ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{namespaceIngressNetworkPolicyToNamespace2Pod3FromPod4Port5432}),
		Entry("recommend a namespace policy with ingress rule for a flow between 3 endpoints with no intersecting label - and matching destination endpoint and 2 ports",
			namespace1Object, namespace2Object, emptyEndpoint, namespace2, defaultTier, nil,
			[]flowWithError{
				{flowPod4Rs1ToPod3Allow5432ReporterDestination, false},
				{flowPod4Rs2ToPod3Allow5432ReporterDestination, false},
				{flowPod4Rs1ToPod3Allow8080ReporterDestination, false},
				{flowPod4Rs2ToPod3Allow8080ReporterDestination, false},
			},
			[]*v3.StagedNetworkPolicy{namespaceIngressNetworkPolicyToNamespace2Pod3FromPod4Port5432And8080}),
	)
	It("should reject flows that don't match endpoint name and namespace", func() {
		// Define the mock lma k8s client set.
		mockLmaK8sClientSet = &lmak8s.MockClientSet{}

		By("Initializing a recommendation engine with namespace and name")
		re = policyrec.NewEndpointRecommendationEngine(mockLmaK8sClientSet, pod1Aggr, namespace1, defaultTier, nil)

		By("Processing flow that don't match")
		err = re.ProcessFlow(flowPod2ToPod3Allow5432ReporterSource)
		Expect(err).ToNot(BeNil())
		err = re.ProcessFlow(flowPod2ToPod3Allow5432ReporterDestination)
		Expect(err).ToNot(BeNil())
	})
	It("should reject flows that are for endpoint type that isn't wep", func() {
		// Define the kubernetes interface
		mockLmaK8sClientSet = &lmak8s.MockClientSet{}

		By("Initializing a recommendation engine with namespace and name")
		re = policyrec.NewEndpointRecommendationEngine(mockLmaK8sClientSet, ns1Aggr, namespace1, defaultTier, nil)

		By("Processing flow that don't match")
		err = re.ProcessFlow(flowPod2ToNs1Allow80ReporterSource)
		Expect(err).ToNot(BeNil())
	})
	It("should not produce any policies for flows that match endpoint name and namespace but not direction reported", func() {
		// Define the kubernetes interface
		mockLmaK8sClientSet = &lmak8s.MockClientSet{}
		appV1 := fake.NewSimpleClientset().AppsV1()
		coreV1 := fake.NewSimpleClientset().CoreV1()
		batchV1 := fake.NewSimpleClientset().BatchV1()
		batchV1Beta1 := fake.NewSimpleClientset().BatchV1beta1()
		// Define the return methods called by this test.
		mockLmaK8sClientSet.On("CoreV1").Return(coreV1)
		mockLmaK8sClientSet.On("AppsV1").Return(appV1)
		mockLmaK8sClientSet.On("BatchV1").Return(batchV1)
		mockLmaK8sClientSet.On("BatchV1beta1").Return(batchV1Beta1)

		By("Initializing a recommendation engine with namespace and name")
		re = policyrec.NewEndpointRecommendationEngine(mockLmaK8sClientSet, pod2Aggr, namespace1, defaultTier, nil)

		By("Processing flow that don't match")
		err = re.ProcessFlow(flowPod1BlueToPod2Allow443ReporterSource)
		Expect(err).ToNot(BeNil())
		err = re.ProcessFlow(flowPod1RedToPod2Allow443ReporterSource)
		Expect(err).ToNot(BeNil())

		_, err = re.Recommend()
		Expect(err).ToNot(BeNil())
	})
	It("should not produce any policies for flows that match endpoint name and namespace but not direction reported", func() {
		// Define the kubernetes interface
		mockLmaK8sClientSet = &lmak8s.MockClientSet{}
		mockLmaK8sClientSet.On("ProjectcalicoV3").Return(
			clientsetfake.NewSimpleClientset().ProjectcalicoV3(),
		)
		coreV1 := fake.NewSimpleClientset().CoreV1()
		_, err = coreV1.Namespaces().Create(req.Context(), namespace1Object, metav1.CreateOptions{})
		Expect(err).To(BeNil())
		_, err = coreV1.Namespaces().Create(req.Context(), namespace2Object, metav1.CreateOptions{})
		Expect(err).To(BeNil())

		appV1 := fake.NewSimpleClientset().AppsV1()

		batchV1 := fake.NewSimpleClientset().BatchV1()

		batchV1Beta1 := fake.NewSimpleClientset().BatchV1beta1()

		// Define the return methods called by this test.
		mockLmaK8sClientSet.On("CoreV1").Return(coreV1)
		mockLmaK8sClientSet.On("AppsV1").Return(appV1)
		mockLmaK8sClientSet.On("BatchV1").Return(batchV1)
		mockLmaK8sClientSet.On("BatchV1beta1").Return(batchV1Beta1)

		By("Initializing a recommendation engine with namespace and name")
		re = policyrec.NewEndpointRecommendationEngine(mockLmaK8sClientSet, pod2Aggr, namespace1, defaultTier, nil)

		By("Processing flow that don't match")
		err = re.ProcessFlow(flowPod1BlueToPod2Allow443ReporterSource)
		Expect(err).ToNot(BeNil())
		err = re.ProcessFlow(flowPod1RedToPod2Allow443ReporterSource)
		Expect(err).ToNot(BeNil())

		_, err = re.Recommend()
		Expect(err).ToNot(BeNil())
	})
})
