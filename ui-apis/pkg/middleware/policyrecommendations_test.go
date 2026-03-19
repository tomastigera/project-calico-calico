// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientsetfake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

var _ = Describe("getStageNetworkPoliciesPage", func() {
	var (
		ctx                 context.Context
		mockLmaK8sClientSet *lmak8s.MockClientSet
	)

	BeforeEach(func() {
		ctx = context.Background()

		mockLmaK8sClientSet = &lmak8s.MockClientSet{}

		mockLmaK8sClientSet.On("ProjectcalicoV3").Return(clientsetfake.NewClientset().ProjectcalicoV3())
	})

	Context("when the clientset returns valid data", func() {
		BeforeEach(func() {
			for _, snp := range snpCreateList {
				_, err := mockLmaK8sClientSet.ProjectcalicoV3().StagedNetworkPolicies(snp.Namespace).Create(ctx, &snp, metav1.CreateOptions{})
				Expect(err).To(BeNil())
			}
		})

		DescribeTable("should return a valid paged response and count",
			func(maxItems, page int, stagedAction string, expectedRes []v3.StagedNetworkPolicy, expectedCnt int) {
				actual, count, err := getStageNetworkPoliciesPage(ctx, mockLmaK8sClientSet, stagedAction, maxItems, page)

				Expect(err).ToNot(HaveOccurred())
				Expect(count).To(Equal(expectedCnt))
				Expect(len(actual)).To(Equal(len(expectedRes)))

				for i, snp := range actual {
					Expect(compareSnps(&snp, &expectedRes[i])).To(BeTrue())
				}
			},
			Entry("Learn,maxItems:5,page:1", 5, 0, "Learn", expectedLearnMaxItems5Page0, 8),
			Entry("Learn,maxItems:5,page:2", 5, 1, "Learn", expectedLearnMaxItems5Page1, 8),
			Entry("Ignore,maxItems:5,page:1", 5, 0, "Ignore", expectedIgnoreMaxItems5Page0, 6),
			Entry("Ignore,maxItems:5,page:2", 5, 1, "Ignore", expectedIgnoreMaxItems5Page1, 6),
			Entry("Set,maxItems:5,page:1", 5, 0, "Set", expectedSetMaxItems5Page0, 11),
			Entry("Set,maxItems:5,page:2", 5, 1, "Set", expectedSetMaxItems5Page1, 11),
			Entry("Set,maxItems:5,page:3", 5, 2, "Set", expectedSetMaxItems5Page2, 11),
		)
	})
})

var _ = Describe("extractPagedRecommendationParamsFromRequest", func() {
	DescribeTable("should return a set of parameters from a request with valid parameters",
		func(data []byte, expected *PagedRecommendationParams) {
			req, err := http.NewRequest("POST", "http://localhost:8080", bytes.NewBuffer(data))
			Expect(err).NotTo(HaveOccurred())

			params, err := extractPagedRecommendationParamsFromRequest(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(params).To(Equal(expected))
		},
		Entry("Learn,maxItems:5,page:0",
			[]byte(`{"stagedAction": "Learn", "maxItems": 5, "page": 0}`),
			&PagedRecommendationParams{
				StagedAction: "Learn",
				MaxItems:     5,
				Page:         0,
			},
		),
		Entry("Set,maxItems:5,page:0",
			[]byte(`{"stagedAction": "Set", "maxItems": 5, "page": 0}`),
			&PagedRecommendationParams{
				StagedAction: "Set",
				MaxItems:     5,
				Page:         0,
			},
		),
		Entry("Ignore,maxItems:5,page:0",
			[]byte(`{"stagedAction": "Ignore", "maxItems": 5, "page": 0}`),
			&PagedRecommendationParams{
				StagedAction: "Ignore",
				MaxItems:     5,
				Page:         0,
			},
		),
		Entry("Ignore,maxItems:0,page:0",
			[]byte(`{"stagedAction": "Ignore", "maxItems": 0, "page": 0}`),
			&PagedRecommendationParams{
				StagedAction: "Ignore",
				MaxItems:     0,
				Page:         0,
			},
		),
	)

	DescribeTable("should return an error for invalid parameters in the request",
		func(data []byte, expectedErr error) {
			req, err := http.NewRequest("POST", "http://localhost:8080", bytes.NewBuffer(data))
			Expect(err).NotTo(HaveOccurred())

			_, err = extractPagedRecommendationParamsFromRequest(req)
			Expect(err).To(Equal(expectedErr))
		},
		Entry("invalid page",
			[]byte(`{"stagedAction": "Learn", "maxItems": 5, "page": -1}`),
			errors.New("invalid page: -1 or max items: 5 value. Values must '>=0'"),
		),
		Entry("invalid maxItems",
			[]byte(`{"stagedAction": "Set", "maxItems": -1, "page": 0}`),
			errors.New("invalid page: 0 or max items: -1 value. Values must '>=0'"),
		),
		Entry("invalid stagedAction",
			[]byte(`{"stagedAction": "Invalid", "maxItems": 5, "page": 0}`),
			errors.New("unsupported action: Invalid"),
		),
	)
})

var _ = Describe("PagedRecommendationsHandler", func() {
	const (
		clusterID = "cluster"
		tier      = "namespace-isolation"

		recommendationsURLPath = "/pagedRecommendations"
	)

	var (
		ctx context.Context

		mockAuthenticator       *lmaauth.MockJWTAuth
		mockLmaK8sClientSet     lmak8s.MockClientSet
		mockLmaK8sClientFactory *lmak8s.MockClientSetFactory
		mockK8sClientFactory    *datastore.MockClusterCtxK8sClientFactory
	)

	BeforeEach(func() {
		ctx = context.Background()

		mockAuthenticator = &lmaauth.MockJWTAuth{}
		mockLmaK8sClientFactory = &lmak8s.MockClientSetFactory{}
		mockLmaK8sClientSet = lmak8s.MockClientSet{}

		mockAuthenticator.On("Authenticate", mock.Anything).Return(&user.DefaultInfo{}, http.StatusOK, nil)

		mockLmaK8sClientFactory.On("NewClientSetForUser", mock.Anything, clusterID).Return(&mockLmaK8sClientSet, nil)

		mockLmaK8sClientSet.On("ProjectcalicoV3").Return(clientsetfake.NewClientset().ProjectcalicoV3())
		mockLmaK8sClientSet.On("CoreV1").Return(fakeK8s.NewClientset().CoreV1())
	})

	Context("when the clientset returns valid data", func() {
		BeforeEach(func() {
			// Load our calico client with test data
			for _, snp := range snpCreateList {
				_, err := mockLmaK8sClientSet.ProjectcalicoV3().StagedNetworkPolicies(snp.Namespace).Create(ctx, &snp, metav1.CreateOptions{})
				Expect(err).To(BeNil())

			}
		})

		DescribeTable("should return a valid paged response and count",
			func(query *PagedRecommendationParams, expected *Recommendations) {
				// Request is handled after calling hdlr.ServeHTTP
				hdlr := PagedRecommendationsHandler(mockAuthenticator, mockLmaK8sClientFactory, mockK8sClientFactory)

				jsonQuery, err := json.Marshal(query)
				Expect(err).To(BeNil())
				req, err := http.NewRequest(
					http.MethodPost, recommendationsURLPath, bytes.NewBuffer(jsonQuery))
				Expect(err).To(BeNil())
				// Add a bogus user
				req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

				// PagedRecommendationsHandler is called once the request is served
				w := httptest.NewRecorder()
				hdlr.ServeHTTP(w, req)
				Expect(err).To(BeNil())

				body, err := io.ReadAll(w.Body)
				Expect(err).To(BeNil())

				// Verify
				actual := &Recommendations{}
				if len(body) > 0 {
					err = json.Unmarshal(body, &actual)
					Expect(err).To(BeNil())
					Expect(actual).To(Equal(expected))
				}
			},
			Entry("Learn,maxItems:5,page:0",
				&PagedRecommendationParams{
					StagedAction: "Learn",
					Page:         0,
					MaxItems:     5,
				},
				&Recommendations{
					Count:                 8,
					StagedNetworkPolicies: expectedLearnMaxItems5Page0,
				},
			),
			Entry("Learn,maxItems:5,page:1",
				&PagedRecommendationParams{
					StagedAction: "Learn",
					Page:         1,
					MaxItems:     5,
				},
				&Recommendations{
					Count:                 8,
					StagedNetworkPolicies: expectedLearnMaxItems5Page1,
				},
			),
			Entry("Ignore,maxItems:5,page:0",
				&PagedRecommendationParams{
					StagedAction: "Ignore",
					Page:         0,
					MaxItems:     5,
				},
				&Recommendations{
					Count:                 6,
					StagedNetworkPolicies: expectedIgnoreMaxItems5Page0,
				},
			),
			Entry("Ignore,maxItems:5,page:1",
				&PagedRecommendationParams{
					StagedAction: "Ignore",
					Page:         1,
					MaxItems:     5,
				},
				&Recommendations{
					Count:                 6,
					StagedNetworkPolicies: expectedIgnoreMaxItems5Page1,
				},
			),
			Entry("Set,maxItems:5,page:0",
				&PagedRecommendationParams{
					StagedAction: "Set",
					Page:         0,
					MaxItems:     5,
				},
				&Recommendations{
					Count:                 11,
					StagedNetworkPolicies: expectedSetMaxItems5Page0,
				},
			),
			Entry("Set,maxItems:5,page:1",
				&PagedRecommendationParams{
					StagedAction: "Set",
					Page:         1,
					MaxItems:     5,
				},
				&Recommendations{
					Count:                 11,
					StagedNetworkPolicies: expectedSetMaxItems5Page1,
				},
			),
			Entry("Set,maxItems:5,page:2",
				&PagedRecommendationParams{
					StagedAction: "Set",
					Page:         2,
					MaxItems:     5,
				},
				&Recommendations{
					Count:                 11,
					StagedNetworkPolicies: expectedSetMaxItems5Page2,
				},
			),
		)
	})

	DescribeTable("should return an error for invalid parameters",
		func(query *PagedRecommendationParams, expectedError error) {
			// Request is handled after calling hdlr.ServeHTTP
			hdlr := PagedRecommendationsHandler(mockAuthenticator, mockLmaK8sClientFactory, mockK8sClientFactory)

			jsonQuery, err := json.Marshal(query)
			Expect(err).To(BeNil())
			req, err := http.NewRequest(
				http.MethodPost, recommendationsURLPath, bytes.NewBuffer(jsonQuery))
			Expect(err).To(BeNil())
			// Add a bogus user
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			// PagedRecommendationsHandler is called once the request is served
			w := httptest.NewRecorder()
			hdlr.ServeHTTP(w, req)
			Expect(err).To(BeNil())

			body, err := io.ReadAll(w.Body)
			Expect(err).To(BeNil())

			// Verify
			var errorMessage struct {
				Message string "json:\"message\""
			}
			if len(body) > 0 {
				err = json.Unmarshal(body, &errorMessage)
				Expect(err).To(BeNil())
				Expect(errorMessage.Message).To(Equal(expectedError.Error()))
			}
		},
		Entry("invalid page",
			&PagedRecommendationParams{
				StagedAction: "Learn",
				Page:         -1,
				MaxItems:     5,
			},
			errors.New("invalid page: -1 or max items: 5 value. Values must '>=0'"),
		),
		Entry("invalid maxItems",
			&PagedRecommendationParams{
				StagedAction: "Learn",
				Page:         1,
				MaxItems:     -5,
			},
			errors.New("invalid page: 1 or max items: -5 value. Values must '>=0'"),
		),
		Entry("invalid staged action",
			&PagedRecommendationParams{
				StagedAction: "Invalid",
				Page:         0,
				MaxItems:     5,
			},
			errors.New("unsupported action: Invalid"),
		),
	)
})

func compareSnps(actual, exptected *v3.StagedNetworkPolicy) bool {
	Expect(actual.Name).To(Equal(exptected.Name), "Unexpected name")
	Expect(actual.Namespace).To(Equal(exptected.Namespace), "Unexpected namespace")
	Expect(actual.Spec.StagedAction).To(Equal(exptected.Spec.StagedAction), "unexpected stagedAction")

	return true
}

var (
	snpCreateList = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns11-recommendation",
				Namespace: "ns11",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns1-recommendation",
				Namespace: "ns1",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns3-recommendation",
				Namespace: "ns3",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns17-recommendation",
				Namespace: "ns17",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns5-recommendation",
				Namespace: "ns5",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns2-recommendation",
				Namespace: "ns2",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns21-recommendation",
				Namespace: "ns21",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns6-recommendation",
				Namespace: "ns6",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns7-recommendation",
				Namespace: "ns7",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns8-recommendation",
				Namespace: "ns8",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns9-recommendation",
				Namespace: "ns9",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns25-recommendation",
				Namespace: "ns25",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns10-recommendation",
				Namespace: "ns10",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns4-recommendation",
				Namespace: "ns4",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns13-recommendation",
				Namespace: "ns13",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns14-recommendation",
				Namespace: "ns14",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns23-recommendation",
				Namespace: "ns23",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns15-recommendation",
				Namespace: "ns15",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns16-recommendation",
				Namespace: "ns16",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns18-recommendation",
				Namespace: "ns18",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns19-recommendation",
				Namespace: "ns19",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns20-recommendation",
				Namespace: "ns20",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns12-recommendation",
				Namespace: "ns12",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns22-recommendation",
				Namespace: "ns22",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns24-recommendation",
				Namespace: "ns24",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
	}

	expectedLearnMaxItems5Page0 = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns11-recommendation",
				Namespace: "ns11",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns16-recommendation",
				Namespace: "ns16",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns20-recommendation",
				Namespace: "ns20",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns21-recommendation",
				Namespace: "ns21",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns23-recommendation",
				Namespace: "ns23",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
	}

	expectedLearnMaxItems5Page1 = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns25-recommendation",
				Namespace: "ns25",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns3-recommendation",
				Namespace: "ns3",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns8-recommendation",
				Namespace: "ns8",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Learn",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
				Tier:         "namespace-isolation",
			},
		},
	}

	expectedIgnoreMaxItems5Page0 = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns14-recommendation",
				Namespace: "ns14",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns17-recommendation",
				Namespace: "ns17",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns2-recommendation",
				Namespace: "ns2",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns4-recommendation",
				Namespace: "ns4",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns5-recommendation",
				Namespace: "ns5",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
	}

	expectedIgnoreMaxItems5Page1 = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns9-recommendation",
				Namespace: "ns9",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Ignore",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
				Tier:         "namespace-isolation",
			},
		},
	}

	expectedSetMaxItems5Page0 = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns1-recommendation",
				Namespace: "ns1",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns10-recommendation",
				Namespace: "ns10",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns12-recommendation",
				Namespace: "ns12",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns13-recommendation",
				Namespace: "ns13",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns15-recommendation",
				Namespace: "ns15",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
	}

	expectedSetMaxItems5Page1 = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns18-recommendation",
				Namespace: "ns18",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns19-recommendation",
				Namespace: "ns19",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns22-recommendation",
				Namespace: "ns22",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns24-recommendation",
				Namespace: "ns24",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns6-recommendation",
				Namespace: "ns6",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
	}

	expectedSetMaxItems5Page2 = []v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "namespace-isolation.ns7-recommendation",
				Namespace: "ns7",
				Labels: map[string]string{
					"projectcalico.org/tier":                "namespace-isolation",
					"projectcalico.org/ownerReference.kind": "PolicyRecommendationScope",
					"projectcalico.org/spec.stagedAction":   "Set",
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
				Tier:         "namespace-isolation",
			},
		},
	}
)
