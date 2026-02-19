// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	clientsetfake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	fakeK8s "k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/compliance/pkg/datastore"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

const (
	recommendationBatchURLPath = "/recommendationBatch"
)

var _ = Describe("Policy Recommendation Batch", func() {
	const (
		clusterID = "cluster"
		tier      = "namespace-isolation"
	)

	var (
		errorMessage struct {
			Message string `json:"message"`
		}

		mockAuthenticator       *lmaauth.MockJWTAuth
		mockLmaK8sClientFactory *lmak8s.MockClientSetFactory
		mockK8sClientFactory    *datastore.MockClusterCtxK8sClientFactory
	)

	BeforeEach(func() {
		mockAuthenticator = &lmaauth.MockJWTAuth{}
		mockLmaK8sClientFactory = &lmak8s.MockClientSetFactory{}
		mockLmaK8sClientSet := lmak8s.MockClientSet{}

		mockAuthenticator.On("Authenticate", mock.Anything).Return(&user.DefaultInfo{}, http.StatusOK, nil)

		mockLmaK8sClientFactory.On("NewClientSetForApplication", clusterID).Return(&mockLmaK8sClientSet, nil)
		mockLmaK8sClientFactory.On("NewClientSetForUser", mock.Anything, clusterID).Return(&mockLmaK8sClientSet, nil)

		mockLmaK8sClientSet.On("ProjectcalicoV3").Return(clientsetfake.NewSimpleClientset().ProjectcalicoV3())
		mockLmaK8sClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1())
	})

	DescribeTable("Batch update staged network policy staged actions",
		func(query *BatchStagedActionParams, expectedSnps []*v3.StagedNetworkPolicy) {
			jsonQuery, err := json.Marshal(query)
			Expect(err).To(BeNil())

			req, err := http.NewRequest(
				http.MethodPatch, recommendationBatchURLPath, bytes.NewBuffer(jsonQuery))
			Expect(err).To(BeNil())

			cs, err := mockLmaK8sClientFactory.NewClientSetForApplication(clusterID)
			Expect(err).NotTo(HaveOccurred())

			// Create staged network policies for test
			err = createSnps(req.Context(), cs)
			Expect(err).NotTo(HaveOccurred())

			By("Updating the snp StagedAction to set")
			hdlr := BatchStagedActionsHandler(mockAuthenticator, mockLmaK8sClientFactory,
				mockK8sClientFactory)

			// Add a bogus user
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			w := httptest.NewRecorder()
			hdlr.ServeHTTP(w, req)
			Expect(err).To(BeNil())

			_, err = io.ReadAll(w.Body)
			Expect(err).To(BeNil())

			// Get the list of updated staged network policies
			snpList, err := cs.ProjectcalicoV3().StagedNetworkPolicies("").List(req.Context(), metav1.ListOptions{})
			Expect(err).To(BeNil())

			for i, snp := range snpList.Items {
				Expect(reflect.DeepEqual(snp.ObjectMeta.OwnerReferences, expectedSnps[i].ObjectMeta.OwnerReferences)).To(BeTrue())
				Expect(snp.Spec.StagedAction).To(Equal(expectedSnps[i].Spec.StagedAction))
			}
		},
		Entry("Update StagedAction to 'Activate'", activateQuery, expectedActivatedSnps),
		Entry("Update StagedAction to 'Ignore'", ignoreQuery, expectedIgnoredSnps),
		Entry("Update StagedAction to 'Learn'", learnQuery, expectedRecommendedSnps),
	)

	DescribeTable("Handles http method PATCH",
		func(method string, query *BatchStagedActionParams, expectedErr error) {
			jsonQuery, err := json.Marshal(query)
			Expect(err).To(BeNil())

			req, err := http.NewRequest(
				method, recommendationBatchURLPath, bytes.NewBuffer(jsonQuery))
			Expect(err).To(BeNil())

			cs, err := mockLmaK8sClientFactory.NewClientSetForApplication(clusterID)
			Expect(err).NotTo(HaveOccurred())

			// Create staged network policies for test
			err = createSnps(req.Context(), cs)
			Expect(err).NotTo(HaveOccurred())

			By("Updating the snp StagedAction to set")
			hdlr := BatchStagedActionsHandler(mockAuthenticator, mockLmaK8sClientFactory, mockK8sClientFactory)

			// Add a bogus user
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			w := httptest.NewRecorder()
			hdlr.ServeHTTP(w, req)
			Expect(err).To(BeNil())

			body, err := io.ReadAll(w.Body)
			Expect(err).To(BeNil())

			if len(body) > 0 {
				err = json.Unmarshal(body, &errorMessage)
				Expect(err).To(BeNil())

				if errorMessage.Message == "" {
					resp := BatchResponse{}
					err = json.Unmarshal(body, &resp)
					Expect(err).To(BeNil())

					Expect(resp.Status).To(Equal(http.StatusOK))
					Expect(resp.Error).To(BeNil())
				} else {
					Expect(errorMessage.Message).To(Equal(expectedErr.Error()))
				}
			}
		},
		Entry("Patch", http.MethodPatch, activateQuery, nil),
		Entry("Post", http.MethodPost, activateQuery, nil),
		Entry("Connect", http.MethodConnect, activateQuery, fmt.Errorf("unsupported method type %s, only %s is supported", http.MethodConnect, http.MethodPatch)),
		Entry("Delete", http.MethodDelete, activateQuery, fmt.Errorf("unsupported method type %s, only %s is supported", http.MethodDelete, http.MethodPatch)),
		Entry("Get", http.MethodGet, activateQuery, fmt.Errorf("unsupported method type %s, only %s is supported", http.MethodGet, http.MethodPatch)),
		Entry("Head", http.MethodHead, activateQuery, fmt.Errorf("unsupported method type %s, only %s is supported", http.MethodHead, http.MethodPatch)),
		Entry("Options", http.MethodOptions, activateQuery, fmt.Errorf("unsupported method type %s, only %s is supported", http.MethodOptions, http.MethodPatch)),
		Entry("Put", http.MethodPut, activateQuery, fmt.Errorf("unsupported method type %s, only %s is supported", http.MethodPut, http.MethodPatch)),
		Entry("Trace", http.MethodTrace, activateQuery, fmt.Errorf("unsupported method type %s, only %s is supported", http.MethodTrace, http.MethodPatch)),
	)
})

var _ = Describe("Policy Recommendation Batch Authen/Authz", func() {
	type eMessage struct {
		Message string `json:"message"`
	}

	const (
		clusterID = "cluster"
		tier      = "namespace-isolation"
	)

	var (
		errorMessage eMessage

		mockAuthenticator *lmaauth.MockJWTAuth

		mockLmaK8sClientFactory *lmak8s.MockClientSetFactory
		mockK8sClientFactory    *datastore.MockClusterCtxK8sClientFactory
	)

	BeforeEach(func() {
		mockAuthenticator = &lmaauth.MockJWTAuth{}
		mockLmaK8sClientFactory = &lmak8s.MockClientSetFactory{}
		mockLmaK8sClientSet := lmak8s.MockClientSet{}

		mockLmaK8sClientFactory.On("NewClientSetForApplication", clusterID).Return(&mockLmaK8sClientSet, nil)
		mockLmaK8sClientFactory.On("NewClientSetForUser", mock.Anything, clusterID).Return(&mockLmaK8sClientSet, nil)

		mockLmaK8sClientSet.On("ProjectcalicoV3").Return(clientsetfake.NewSimpleClientset().ProjectcalicoV3())
		mockLmaK8sClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1())

		errorMessage = eMessage{}
	})

	DescribeTable("Authentication",
		func(query *BatchStagedActionParams, userInfo user.Info, httpStatusCode int, expectedErr error) {
			mockAuthenticator.On("Authenticate", mock.Anything).Return(userInfo, httpStatusCode, expectedErr)

			jsonQuery, err := json.Marshal(query)
			Expect(err).To(BeNil())

			req, err := http.NewRequest(
				http.MethodPatch, recommendationBatchURLPath, bytes.NewBuffer(jsonQuery))
			Expect(err).To(BeNil())

			cs, err := mockLmaK8sClientFactory.NewClientSetForApplication(clusterID)
			Expect(err).NotTo(HaveOccurred())

			// Create staged network policies for test
			err = createSnps(req.Context(), cs)
			Expect(err).NotTo(HaveOccurred())

			By("Updating the snp StagedAction to set")
			hdlr := BatchStagedActionsHandler(mockAuthenticator, mockLmaK8sClientFactory, mockK8sClientFactory)

			// Add a bogus user
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			w := httptest.NewRecorder()
			hdlr.ServeHTTP(w, req)
			Expect(err).To(BeNil())

			body, err := io.ReadAll(w.Body)
			Expect(err).To(BeNil())

			if len(body) > 0 {
				err = json.Unmarshal(body, &errorMessage)
				Expect(err).To(BeNil())

				if errorMessage.Message == "" {
					resp := BatchResponse{}
					err = json.Unmarshal(body, &resp)
					Expect(err).To(BeNil())

					Expect(resp.Status).To(Equal(http.StatusOK))
					Expect(resp.Error).To(BeNil())
				} else {
					Expect(errorMessage.Message).To(Equal(expectedErr.Error()))
				}
			}
		},
		Entry("Valid Authentication", activateQuery, &user.DefaultInfo{}, http.StatusOK, nil),
		Entry("Unauthorized request - 401", activateQuery, nil, http.StatusUnauthorized, errors.New("401 error authenticating user")),
		Entry("Internal server error - 500", activateQuery, nil, http.StatusInternalServerError, errors.New("500 error authenticating user")),
	)
})

var _ = Describe("Policy Recommendation Batch Patch", func() {
	const (
		clusterID = "cluster"
		tier      = "namespace-isolation"
	)

	var (
		mockLmaK8sClientFactory *lmak8s.MockClientSetFactory
	)

	BeforeEach(func() {
		mockLmaK8sClientFactory = &lmak8s.MockClientSetFactory{}
		mockLmaK8sClientSet := lmak8s.MockClientSet{}

		mockLmaK8sClientFactory.On("NewClientSetForApplication", clusterID).Return(&mockLmaK8sClientSet, nil)
		mockLmaK8sClientFactory.On("NewClientSetForUser", mock.Anything, clusterID).Return(&mockLmaK8sClientSet, nil)

		mockLmaK8sClientSet.On("ProjectcalicoV3").Return(clientsetfake.NewSimpleClientset().ProjectcalicoV3())
		mockLmaK8sClientSet.On("CoreV1").Return(fakeK8s.NewSimpleClientset().CoreV1())
	})

	DescribeTable("PatchSnp",
		func(sa string, snp *v3.StagedNetworkPolicy, errs chan error, expectedSnp *v3.StagedNetworkPolicy, expectedErr error) {
			var wg sync.WaitGroup

			ctx := context.Background()
			// Get the k8s client set for this cluster
			clientSet, err := mockLmaK8sClientFactory.NewClientSetForApplication(clusterID)
			Expect(err).To(BeNil())
			// Add the staged network policy
			_, err = clientSet.ProjectcalicoV3().StagedNetworkPolicies(snp.Namespace).Create(ctx, snp, metav1.CreateOptions{})
			Expect(err).To(BeNil())

			wg.Add(1)
			patchSNP(ctx, clientSet, *snp, sa, errs, &wg)
			wg.Wait()

			close(errs)
			if len(errs) > 0 {
				for err := range errs {
					if err != nil {
						Expect(err).To(Equal(expectedErr))
					}
				}
			} else {
				res, err := clientSet.ProjectcalicoV3().StagedNetworkPolicies(snp.Namespace).Get(ctx, snp.Name, metav1.GetOptions{})
				Expect(err).To(BeNil())

				Expect(reflect.DeepEqual(res, expectedSnp)).To(BeTrue())
				Expect(res.Spec.StagedAction).To(Equal(expectedSnp.Spec.StagedAction))
			}
		},
		Entry("Patch to 'Set'",
			string(v3.StagedActionSet),
			&v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getPolicyName("namespace-isolation", ns1.Name),
					Namespace: ns1.Name,
					Labels: map[string]string{
						"projectcalico.org/spec.stagedAction": "Learn",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Name: "default",
							Kind: "PolicyRecommendationScope",
						},
					},
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionLearn,
				},
			},
			make(chan error, 1),
			&v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getPolicyName("namespace-isolation", ns1.Name),
					Namespace: ns1.Namespace,
					Labels: map[string]string{
						"projectcalico.org/spec.stagedAction": "Set",
					},
					OwnerReferences: nil,
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionSet,
				},
			},
			nil,
		),
		Entry("Patch to 'Ignore'",
			string(v3.StagedActionIgnore),
			&v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getPolicyName("namespace-isolation", ns1.Name),
					Namespace: ns1.Name,
					Labels: map[string]string{
						"projectcalico.org/spec.stagedAction": "Learn",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Name: "default",
							Kind: "PolicyRecommendationScope",
						},
					},
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionLearn,
				},
			},
			make(chan error, 1),
			&v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getPolicyName("namespace-isolation", ns1.Name),
					Namespace: ns1.Namespace,
					Labels: map[string]string{
						"projectcalico.org/spec.stagedAction": "Ignore",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Name: "default",
							Kind: "PolicyRecommendationScope",
						},
					},
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionIgnore,
				},
			},
			nil,
		),
		Entry("Patch to 'Learn'",
			string(v3.StagedActionLearn),
			&v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getPolicyName("namespace-isolation", ns1.Name),
					Namespace: ns1.Name,
					Labels: map[string]string{
						"projectcalico.org/spec.stagedAction": "Ignore",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Name: "default",
							Kind: "PolicyRecommendationScope",
						},
					},
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionIgnore,
				},
			},
			make(chan error, 1),
			&v3.StagedNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      getPolicyName("namespace-isolation", ns1.Name),
					Namespace: ns1.Namespace,
					Labels: map[string]string{
						"projectcalico.org/spec.stagedAction": "Learn",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							Name: "default",
							Kind: "PolicyRecommendationScope",
						},
					},
				},
				Spec: v3.StagedNetworkPolicySpec{
					StagedAction: v3.StagedActionLearn,
				},
			},
			nil,
		),
	)
})

// Creates a list of staged network policies in the client set
func createSnps(ctx context.Context, cs lmak8s.ClientSet) error {
	for _, snp := range testSnps {
		if _, err := cs.ProjectcalicoV3().StagedNetworkPolicies(snp.Namespace).Create(
			ctx, snp, metav1.CreateOptions{}); err != nil {
			return err
		}

	}

	return nil
}

func getPolicyName(tier, name string) string {
	return fmt.Sprintf("%s.%s-recommendation", tier, name)
}

var (
	ns1 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns1",
			Namespace: "ns1",
		},
	}
	ns2 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns2",
			Namespace: "ns2",
		},
	}
	ns3 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns3",
			Namespace: "ns3",
		},
	}
	ns4 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns4",
			Namespace: "ns4",
		},
	}
	ns5 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns5",
			Namespace: "ns5",
		},
	}
	ns6 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns6",
			Namespace: "ns6",
		},
	}

	activateQuery = &BatchStagedActionParams{
		StagedNetworkPolicies: []StagedNetworkPolicy{
			{
				Name:      getPolicyName("namespace-isolation", ns1.Name),
				Namespace: ns1.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns2.Name),
				Namespace: ns2.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns3.Name),
				Namespace: ns3.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns4.Name),
				Namespace: ns4.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns5.Name),
				Namespace: ns5.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns6.Name),
				Namespace: ns6.Namespace,
			},
		},
		StagedAction: string(v3.StagedActionSet),
	}

	ignoreQuery = &BatchStagedActionParams{
		StagedNetworkPolicies: []StagedNetworkPolicy{
			{
				Name:      getPolicyName("namespace-isolation", ns1.Name),
				Namespace: ns1.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns2.Name),
				Namespace: ns2.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns3.Name),
				Namespace: ns3.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns4.Name),
				Namespace: ns4.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns5.Name),
				Namespace: ns5.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns6.Name),
				Namespace: ns6.Namespace,
			},
		},
		StagedAction: string(v3.StagedActionIgnore),
	}

	learnQuery = &BatchStagedActionParams{
		StagedNetworkPolicies: []StagedNetworkPolicy{
			{
				Name:      getPolicyName("namespace-isolation", ns1.Name),
				Namespace: ns1.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns2.Name),
				Namespace: ns2.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns3.Name),
				Namespace: ns3.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns4.Name),
				Namespace: ns4.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns5.Name),
				Namespace: ns5.Namespace,
			},
			{
				Name:      getPolicyName("namespace-isolation", ns6.Name),
				Namespace: ns6.Namespace,
			},
		},
		StagedAction: string(v3.StagedActionLearn),
	}

	testSnps = []*v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns1.Name),
				Namespace: ns1.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns2.Name),
				Namespace: ns2.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns3.Name),
				Namespace: ns3.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns4.Name),
				Namespace: ns4.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns5.Name),
				Namespace: ns5.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns6.Name),
				Namespace: ns6.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
		},
	}

	expectedActivatedSnps = []*v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            getPolicyName("namespace-isolation", ns1.Name),
				Namespace:       ns1.Namespace,
				OwnerReferences: nil,
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            getPolicyName("namespace-isolation", ns2.Name),
				Namespace:       ns2.Namespace,
				OwnerReferences: nil,
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            getPolicyName("namespace-isolation", ns3.Name),
				Namespace:       ns3.Namespace,
				OwnerReferences: nil,
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            getPolicyName("namespace-isolation", ns4.Name),
				Namespace:       ns4.Namespace,
				OwnerReferences: nil,
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            getPolicyName("namespace-isolation", ns5.Name),
				Namespace:       ns5.Namespace,
				OwnerReferences: nil,
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:            getPolicyName("namespace-isolation", ns6.Name),
				Namespace:       ns6.Namespace,
				OwnerReferences: nil,
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionSet,
			},
		},
	}

	expectedRecommendedSnps = []*v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns1.Name),
				Namespace: ns1.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns2.Name),
				Namespace: ns2.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns3.Name),
				Namespace: ns3.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns4.Name),
				Namespace: ns4.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns5.Name),
				Namespace: ns5.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns6.Name),
				Namespace: ns6.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionLearn,
			},
		},
	}

	expectedIgnoredSnps = []*v3.StagedNetworkPolicy{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns1.Name),
				Namespace: ns1.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns2.Name),
				Namespace: ns2.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns3.Name),
				Namespace: ns3.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns4.Name),
				Namespace: ns4.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns5.Name),
				Namespace: ns5.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      getPolicyName("namespace-isolation", ns6.Name),
				Namespace: ns6.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						Name: "default",
						Kind: "PolicyRecommendationScope",
					},
				},
			},
			Spec: v3.StagedNetworkPolicySpec{
				StagedAction: v3.StagedActionIgnore,
			},
		},
	}
)
