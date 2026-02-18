// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package client

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("", func() {

	Context("test label handler", func() {
		It("Labels", func() {
			k8sClient := fake.NewSimpleClientset()
			authz := &mockAuthorizer{}
			calicoClient := newMockCalicoClient()

			l := NewLabelsAggregator(k8sClient, calicoClient)

			permissions, err := authz.PerformUserAuthorizationReview(context.Background(), LabelsResourceAuthReviewAttrList)
			Expect(err).NotTo(HaveOccurred())

			By("getting labels for All NetworkPolicies")
			// TODO: need to mock policy cache
			// l.GetAllPoliciesLabels(permissions)

			By("getting labels for All NetworkSets")
			// TODO: need to mock networkset cache
			// l.GetAllNetworkSetsLabels(permissions, )

			By("getting labels for Pods")
			// TODO: need to mock endpoints cache
			// l.GetPodsLabels(permissions, )

			By("getting labels for Namespaces")
			labels, warning, err := l.GetNamespacesLabels(context.Background(), permissions)
			Expect(err).NotTo(HaveOccurred())
			Expect(warning).To(HaveLen(0))
			Expect(labels.GetLabels()).To(HaveLen(0))

			By("getting labels for ServiceAccounts")
			labels, warning, err = l.GetServiceAccountsLabels(context.Background(), permissions)
			Expect(err).NotTo(HaveOccurred())
			Expect(warning).To(HaveLen(0))
			Expect(labels.GetLabels()).To(HaveLen(0))

			By("getting labels for GlobalThreatFeeds")
			labels, warning, err = l.GetGlobalThreatfeedsLabels(context.Background(), permissions)
			Expect(err).NotTo(HaveOccurred())
			Expect(warning).To(HaveLen(0))
			Expect(labels.GetLabels()).To(HaveLen(1))

			By("getting labels for ManagedClusters")
			labels, warning, err = l.GetManagedClustersLabels(context.Background(), permissions)
			Expect(err).NotTo(HaveOccurred())
			Expect(warning).To(HaveLen(0))
			Expect(labels.GetLabels()).To(HaveLen(1))
		})
	})
})
