// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package server_test

import (
	"net/http"

	. "github.com/onsi/ginkgo/v2"
	"github.com/stretchr/testify/mock"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/datastore"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
)

var _ = Describe("Download tests", func() {
	var mockClientSetFactory *datastore.MockClusterCtxK8sClientFactory
	var mockFactory *api.MockStoreFactory
	var mockAuthenticator *lmaauth.MockJWTAuth
	var mockRBACAuthorizer *lmaauth.MockRBACAuthorizer
	var mockStore *api.MockComplianceStore

	BeforeEach(func() {
		mockClientSetFactory = new(datastore.MockClusterCtxK8sClientFactory)
		mockFactory = new(api.MockStoreFactory)
		mockAuthenticator = new(lmaauth.MockJWTAuth)
		mockRBACAuthorizer = new(lmaauth.MockRBACAuthorizer)
		mockStore = new(api.MockComplianceStore)
		mockAuthenticator.On("Authenticate", mock.Anything).Return(&user.DefaultInfo{}, 0, nil)
	})

	AfterEach(func() {
		mockClientSetFactory.AssertExpectations(GinkgoT())
		mockFactory.AssertExpectations(GinkgoT())
		mockAuthenticator.AssertExpectations(GinkgoT())
		mockRBACAuthorizer.AssertExpectations(GinkgoT())
		mockStore.AssertExpectations(GinkgoT())
	})

	DescribeTable(
		"Authorized Report Downloads",
		func(id string, expStatus int, forecasts []forecastFile, authorizedAttrs []*authzv1.ResourceAttributes) {
			By("Starting a test server")
			t := startTester(mockClientSetFactory, mockFactory, mockAuthenticator)
			defer t.stop()

			for _, authorizedAttr := range authorizedAttrs {
				mockRBACAuthorizer.On("Authorize", mock.Anything, authorizedAttr, mock.Anything).Return(true, nil)
			}

			mockClientSetFactory.On("RBACAuthorizerForCluster", mock.Anything).Return(mockRBACAuthorizer, nil)

			mockStore.On("RetrieveArchivedReport", mock.Anything, mock.Anything).Return(reportGetTypeGet, nil)
			mockFactory.On("NewStore", mock.Anything).Return(mockStore, nil)

			calicoCli := fake.NewClientset(&reportTypeGettable, &reportTypeNotGettable)
			mockClientSetFactory.On("ClientSetForCluster", mock.Anything).Return(datastore.NewClientSet(nil, calicoCli.ProjectcalicoV3()), nil)

			By("Running a download query that should succeed")
			if len(forecasts) > 1 {
				t.downloadMulti(id, expStatus, forecasts)
			} else {
				t.downloadSingle(id, expStatus, forecasts[0])
			}
		},
		Entry(
			"Single report",
			reportGetTypeGet.UID(), http.StatusOK, []forecastFile{forecastFile1},
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreports", Name: "Get"},
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreporttypes", Name: "inventoryGet"},
			},
		),
		Entry(
			"Multiple reports",
			reportGetTypeGet.UID(), http.StatusOK, []forecastFile{forecastFile1, forecastFile2},
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreports", Name: "Get"},
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreporttypes", Name: "inventoryGet"},
			},
		),
	)

	DescribeTable(
		"Unauthorized Report Downloads",
		func(id string, expStatus int, forecasts []forecastFile, authorizedAttrs, unAuthorizedAttrs []*authzv1.ResourceAttributes) {
			By("Starting a test server")
			t := startTester(mockClientSetFactory, mockFactory, mockAuthenticator)
			defer t.stop()

			for _, attr := range authorizedAttrs {
				mockRBACAuthorizer.On("Authorize", mock.Anything, attr, mock.Anything).Return(true, nil)
			}

			for _, attr := range unAuthorizedAttrs {
				mockRBACAuthorizer.On("Authorize", mock.Anything, attr, mock.Anything).Return(false, nil)
			}

			mockClientSetFactory.On("RBACAuthorizerForCluster", mock.Anything).Return(mockRBACAuthorizer, nil)

			By("Running a download query that should succeed")
			if len(forecasts) > 1 {
				t.downloadMulti(id, expStatus, forecasts)
			} else {
				t.downloadSingle(id, expStatus, forecasts[0])
			}
		},
		Entry("single report globalreports get access but no globalreporttypes access for inventoryNoGo",
			reportGetTypeNoGet.UID(), http.StatusUnauthorized, []forecastFile{forecastFile1},
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreports", Name: "Get"},
			},
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreporttypes", Name: "inventoryNoGo"},
			},
		),
		Entry("multiple reports globalreports get access but no globalreporttypes access for inventoryNoGo",
			reportGetTypeNoGet.UID(), http.StatusUnauthorized, []forecastFile{forecastFile1, forecastFile2},
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreports", Name: "Get"},
			},
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreporttypes", Name: "inventoryNoGo"},
			},
		),
		Entry("single report no access to globalreports",
			reportGetTypeNoGet.UID(), http.StatusUnauthorized, []forecastFile{forecastFile1}, nil,
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreports", Name: "Get"},
			},
		),
		Entry("multiple reports no access to globalreports",
			reportGetTypeNoGet.UID(), http.StatusUnauthorized, []forecastFile{forecastFile1, forecastFile2}, nil,
			[]*authzv1.ResourceAttributes{
				{Verb: "get", Group: "projectcalico.org", Resource: "globalreports", Name: "Get"},
			},
		),
	)
})
