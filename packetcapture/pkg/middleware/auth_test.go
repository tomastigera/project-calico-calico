// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
	"github.com/projectcalico/calico/packetcapture/pkg/cache"
	"github.com/projectcalico/calico/packetcapture/pkg/middleware"
)

var _ = Describe("AuthZ", func() {
	var req *http.Request
	var noOpHandler http.HandlerFunc
	var anyError = fmt.Errorf("any error")
	var getResAtr = &authzv1.ResourceAttributes{
		Verb:        "get",
		Group:       "projectcalico.org",
		Resource:    "packetcaptures",
		Subresource: "files",
		Name:        "name",
		Namespace:   "ns",
	}
	var deleteResAtr = &authzv1.ResourceAttributes{
		Verb:        "delete",
		Group:       "projectcalico.org",
		Resource:    "packetcaptures",
		Subresource: "files",
		Name:        "name",
		Namespace:   "ns",
	}

	BeforeEach(func() {
		// Create a new request
		var err error
		req, err = http.NewRequest("", "any", nil)
		Expect(err).NotTo(HaveOccurred())
		// Set the Authorization header
		req.Header.Set("Authorization", "token")
		// Create a noOp handler func for the middleware
		noOpHandler = func(w http.ResponseWriter, r *http.Request) {}

		// Setup the variables on the context to be used for authN/authZ
		req = req.WithContext(middleware.WithClusterID(req.Context(), lmak8s.DefaultCluster))
		req = req.WithContext(middleware.WithNamespace(req.Context(), "ns"))
		req = req.WithContext(middleware.WithCaptureName(req.Context(), "name"))
	})

	It("Fails to authenticate user", func() {
		// Bootstrap the authenticator
		mockAuthenticator := new(lmaauth.MockJWTAuth)
		mockAuthenticator.On("Authenticate", req).Return(&user.DefaultInfo{},
			http.StatusUnauthorized, anyError)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := middleware.AuthenticationHandler(mockAuthenticator, noOpHandler)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
		Expect(recorder.Body.String()).To(Equal("any error\n"))
	})

	It("Authenticate user without checking impersonation", func() {
		// Bootstrap the authenticator
		var user = &user.DefaultInfo{}
		mockAuthenticator := new(lmaauth.MockJWTAuth)
		mockAuthenticator.On("Authenticate", req).Return(user, http.StatusOK, nil)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := middleware.AuthenticationHandler(mockAuthenticator, noOpHandler)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusOK))
		Expect(recorder.Body.String()).To(Equal(""))
	})

	It("Fails to create client for authorizer", func() {
		// Bootstrap the authorizer
		var mockCache = &cache.MockClientCache{}
		mockCache.On("GetAuthorizer", lmak8s.DefaultCluster).Return(nil, anyError)
		var auth = middleware.NewAuthZ(mockCache)

		// Bootstrap the http recorder
		recorder := httptest.NewRecorder()
		handler := auth.Authorize(noOpHandler)
		handler.ServeHTTP(recorder, req)

		Expect(recorder.Code).To(Equal(http.StatusInternalServerError))
		Expect(recorder.Body.String()).To(Equal("any error\n"))
	})

	DescribeTable("Fails to authorize user",
		func(action string, resAttr *authzv1.ResourceAttributes) {
			req = req.WithContext(middleware.WithActionID(req.Context(), action))
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			// Bootstrap the authorizer
			var mockCache = &cache.MockClientCache{}
			var mockAuth = &lmaauth.MockRBACAuthorizer{}
			mockCache.On("GetAuthorizer", lmak8s.DefaultCluster).Return(mockAuth, nil)
			mockAuth.On("Authorize", &user.DefaultInfo{}, resAttr, (*authzv1.NonResourceAttributes)(nil)).Return(false, anyError)
			var auth = middleware.NewAuthZ(mockCache)

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := auth.Authorize(noOpHandler)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(Equal("any error\n"))
		},
		Entry("GET", middleware.GET, getResAtr),
		Entry("DELETE", middleware.DELETE, deleteResAtr),
	)

	DescribeTable("User is not authorized",
		func(action string, resAttr *authzv1.ResourceAttributes) {
			req = req.WithContext(middleware.WithActionID(req.Context(), action))
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			// Bootstrap the authorizer
			var mockCache = &cache.MockClientCache{}
			var mockAuth = &lmaauth.MockRBACAuthorizer{}
			mockCache.On("GetAuthorizer", lmak8s.DefaultCluster).Return(mockAuth, nil)
			mockAuth.On("Authorize", &user.DefaultInfo{}, resAttr, (*authzv1.NonResourceAttributes)(nil)).Return(false, anyError)
			var auth = middleware.NewAuthZ(mockCache)

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := auth.Authorize(noOpHandler)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusUnauthorized))
			Expect(recorder.Body.String()).To(Equal("any error\n"))
		},
		Entry("GET", middleware.GET, getResAtr),
		Entry("DELETE", middleware.DELETE, deleteResAtr),
	)

	DescribeTable("Authorizes user",
		func(action string, resAttr *authzv1.ResourceAttributes) {
			req = req.WithContext(middleware.WithActionID(req.Context(), action))
			req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{}))

			// Bootstrap the authorizer
			var mockCache = &cache.MockClientCache{}
			var mockAuth = &lmaauth.MockRBACAuthorizer{}
			mockCache.On("GetAuthorizer", lmak8s.DefaultCluster).Return(mockAuth, nil)
			mockAuth.On("Authorize", &user.DefaultInfo{}, resAttr, (*authzv1.NonResourceAttributes)(nil)).Return(true, nil)
			var auth = middleware.NewAuthZ(mockCache)

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := auth.Authorize(noOpHandler)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(http.StatusOK))
			Expect(recorder.Body.String()).To(Equal(""))
		},
		Entry("GET", middleware.GET, getResAtr),
		Entry("DELETE", middleware.DELETE, deleteResAtr),
	)
})

type expectedImpersonationReq struct {
	resAttr *authzv1.ResourceAttributes
	allowed bool
}

var _ = Describe("Impersonation", func() {

	const (
		clientID      = "tigera-manager"
		clusterIssuer = "https://kubernetes.default.svc"
	)

	var fakeK8sCli *fake.Clientset

	var (
		jwtAuth          lmaauth.JWTAuth
		impersonatingJWT = testing.NewFakeJWT(clusterIssuer, clientID)
		req              *http.Request
		err              error
	)

	BeforeEach(func() {
		fakeK8sCli = new(fake.Clientset)
		jwtAuth, err = lmaauth.NewJWTAuth(&rest.Config{BearerToken: impersonatingJWT.ToString()}, fakeK8sCli)
		Expect(err).NotTo(HaveOccurred())
		req, err = http.NewRequest("", "any", nil)
		Expect(err).NotTo(HaveOccurred())
		testing.SetTokenReviewsReactor(fakeK8sCli, impersonatingJWT)
	})

	DescribeTable("Authenticate user based on impersonation headers",
		func(jwt *testing.FakeJWT, impersonateUser string, impersonateGroups []string, extras map[string][]string,
			expectedImpersonationReq []expectedImpersonationReq, expectedStatus int, expectedBody string, expectedUser *user.DefaultInfo) {
			// Setup the jwt of the service account that will be doing the impersonation
			req.Header.Set("Authorization", jwt.BearerTokenHeader())
			// Setup up impersonation headers
			req.Header.Set(authenticationv1.ImpersonateUserHeader, impersonateUser)
			for _, group := range impersonateGroups {
				req.Header.Add(authenticationv1.ImpersonateGroupHeader, group)
			}
			for extraKey, values := range extras {
				for _, value := range values {
					req.Header.Add(fmt.Sprintf("%s%s", authenticationv1.ImpersonateUserExtraHeaderPrefix, extraKey), value)
				}
			}

			var usr user.Info
			// Bootstrap test handler
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Expect authentication information to be set on the context
				var ok bool
				usr, ok = request.UserFrom(r.Context())
				Expect(ok).To(BeTrue())
				Expect(usr).To(Equal(expectedUser))
			})

			// Mock authorization
			var mockCache = &cache.MockClientCache{}
			mockCache.On("GetAuthorizer", lmak8s.DefaultCluster).Return(jwtAuth, nil)
			addAccessReviewsReactor(fakeK8sCli, expectedImpersonationReq, &user.DefaultInfo{
				Name: fmt.Sprintf("%v", jwt.PayloadMap[lmaauth.ClaimNameName]),
			})

			// Bootstrap the http recorder
			recorder := httptest.NewRecorder()
			handler := middleware.AuthenticationHandler(jwtAuth, testHandler)
			handler.ServeHTTP(recorder, req)

			Expect(recorder.Code).To(Equal(expectedStatus))
			Expect(strings.Trim(recorder.Body.String(), "\n")).To(Equal(expectedBody))
		},
		Entry("Impersonate serviceAccount", impersonatingJWT, "system:serviceaccount:default:jane",
			[]string{"system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"},
			make(map[string][]string), []expectedImpersonationReq{
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:      "impersonate",
						Resource:  "serviceaccounts",
						Name:      "jane",
						Namespace: "default",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "groups",
						Name:     "system:serviceaccounts",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "groups",
						Name:     "system:serviceaccounts:default",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "groups",
						Name:     "system:authenticated",
					},
					allowed: true,
				},
			}, http.StatusOK, "", &user.DefaultInfo{
				Name:   "system:serviceaccount:default:jane",
				Groups: []string{"system:serviceaccounts", "system:serviceaccounts:default", "system:authenticated"},
				Extra:  map[string][]string{},
			}),
		Entry("Impersonate user", impersonatingJWT, "jane",
			[]string{"system:authenticated"},
			make(map[string][]string), []expectedImpersonationReq{
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "users",
						Name:     "jane",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "groups",
						Name:     "system:authenticated",
					},
					allowed: true,
				},
			}, http.StatusOK, "", &user.DefaultInfo{
				Name:   "jane",
				Groups: []string{"system:authenticated"},
				Extra:  map[string][]string{},
			}),
		Entry("Impersonate extra scopes", impersonatingJWT, "jane",
			[]string{"system:authenticated"},
			map[string][]string{
				"scopes":             {"view", "deployment"},
				"acme.com%2Fproject": {"some-project"},
			}, []expectedImpersonationReq{
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "users",
						Name:     "jane",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "groups",
						Name:     "system:authenticated",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:        "impersonate",
						Resource:    "userextras",
						Subresource: "scopes",
						Name:        "view",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:        "impersonate",
						Resource:    "userextras",
						Subresource: "scopes",
						Name:        "deployment",
					},
					allowed: true,
				},
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:        "impersonate",
						Resource:    "userextras",
						Subresource: "acme.com/project",
						Name:        "some-project",
					},
					allowed: true,
				},
			}, http.StatusOK, "", &user.DefaultInfo{
				Name:   "jane",
				Groups: []string{"system:authenticated"},
				Extra: map[string][]string{
					"scopes":           {"view", "deployment"},
					"acme.com/project": {"some-project"}},
			}),
		Entry("Missing user impersonation header", impersonatingJWT, "",
			[]string{"system:authenticated"},
			map[string][]string{},
			[]expectedImpersonationReq{}, http.StatusUnauthorized, "impersonation headers are missing impersonate user header", &user.DefaultInfo{}),
		Entry("Token not allowed to impersonate user", impersonatingJWT, "jane",
			[]string{"system:authenticated"},
			make(map[string][]string), []expectedImpersonationReq{
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "users",
						Name:     "jane",
					},
					allowed: false,
				},
			}, http.StatusUnauthorized, "user is not allowed to impersonate", &user.DefaultInfo{}),
		Entry("Failure to impersonate users", impersonatingJWT, "jane",
			[]string{"system:authenticated"},
			make(map[string][]string), []expectedImpersonationReq{
				{
					resAttr: &authzv1.ResourceAttributes{
						Verb:     "impersonate",
						Resource: "users",
						Name:     "jane",
					},
					allowed: false,
				},
			}, http.StatusUnauthorized, "user is not allowed to impersonate", &user.DefaultInfo{}),
	)
})

func addAccessReviewsReactor(fakeK8sCli *fake.Clientset, reqs []expectedImpersonationReq, userInfo user.Info) {

	attrs := map[authzv1.ResourceAttributes]expectedImpersonationReq{}

	for _, req := range reqs {
		attrs[*req.resAttr] = req
	}

	fakeK8sCli.AddReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		extra := make(map[string]authzv1.ExtraValue)
		for k, v := range userInfo.GetExtra() {
			extra[k] = v
		}

		createAction, ok := action.(k8stesting.CreateAction)
		Expect(ok).To(BeTrue())
		review, ok := createAction.GetObject().(*authzv1.SubjectAccessReview)
		Expect(ok).To(BeTrue())
		Expect(review.Spec.User).To(Equal(userInfo.GetName()))
		Expect(review.Spec.UID).To(Equal(userInfo.GetUID()))
		Expect(review.Spec.Groups).To(Equal(userInfo.GetGroups()))
		Expect(review.Spec.Extra).To(Equal(extra))
		req, ok := attrs[*review.Spec.ResourceAttributes]
		Expect(ok).To(BeTrue())
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: req.allowed}}, nil
	})
}
