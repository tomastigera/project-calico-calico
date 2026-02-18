// Copyright (c) 2021 Tigera. All rights reserved.
package handler_test

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
	handler "github.com/projectcalico/calico/prometheus-service/pkg/handler/proxy"
)

var _ = Describe("Prometheus Proxy Query test", func() {
	const (
		iss  = "https://example.com/my-issuer"
		name = "Gerrit"
	)

	var (
		authn      auth.JWTAuth
		err        error
		mAuth      *mockAuth
		fakeK8sCli *fake.Clientset
		jwt        = testing.NewFakeJWT(iss, name)
		testUrl, _ = url.Parse("http://test-service:9090")
		userInfo   = &user.DefaultInfo{Name: "default"}
	)

	BeforeEach(func() {
		mAuth = &mockAuth{}
		fakeK8sCli = new(fake.Clientset)
		authn, err = auth.NewJWTAuth(&rest.Config{BearerToken: jwt.ToString()}, fakeK8sCli, auth.WithAuthenticator(iss, mAuth))
		Expect(err).NotTo(HaveOccurred())
	})

	It("passes the request to the Proxy", func() {
		req, _ := http.NewRequest("GET", "/test-endpoint", nil)
		req.Header.Set("Authorization", jwt.BearerTokenHeader())

		mAuth.On("Authenticate", req).Return(userInfo, http.StatusOK, nil)
		addAccessReviewsReactor(fakeK8sCli, true, userInfo)
		var requestReceived *http.Request

		mockRevProxy := httputil.NewSingleHostReverseProxy(testUrl)
		mockRevProxy.Director = func(req *http.Request) {
			requestReceived = req
		}

		proxy, err := handler.Proxy(mockRevProxy, authn)
		Expect(err).NotTo(HaveOccurred())
		rr := httptest.NewRecorder()
		proxy.ServeHTTP(rr, req)

		Expect(requestReceived).ToNot(BeNil())
		Expect(requestReceived.Method).To(Equal("GET"))
		Expect(requestReceived.URL.Path).To(Equal("/test-endpoint"))
	})

	It("blocks unauthenticated requests", func() {
		var requestReceived *http.Request

		mockRevProxy := httputil.NewSingleHostReverseProxy(testUrl)
		mockRevProxy.Director = func(req *http.Request) {
			requestReceived = req
		}

		proxy, err := handler.Proxy(mockRevProxy, authn)
		Expect(err).NotTo(HaveOccurred())
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test-endpoint", nil)
		proxy.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusUnauthorized))
		Expect(requestReceived).To(BeNil())
	})

	It("blocks unauthorized requests", func() {
		req, _ := http.NewRequest("GET", "/test-endpoint", nil)
		req.Header.Set("Authorization", jwt.BearerTokenHeader())

		mAuth.On("Authenticate", req).Return(userInfo, http.StatusOK, nil)
		addAccessReviewsReactor(fakeK8sCli, false, userInfo)
		var requestReceived *http.Request

		mockRevProxy := httputil.NewSingleHostReverseProxy(testUrl)
		mockRevProxy.Director = func(req *http.Request) {
			requestReceived = req
		}

		proxy, err := handler.Proxy(mockRevProxy, authn)
		Expect(err).NotTo(HaveOccurred())
		rr := httptest.NewRecorder()
		proxy.ServeHTTP(rr, req)
		Expect(rr.Code).To(Equal(http.StatusForbidden))
		Expect(requestReceived).To(BeNil())
	})
})

type mockAuth struct {
	mock.Mock
}

func (m *mockAuth) Authenticate(r *http.Request) (user.Info, int, error) {
	args := m.Called(r)
	err := args.Get(2)
	if err != nil {
		return nil, args.Get(1).(int), err.(error)
	}
	return args.Get(0).(user.Info), args.Get(1).(int), nil
}

func addAccessReviewsReactor(fakeK8sCli *fake.Clientset, authorized bool, userInfo user.Info) {
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
		Expect(review.Spec.ResourceAttributes.Name).To(BeElementOf("https:calico-api:8080", "calico-node-prometheus:9090"))
		Expect(review.Spec.ResourceAttributes.Resource).To(Equal("services/proxy"))
		Expect(review.Spec.ResourceAttributes.Verb).To(Equal("get"))
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: authorized}}, nil
	})
}
