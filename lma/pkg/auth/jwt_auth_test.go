// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
)

var _ = Describe("Test dex username prefixes", func() {

	const (
		iss           = "https://127.0.0.1:9443/dex"
		clientID      = "tigera-manager"
		usernameClaim = "email"
		clusterIssuer = "https://kubernetes.default.svc"
	)

	var fakeK8sCli *fake.Clientset

	var (
		jwtAuth           auth.JWTAuth
		serviceaccountJWT = testing.NewFakeServiceAccountJWT()
		impersonatingJWT  = testing.NewFakeJWT(clusterIssuer, clientID)
	)

	newJWTAuth := func(opts ...auth.JWTAuthOption) (auth.JWTAuth, error) {
		dex, err := auth.NewDexAuthenticator(iss, clientID, usernameClaim, auth.WithKeySet(&testKeySet{}))
		if err != nil {
			return nil, err
		}
		opts = append(opts, auth.WithAuthenticator(iss, dex))
		return auth.NewJWTAuth(&rest.Config{BearerToken: impersonatingJWT.ToString()}, fakeK8sCli, opts...)
	}

	BeforeEach(func() {
		var err error
		fakeK8sCli = new(fake.Clientset)
		jwtAuth, err = newJWTAuth()
		Expect(err).NotTo(HaveOccurred())
	})

	It("Should authenticate a service account token", func() {
		testing.SetTokenReviewsReactor(fakeK8sCli, serviceaccountJWT)
		hdrs := http.Header{}
		hdrs.Set("Authorization", serviceaccountJWT.BearerTokenHeader())
		req := &http.Request{Header: hdrs}

		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(200))
		Expect(usr.GetName()).To(Equal("tigera-prometheus:default"))
	})

	It("Should refuse a missing jwtAuth header", func() {
		req := &http.Request{}
		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).To(HaveOccurred())
		Expect(stat).To(Equal(401))
		Expect(usr).To(BeNil())
	})

	It("Should authenticate and impersonate", func() {
		testing.SetTokenReviewsReactor(fakeK8sCli, impersonatingJWT)
		addAccessReviewsReactor(fakeK8sCli, true, &user.DefaultInfo{
			Name: fmt.Sprintf("%v", impersonatingJWT.PayloadMap[auth.ClaimNameName]),
		})
		hdrs := http.Header{}
		hdrs.Set("Authorization", impersonatingJWT.BearerTokenHeader())
		hdrs.Set(authnv1.ImpersonateUserHeader, "jane")
		hdrs.Set(authnv1.ImpersonateGroupHeader, "admin")
		req := &http.Request{Header: hdrs}

		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(200))
		Expect(usr.GetName()).To(Equal("jane"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
	})

	It("Should cache impersonation authorizations by token when caching is enabled", func() {
		jwtAuth, err := newJWTAuth(auth.WithAuthzCacheTTL(context.Background(), time.Second))
		Expect(err).NotTo(HaveOccurred())

		otherJWT := testing.NewFakeJWT(clusterIssuer, "some-other-client-id")

		testing.SetTokenReviewsReactor(fakeK8sCli, impersonatingJWT, otherJWT)
		accessReviewCallCounter := addAccessReviewsReactor(fakeK8sCli, true,
			&user.DefaultInfo{
				Name: fmt.Sprintf("%v", impersonatingJWT.PayloadMap[auth.ClaimNameName]),
			},
			&user.DefaultInfo{
				Name: fmt.Sprintf("%v", otherJWT.PayloadMap[auth.ClaimNameName]),
			},
		)

		newRequest := func(token *testing.FakeJWT, impersonateUser, impersonateGroup string) *http.Request {
			hdrs := http.Header{}
			hdrs.Set("Authorization", token.BearerTokenHeader())
			hdrs.Set(authnv1.ImpersonateUserHeader, impersonateUser)
			hdrs.Set(authnv1.ImpersonateGroupHeader, impersonateGroup)
			req := &http.Request{Header: hdrs}
			return req
		}

		usr, stat, err := jwtAuth.Authenticate(newRequest(impersonatingJWT, "jane", "admin"))
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(200))
		Expect(usr.GetName()).To(Equal("jane"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
		Expect(accessReviewCallCounter.Load()).To(Equal(int32(2))) // one call per header

		By("impersonating a different user should not return cached results")
		usr, stat, err = jwtAuth.Authenticate(newRequest(impersonatingJWT, "bob", "admin"))
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(200))
		Expect(usr.GetName()).To(Equal("bob"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
		Expect(accessReviewCallCounter.Load()).To(Equal(int32(3))) // one more call for the bob user.

		By("using a different token should not return cached results")
		usr, stat, err = jwtAuth.Authenticate(newRequest(otherJWT, "jane", "admin"))
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(200))
		Expect(usr.GetName()).To(Equal("jane"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
		Expect(accessReviewCallCounter.Load()).To(Equal(int32(5))) // new token so a call for each header

		By("repeating the same calls should return cached results")
		for i := 0; i < 5; i++ {
			usr, stat, err = jwtAuth.Authenticate(newRequest(otherJWT, "jane", "admin"))
			Expect(err).NotTo(HaveOccurred())
			Expect(stat).To(Equal(200))
			Expect(usr.GetName()).To(Equal("jane"))
			Expect(usr.GetGroups()).To(HaveLen(1))
			Expect(usr.GetGroups()[0]).To(Equal("admin"))
		}
		Expect(accessReviewCallCounter.Load()).To(Equal(int32(5)))
	})

	It("Should refuse service account that is not allowed to impersonate", func() {
		testing.SetTokenReviewsReactor(fakeK8sCli, impersonatingJWT)
		addAccessReviewsReactor(fakeK8sCli, false, &user.DefaultInfo{
			Name: fmt.Sprintf("%v", impersonatingJWT.PayloadMap[auth.ClaimNameName]),
		})
		hdrs := http.Header{}
		hdrs.Set("Authorization", impersonatingJWT.BearerTokenHeader())
		hdrs.Set(authnv1.ImpersonateUserHeader, "jane")
		hdrs.Set(authnv1.ImpersonateGroupHeader, "admin")
		req := &http.Request{Header: hdrs}

		_, stat, err := jwtAuth.Authenticate(req)
		Expect(err).To(HaveOccurred())
		Expect(stat).To(Equal(401))
	})
})

func addAccessReviewsReactor(fakeK8sCli *fake.Clientset, authorized bool, users ...user.Info) (callCounter *atomic.Int32) {
	callCounter = new(atomic.Int32)
	usersMap := make(map[string]user.Info)
	for _, u := range users {
		usersMap[u.GetName()] = u
	}
	fakeK8sCli.AddReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		callCounter.Add(1)
		createAction, ok := action.(k8stesting.CreateAction)
		Expect(ok).To(BeTrue())
		review, ok := createAction.GetObject().(*authzv1.SubjectAccessReview)
		Expect(ok).To(BeTrue())
		userInfo, ok := usersMap[review.Spec.User]
		Expect(ok).To(BeTrue(), "user %v not found", review.Spec.User)
		extra := make(map[string]authzv1.ExtraValue)
		for k, v := range userInfo.GetExtra() {
			extra[k] = v
		}
		Expect(review.Spec.UID).To(Equal(userInfo.GetUID()))
		Expect(review.Spec.Groups).To(Equal(userInfo.GetGroups()))
		Expect(review.Spec.Extra).To(Equal(extra))
		Expect(review.Spec.ResourceAttributes.Name).To(BeElementOf("jane", "bob", "admin"))
		Expect(review.Spec.ResourceAttributes.Resource).To(BeElementOf("users", "groups"))
		Expect(review.Spec.ResourceAttributes.Verb).To(Equal("impersonate"))
		return true, &authzv1.SubjectAccessReview{Status: authzv1.SubjectAccessReviewStatus{Allowed: authorized}}, nil
	})
	return callCounter
}
