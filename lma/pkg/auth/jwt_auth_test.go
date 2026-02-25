// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package auth_test

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apiserverserviceaccount "k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
)

var (
	//go:embed testdata/tigera-issuer.crt
	tigeraIssuerCertBundle []byte
	//go:embed testdata/no-tigera-issuer.crt
	noTigeraIssuerCertBundle []byte
	//go:embed testdata/tigera-issuer.jwt
	tigeraIssuedJWT string
)

var _ = Describe("JWT authentication tests", func() {

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
		Expect(stat).To(Equal(http.StatusOK))
		Expect(usr.GetName()).To(Equal("tigera-prometheus:default"))
	})

	It("Should refuse a missing jwtAuth header", func() {
		req := &http.Request{}
		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).To(HaveOccurred())
		Expect(stat).To(Equal(http.StatusUnauthorized))
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
		Expect(stat).To(Equal(http.StatusOK))
		Expect(usr.GetName()).To(Equal("jane"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
	})

	It("Should authenticate when the JWT token is issued by Tigera", func() {
		saNamespace := "calico-system"
		saName := "tigera-noncluster-host"

		fakeK8sCli = fake.NewSimpleClientset()
		sa, err := fakeK8sCli.CoreV1().ServiceAccounts(saNamespace).Create(context.TODO(), &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      saName,
				Namespace: saNamespace,
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		hdrs := http.Header{}
		hdrs.Set("Authorization", "Bearer "+tigeraIssuedJWT)
		req := &http.Request{Header: hdrs}

		tmpFile, err := os.CreateTemp("", "tigera-issuer-*.crt")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		_, err = tmpFile.Write(tigeraIssuerCertBundle)
		Expect(err).NotTo(HaveOccurred())

		jwtAuth, err = newJWTAuth(auth.WithTigeraIssuerPublicKey(tmpFile.Name()))
		Expect(err).NotTo(HaveOccurred())

		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(http.StatusOK))
		Expect(usr.GetName()).To(Equal(apiserverserviceaccount.MakeUsername(saNamespace, saName)))
		Expect(usr.GetUID()).To(Equal(string(sa.UID)))
		Expect(usr.GetGroups()).To(HaveLen(3))
		Expect(usr.GetGroups()).To(Equal([]string{"system:serviceaccounts", "system:authenticated", "system:serviceaccounts:calico-system"}))
	})

	It("Should return error when the tigera-operator-signer certificate is not in the CA bundle", func() {
		tmpFile, err := os.CreateTemp("", "no-tigera-issuer-*.crt")
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		_, err = tmpFile.Write(noTigeraIssuerCertBundle)
		Expect(err).NotTo(HaveOccurred())

		jwtAuth, err = newJWTAuth(auth.WithTigeraIssuerPublicKey(tmpFile.Name()))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("no valid Tigera issuer public key found"))
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
		Expect(stat).To(Equal(http.StatusOK))
		Expect(usr.GetName()).To(Equal("jane"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
		Expect(accessReviewCallCounter.Load()).To(Equal(int32(2))) // one call per header

		By("impersonating a different user should not return cached results")
		usr, stat, err = jwtAuth.Authenticate(newRequest(impersonatingJWT, "bob", "admin"))
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(http.StatusOK))
		Expect(usr.GetName()).To(Equal("bob"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
		Expect(accessReviewCallCounter.Load()).To(Equal(int32(3))) // one more call for the bob user.

		By("using a different token should not return cached results")
		usr, stat, err = jwtAuth.Authenticate(newRequest(otherJWT, "jane", "admin"))
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(http.StatusOK))
		Expect(usr.GetName()).To(Equal("jane"))
		Expect(usr.GetGroups()).To(HaveLen(1))
		Expect(usr.GetGroups()[0]).To(Equal("admin"))
		Expect(accessReviewCallCounter.Load()).To(Equal(int32(5))) // new token so a call for each header

		By("repeating the same calls should return cached results")
		for range 5 {
			usr, stat, err = jwtAuth.Authenticate(newRequest(otherJWT, "jane", "admin"))
			Expect(err).NotTo(HaveOccurred())
			Expect(stat).To(Equal(http.StatusOK))
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
		Expect(stat).To(Equal(http.StatusUnauthorized))
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
