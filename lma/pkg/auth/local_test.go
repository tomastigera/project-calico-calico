// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/linseed/pkg/controller/token"
	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
)

var _ = Describe("Test local authenticator", func() {
	const (
		iss = "my-local-issuer"
	)

	var (
		fakeK8sCli        *fake.Clientset
		jwtAuth           auth.JWTAuth
		serviceaccountJWT = testing.NewFakeServiceAccountJWT()

		validToken       *jwt.Token
		validTokenString string

		badToken       *jwt.Token
		badTokenString string
	)

	BeforeEach(func() {
		var err error
		parser := token.ParseClaimsLinseed

		// Create a private key to use for the issuer.
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		// Create another private key to sign invalid tokens.
		badPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())

		// Create a valid token.
		claims := &jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   "system:serviceaccount:foo:bar",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		}
		validToken = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		validTokenString, err = validToken.SignedString(privateKey)
		Expect(err).NotTo(HaveOccurred())

		// Use the same claims, but sign with a different key.
		badToken = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		badTokenString, err = badToken.SignedString(badPrivateKey)
		Expect(err).NotTo(HaveOccurred())

		// Create the authenticator to test, passing the "good" public key.
		local := auth.NewLocalAuthenticator(iss, privateKey.Public(), parser)
		fakeK8sCli = new(fake.Clientset)
		jwtAuth, err = auth.NewJWTAuth(&rest.Config{BearerToken: serviceaccountJWT.ToString()}, fakeK8sCli, auth.WithAuthenticator(iss, local))
		Expect(err).NotTo(HaveOccurred())
	})

	It("Should authenticate a valid token", func() {
		testing.SetTokenReviewsReactor(fakeK8sCli, serviceaccountJWT)
		hdrs := http.Header{}
		hdrs.Set("Authorization", fmt.Sprintf("Bearer %s", validTokenString))
		req := &http.Request{Header: hdrs}

		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(200))
		Expect(usr.GetName()).To(Equal("system:serviceaccount:foo:bar"))
	})

	It("Should reject a token signed by a different key", func() {
		testing.SetTokenReviewsReactor(fakeK8sCli, serviceaccountJWT)
		hdrs := http.Header{}
		hdrs.Set("Authorization", fmt.Sprintf("Bearer %s", badTokenString))
		req := &http.Request{Header: hdrs}

		// It should fail to authenticate.
		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).To(HaveOccurred())
		Expect(stat).To(Equal(403))
		Expect(usr).To(BeNil())
	})

	It("Should refuse a missing header", func() {
		req := &http.Request{}
		usr, stat, err := jwtAuth.Authenticate(req)
		Expect(err).To(HaveOccurred())
		Expect(stat).To(Equal(401))
		Expect(usr).To(BeNil())
	})
})
