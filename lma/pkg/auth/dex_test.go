package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/auth/testing"
)

var _ = Describe("Test dex authenticator and options", func() {
	const (
		iss            = "https://127.0.0.1:9443/dex"
		name           = "Gerrit"
		email          = "rene@tigera.io"
		usernamePrefix = "my-user:"
		usernameClaim  = "email"
		clientID       = "tigera-manager"
		prefixedGroup  = "my-group:admins"
		group          = "admins"
		prefixedUser   = "my-user:rene@tigera.io"

		badIss      = "https:/accounts.google.com"
		badExp      = 1600964803 //Recently expired
		badClientID = "starbucks"
	)

	var dex auth.Authenticator
	var err error
	var jwt *testing.FakeJWT
	var keySet *testKeySet
	var req *http.Request

	BeforeEach(func() {
		keySet = &testKeySet{}
		opts := []auth.DexOption{
			auth.WithGroupsClaim("groups"),
			auth.WithUsernamePrefix(usernamePrefix),
			auth.WithGroupsPrefix("my-group:"),
			auth.WithKeySet(keySet),
		}
		dex, err = auth.NewDexAuthenticator(iss, clientID, usernameClaim, opts...)
		Expect(err).NotTo(HaveOccurred())
		req = &http.Request{Header: http.Header{}}
	})

	It("should authenticate a valid dex user", func() {
		jwt = testing.NewFakeJWT(iss, name).WithClaim(auth.ClaimNameEmail, email).WithClaim(auth.ClaimNameAud, clientID).WithClaim(auth.ClaimNameGroups, []string{group})
		keySet.On("VerifySignature", mock.Anything, strings.TrimSpace(jwt.ToString())).Return([]byte(jwt.PayloadJSON), nil)
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dex.Authenticate(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal(prefixedUser))
		Expect(usr.GetGroups()[0]).To(Equal(prefixedGroup))
		Expect(usr.GetExtra()[auth.ClaimNameIss]).To(Equal([]string{iss}))
		Expect(usr.GetExtra()[auth.ClaimNameSub]).To(Equal([]string{name}))
		Expect(stat).To(Equal(200))
	})

	It("should reject an invalid issuer", func() {
		jwt = testing.NewFakeJWT(badIss, name).WithClaim(auth.ClaimNameEmail, email).WithClaim(auth.ClaimNameAud, clientID)
		keySet.On("VerifySignature", mock.Anything, jwt.ToString()).Return([]byte(jwt.PayloadJSON), nil)
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dex.Authenticate(req)
		Expect(err).NotTo(BeNil())
		Expect(usr).To(BeNil())
		Expect(stat).To(Equal(421))
	})

	It("should reject an invalid clientID", func() {
		jwt = testing.NewFakeJWT(iss, name).WithClaim(auth.ClaimNameEmail, email).WithClaim(auth.ClaimNameAud, badClientID)
		keySet.On("VerifySignature", mock.Anything, jwt.ToString()).Return([]byte(jwt.PayloadJSON), nil)
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dex.Authenticate(req)
		Expect(err).NotTo(BeNil())
		Expect(usr).To(BeNil())
		Expect(stat).To(Equal(401))
	})

	It("should reject an expired token", func() {
		jwt = testing.NewFakeJWT(iss, name).WithClaim(auth.ClaimNameEmail, email).WithClaim(auth.ClaimNameAud, clientID).WithClaim(auth.ClaimNameExp, badExp)
		keySet.On("VerifySignature", mock.Anything, jwt.ToString()).Return([]byte(jwt.PayloadJSON), nil)
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dex.Authenticate(req)
		Expect(err).NotTo(BeNil())
		Expect(usr).To(BeNil())
		Expect(stat).To(Equal(401))
	})

	It("should reject an invalid signature", func() {
		jwt = testing.NewFakeJWT(iss, name).WithClaim(auth.ClaimNameEmail, email).WithClaim(auth.ClaimNameAud, clientID)
		keySet.On("VerifySignature", mock.Anything, jwt.ToString()).Return(nil, errors.New("sig error"))
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dex.Authenticate(req)
		Expect(err).NotTo(BeNil())
		Expect(usr).To(BeNil())
		Expect(stat).To(Equal(401))
	})
})

var _ = Describe("Test dex username prefixes", func() {
	const (
		iss      = "https://127.0.0.1:9443/dex"
		email    = "rene@tigera.io"
		name     = "Rene Dekker"
		clientID = "tigera-manager"
	)

	jwt := testing.NewFakeJWT(iss, name).WithClaim(auth.ClaimNameEmail, email).WithClaim(auth.ClaimNameAud, clientID)

	var opts []auth.DexOption
	var req *http.Request

	BeforeEach(func() {

		keySet := &testKeySet{}
		keySet.On("VerifySignature", mock.Anything, jwt.ToString()).Return([]byte(jwt.PayloadJSON), nil)
		opts = []auth.DexOption{
			auth.WithGroupsClaim("groups"),
			auth.WithGroupsPrefix("my-groups"),
			auth.WithKeySet(keySet),
		}
		req = &http.Request{Header: http.Header{}}
	})

	It("should prepend the prefix to the username", func() {
		prefix := "Howdy, "
		opts = append(opts, auth.WithUsernamePrefix(prefix))
		dx, err := auth.NewDexAuthenticator(iss, clientID, "name", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal("Howdy, Rene Dekker"))
		Expect(stat).To(Equal(200))
	})

	It("should prepend nothing to the username", func() {
		prefix := "-"
		opts = append(opts, auth.WithUsernamePrefix(prefix))
		dx, err := auth.NewDexAuthenticator(iss, clientID, "name", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal("Rene Dekker"))
		Expect(stat).To(Equal(200))
	})

	It("should prepend issuer to the username", func() {
		prefix := ""
		opts = append(opts, auth.WithUsernamePrefix(prefix))
		dx, err := auth.NewDexAuthenticator(iss, clientID, "name", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal(fmt.Sprintf("%s#Rene Dekker", iss)))
		Expect(stat).To(Equal(200))
	})

	It("should prepend the prefix to the username (email claim)", func() {
		prefix := "Howdy, "
		opts = append(opts, auth.WithUsernamePrefix(prefix))
		dx, err := auth.NewDexAuthenticator(iss, clientID, "email", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal("Howdy, rene@tigera.io"))
		Expect(stat).To(Equal(200))
	})

	It("should prepend nothing to the username (email claim)(1/2)", func() {
		prefix := "-"
		opts = append(opts, auth.WithUsernamePrefix(prefix))
		dx, err := auth.NewDexAuthenticator(iss, clientID, "email", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal("rene@tigera.io"))
		Expect(stat).To(Equal(200))
	})

	It("should prepend nothing to the username (email claim)(2/2)", func() {
		prefix := ""
		opts = append(opts, auth.WithUsernamePrefix(prefix))
		dx, err := auth.NewDexAuthenticator(iss, clientID, "email", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal("rene@tigera.io"))
		Expect(stat).To(Equal(200))
	})

	It("should prepend the right prefix to the username if no prefix option was specified", func() {
		dx, err := auth.NewDexAuthenticator(iss, clientID, "name", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal(fmt.Sprintf("%s#Rene Dekker", iss)))
		Expect(stat).To(Equal(200))
	})

	It("should prepend the right prefix to the username if no prefix option was specified (email claim)", func() {
		dx, err := auth.NewDexAuthenticator(iss, clientID, "email", opts...)
		Expect(err).NotTo(HaveOccurred())
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		usr, stat, err := dx.Authenticate(req)

		Expect(err).NotTo(HaveOccurred())
		Expect(usr).NotTo(BeNil())
		Expect(usr.GetName()).To(Equal("rene@tigera.io"))
		Expect(stat).To(Equal(200))
	})

})

var _ = Describe("Test CC TenantID Claim", func() {
	const (
		iss           = "https://127.0.0.1:9443/dex"
		name          = "Gerrit"
		email         = "rene@tigera.io"
		usernameClaim = "email"
		clientID      = "tigera-manager"
		group         = "admins"

		ccTenantIDsClaimName = "https://calicocloud.io/tenantIDs"
		ccRequiredTenantID   = "someTenantID"
	)

	var dex auth.Authenticator
	var err error
	var jwt *testing.FakeJWT
	var keySet *testKeySet
	var req *http.Request

	BeforeEach(func() {
		keySet = &testKeySet{}
		opts := []auth.DexOption{
			auth.WithCalicoCloudTenantClaim(ccRequiredTenantID),
			auth.WithKeySet(keySet),
		}
		dex, err = auth.NewDexAuthenticator(iss, clientID, usernameClaim, opts...)
		Expect(err).NotTo(HaveOccurred())
		req = &http.Request{Header: http.Header{}}
	})

	It("should authenticate a dex user with the required claim", func() {
		jwt = testing.NewFakeJWT(iss, name).
			WithClaim(auth.ClaimNameEmail, email).
			WithClaim(auth.ClaimNameAud, clientID).
			WithClaim(auth.ClaimNameGroups, []string{group}).
			WithClaim(ccTenantIDsClaimName, []string{"someOtherTenantID", ccRequiredTenantID})
		keySet.On("VerifySignature", mock.Anything, strings.TrimSpace(jwt.ToString())).Return([]byte(jwt.PayloadJSON), nil)
		req.Header.Set("Authorization", jwt.BearerTokenHeader())
		_, stat, err := dex.Authenticate(req)
		Expect(err).NotTo(HaveOccurred())
		Expect(stat).To(Equal(200))
	})

	type Test struct {
		name           string
		tenantIDsClaim any
	}
	for _, test := range []Test{
		{name: "should reject a user without the required claim", tenantIDsClaim: nil},
		{name: "should reject a user with incorrect claim value", tenantIDsClaim: []any{"someOtherTenantID"}},
		{name: "should reject a user with incorrect claim type", tenantIDsClaim: ccRequiredTenantID /* `string`, not `[]any` */},
	} {
		test := test // beware loop variable capture

		It(test.name, func() {

			jwt = testing.NewFakeJWT(iss, name).
				WithClaim(auth.ClaimNameEmail, email).
				WithClaim(auth.ClaimNameAud, clientID).
				WithClaim(auth.ClaimNameGroups, []string{group})

			if test.tenantIDsClaim != nil {
				jwt.WithClaim(ccTenantIDsClaimName, test.tenantIDsClaim)
			}

			keySet.On("VerifySignature", mock.Anything, jwt.ToString()).Return([]byte(jwt.PayloadJSON), nil)
			req.Header.Set("Authorization", jwt.BearerTokenHeader())
			_, stat, err := dex.Authenticate(req)
			Expect(err).To(HaveOccurred())
			Expect(stat).To(Equal(401))
		})
	}
})

type testKeySet struct {
	mock.Mock
}

// Test Verify method.
func (t *testKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	args := t.Called(ctx, jwt)
	err := args.Get(1)
	if err != nil {
		return nil, err.(error)
	}
	return args.Get(0).([]byte), nil
}
