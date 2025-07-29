package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmatesting "github.com/projectcalico/calico/lma/pkg/auth/testing"
	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security/fake"
	"github.com/tigera/tds-apiserver/lib/logging"
)

func TestAuthService(t *testing.T) {

	logger := logging.New("TestAuthService")

	newSubject := func(cfg *config.Config, dexOptions ...lmaauth.DexOption) (*AuthService, *rsa.PrivateKey, *k8sfake.Clientset) {
		fakeClient := k8sfake.NewSimpleClientset()

		jwtToken, err := jwt.NewBuilder().Issuer("fake-issuer").Build()
		require.NoError(t, err)

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		bearerToken, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256, key))
		require.NoError(t, err)

		subject, err := NewAuthService(
			cfg,
			logger,
			"fake-tenant",
			fake.NewAuthorizer(true),
			fakeClient,
			&rest.Config{
				BearerToken: string(bearerToken),
			},
			dexOptions...,
		)
		require.NoError(t, err)
		return subject, key, fakeClient
	}

	t.Run("authenticate", func(t *testing.T) {
		t.Run("missing auth header", func(t *testing.T) {
			subject, _, _ := newSubject(&config.Config{})
			_, err := subject.authenticateRequest(&http.Request{})
			require.ErrorContains(t, err, "no auth header")
		})

		t.Run("missing bearer auth", func(t *testing.T) {
			subject, _, _ := newSubject(&config.Config{})
			_, err := subject.authenticateRequest(&http.Request{
				Header: http.Header{
					"Authorization": []string{"hello world"},
				},
			})
			require.ErrorContains(t, err, "not bearer auth")
		})

		t.Run("not authenticated", func(t *testing.T) {
			subject, key, _ := newSubject(&config.Config{})
			jwtToken, err := jwt.NewBuilder().Issuer("fake-issuer").Build()
			require.NoError(t, err)

			bearerToken, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256, key))
			require.NoError(t, err)

			_, err = subject.authenticateRequest(&http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer " + string(bearerToken)},
				},
			})
			require.ErrorContains(t, err, "user is not authenticated")
		})

		t.Run("invalid tenantID claim", func(t *testing.T) {
			keySet := &testKeySet{}
			subject, _, _ := newSubject(&config.Config{OIDCAuthIssuer: "fake-issuer", OIDCAuthClientID: "fake-client-id"}, lmaauth.WithKeySet(keySet))

			fakeJWT := lmatesting.NewFakeJWT("fake-issuer", "fake-user").
				WithClaim(lmaauth.ClaimNameAud, "fake-client-id").
				WithClaim("https://calicocloud.io/tenantIDs", []string{"unknown-tenant"})
			keySet.On("VerifySignature", mock.Anything, fakeJWT.ToString()).Return([]byte(fakeJWT.PayloadJSON), nil)

			_, err := subject.authenticateRequest(&http.Request{
				Header: http.Header{
					"Authorization": []string{fakeJWT.BearerTokenHeader()},
				},
			})

			require.ErrorContains(t, err, "claim validation failed")
		})

		t.Run("authenticated", func(t *testing.T) {
			keySet := &testKeySet{}
			subject, _, _ := newSubject(&config.Config{OIDCAuthIssuer: "fake-issuer", OIDCAuthClientID: "fake-client-id"}, lmaauth.WithKeySet(keySet))

			fakeJWT := lmatesting.NewFakeJWT("fake-issuer", "fake-user").
				WithClaim(lmaauth.ClaimNameAud, "fake-client-id").
				WithClaim("https://calicocloud.io/tenantIDs", []string{"fake-tenant"})
			keySet.On("VerifySignature", mock.Anything, fakeJWT.ToString()).Return([]byte(fakeJWT.PayloadJSON), nil)

			authContext, err := subject.authenticateRequest(&http.Request{
				Header: http.Header{
					"Authorization": []string{fakeJWT.BearerTokenHeader()},
				},
			})
			require.NoError(t, err)
			require.Equal(t, &user.DefaultInfo{
				Name: "fake-issuer#fake-user",
				Extra: map[string][]string{
					"iss": {"fake-issuer"},
					"sub": {"fake-user"},
				},
				Groups: []string{},
			}, authContext.UserInfo())
		})
	})
}

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
