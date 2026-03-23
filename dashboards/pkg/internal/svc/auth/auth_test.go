package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/tigera/tds-apiserver/lib/logging"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	lmatesting "github.com/projectcalico/calico/lma/pkg/auth/testing"
)

func TestAuthService(t *testing.T) {

	logger := logging.New("TestAuthService")

	newSubject := func(t *testing.T, cfg *config.Config, dexOptions ...lmaauth.DexOption) (*AuthService, *rsa.PrivateKey, *k8sfake.Clientset) {
		fakeClient := k8sfake.NewSimpleClientset() //nolint:staticcheck // NewClientset doesn't support TokenReview

		jwtToken, err := jwt.NewBuilder().Issuer("fake-issuer").Build()
		require.NoError(t, err)

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		bearerToken, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256, key))
		require.NoError(t, err)

		authorizer, err := security.NewAuthorizer(
			t.Context(),
			logger,
			time.Second,
			security.AuthorizerConfig{
				Namespace:                             "",
				EnableNamespacedRBAC:                  cfg.NamespacedRBAC,
				AuthorizedVerbsCacheHardTTL:           time.Second,
				AuthorizedVerbsCacheSoftTTL:           time.Second,
				AuthorizedVerbsCacheReviewsTimeout:    time.Second,
				AuthorizedVerbsCacheRevalidateTimeout: time.Second,
			},
			nil,
		)
		require.NoError(t, err)

		subject, err := NewAuthService(
			cfg,
			logger,
			"fake-tenant-id",
			"fake-tenant",
			authorizer,
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
			subject, _, _ := newSubject(t, &config.Config{})
			_, err := subject.authenticateRequest(&http.Request{})
			require.ErrorContains(t, err, "no auth header")
		})

		t.Run("missing bearer auth", func(t *testing.T) {
			subject, _, _ := newSubject(t, &config.Config{})
			_, err := subject.authenticateRequest(&http.Request{
				Header: http.Header{
					"Authorization": []string{"hello world"},
				},
			})
			require.ErrorContains(t, err, "not bearer auth")
		})

		t.Run("not authenticated", func(t *testing.T) {
			subject, key, _ := newSubject(t, &config.Config{})

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
			subject, _, _ := newSubject(t, &config.Config{OIDCAuthIssuer: "fake-issuer", OIDCAuthClientID: "fake-client-id"}, lmaauth.WithKeySet(keySet))

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
			subject, _, _ := newSubject(t, &config.Config{
				OIDCAuthIssuer:   "fake-issuer",
				OIDCAuthClientID: "fake-client-id",
				ProductMode:      config.ProductModeCloud,
			}, lmaauth.WithKeySet(keySet))

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

			t.Run("with groups claim", func(t *testing.T) {
				keySet := &testKeySet{}
				subject, _, _ := newSubject(t, &config.Config{
					OIDCAuthIssuer:      "fake-issuer",
					OIDCAuthClientID:    "fake-client-id",
					OIDCAuthGroupsClaim: "fake-groups-claim",
					ProductMode:         config.ProductModeCloud,
				}, lmaauth.WithKeySet(keySet))

				fakeJWT := lmatesting.NewFakeJWT("fake-issuer", "fake-user").
					WithClaim(lmaauth.ClaimNameAud, "fake-client-id").
					WithClaim("https://calicocloud.io/tenantIDs", []string{"fake-tenant"}).
					WithClaim("fake-groups-claim", []string{"fake-group1", "fake-group2"})
				keySet.On("VerifySignature", mock.Anything, fakeJWT.ToString()).Return([]byte(fakeJWT.PayloadJSON), nil)

				authContext, err := subject.authenticateRequest(&http.Request{
					Header: http.Header{
						"Authorization": []string{fakeJWT.BearerTokenHeader()},
					},
				})
				require.NoError(t, err)
				require.Equal(t, []string{"fake-group1", "fake-group2"}, authContext.Groups())
			})
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
