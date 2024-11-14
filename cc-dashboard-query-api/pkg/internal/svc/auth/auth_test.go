package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"

	authv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/config"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

func TestAuthService(t *testing.T) {

	logger := logging.New("TestAuthService")

	newSubject := func() (*AuthService, *rsa.PrivateKey, *fake.Clientset) {
		fakeClient := fake.NewSimpleClientset()

		jwtToken, err := jwt.NewBuilder().Issuer("fake-issuer").Build()
		require.NoError(t, err)

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		bearerToken, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256, key))
		require.NoError(t, err)

		subject, err := NewAuthService(
			&config.Config{},
			logger,
			fakeClient,
			&rest.Config{
				BearerToken: string(bearerToken),
			},
			security.RBACAuthorizerFunc(
				func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
					return true, nil
				}),
		)
		require.NoError(t, err)
		return subject, key, fakeClient
	}

	t.Run("authenticate", func(t *testing.T) {
		t.Run("missing auth header", func(t *testing.T) {
			subject, _, _ := newSubject()
			_, err := subject.authenticateRequest(&http.Request{})
			require.ErrorContains(t, err, "no auth header")
		})

		t.Run("missing bearer auth", func(t *testing.T) {
			subject, _, _ := newSubject()
			_, err := subject.authenticateRequest(&http.Request{
				Header: http.Header{
					"Authorization": []string{"hello world"},
				},
			})
			require.ErrorContains(t, err, "not bearer auth")
		})

		t.Run("not authenticated", func(t *testing.T) {
			subject, key, _ := newSubject()
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

		t.Run("authenticated", func(t *testing.T) {
			subject, key, client := newSubject()

			client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
				obj := action.(k8stesting.CreateAction).GetObject().(*authv1.TokenReview)
				obj.Status.Authenticated = true
				obj.Status.User.Username = "fake-user"
				return false, obj, nil
			})

			jwtToken, err := jwt.NewBuilder().Issuer("fake-issuer").Build()
			require.NoError(t, err)

			bearerToken, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256, key))
			require.NoError(t, err)

			authContext, err := subject.authenticateRequest(&http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer " + string(bearerToken)},
				},
			})
			require.NoError(t, err)
			require.Equal(t, &user.DefaultInfo{Name: "fake-user", Extra: map[string][]string{}}, authContext.UserInfo())
		})
	})
}
