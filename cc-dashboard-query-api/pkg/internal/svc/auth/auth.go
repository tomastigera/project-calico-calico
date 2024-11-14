package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/swaggest/openapi-go/openapi3"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/config"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
	"github.com/tigera/tds-apiserver/pkg/httpreply"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

type AuthService struct {
	client          dynamic.DynamicClient
	jwtAuth         lmaauth.JWTAuth
	logger          logging.Logger
	rbacAuthorizer  lmaauth.RBACAuthorizer
	tenantNamespace string
}

func NewAuthService(
	cfg *config.Config,
	logger logging.Logger,
	k8sClient kubernetes.Interface,
	k8sRestConfig *rest.Config,
	rbacAuthorizer lmaauth.RBACAuthorizer,
) (*AuthService, error) {
	var opts []lmaauth.JWTAuthOption

	if cfg.OIDCAuthIssuer != "" {
		dexAuth, err := lmaauth.NewDexAuthenticator(
			cfg.OIDCAuthIssuer,
			cfg.OIDCAuthClientID,
			cfg.OIDCAuthUsernameClaim,
			lmaauth.WithGroupsClaim(cfg.OIDCAuthGroupsClaim),
			lmaauth.WithJWKSURL(cfg.OIDCAuthJWKSURL),
			lmaauth.WithUsernamePrefix(cfg.OIDCAuthUsernamePrefix),
			lmaauth.WithGroupsPrefix(cfg.OIDCAuthGroupsPrefix),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to add an issuer to the authenticator: %v", err)
		}
		opts = append(opts, lmaauth.WithAuthenticator(cfg.OIDCAuthIssuer, dexAuth))
	}

	jwtAuth, err := lmaauth.NewJWTAuth(k8sRestConfig, k8sClient, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwtAuth: %v", err)
	}

	return &AuthService{
		logger:         logger,
		jwtAuth:        jwtAuth,
		rbacAuthorizer: rbacAuthorizer,
	}, nil
}

func (s *AuthService) NewUserAuthContextMapper() handleradapters.ReqMapper[security.AuthContext] {
	return handleradapters.NewReqMapper[security.AuthContext](
		func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (security.AuthContext, bool) {
			authContext, err := s.authenticateRequest(r)
			if err != nil {
				// errors are expected here, e.g. token expired, missing, invalid, etc., we don't want alerts so we log at info level
				// once we have an authenticated subject, any subsequent errors below are unexpected and should be logged at error level
				s.logger.Log(r.Context(), logging.InfoLevel, "failed to authenticate request", logging.Error(err))
				handleradapters.WriteErr(httpreply.ReplyAccessDenied, w, r)
				return nil, false
			}
			return authContext, true
		},
		func(op *openapi3.Operation, specOps *handleradapters.SpecOps) {
			specOps.RegisterSecurityScheme("bearer_jwt", openapi3.SecurityScheme{
				HTTPSecurityScheme: &openapi3.HTTPSecurityScheme{
					Scheme:       "bearer",
					BearerFormat: p("JWT"),
				},
			}, op)
		},
	)
}

func (s *AuthService) authenticateRequest(r *http.Request) (security.AuthContext, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, errors.New("no auth header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("not bearer auth")
	}

	userInfo, statusCode, err := s.jwtAuth.Authenticate(r)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected authentication status code: %d", statusCode)
	}

	return security.NewUserAuthContext(r.Context(), userInfo, s.rbacAuthorizer, s.tenantNamespace), nil
}

func p[T any](v T) *T { return &v }
