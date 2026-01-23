package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/SermoDigital/jose/jws"
	"github.com/julienschmidt/httprouter"
	"github.com/swaggest/openapi-go/openapi3"
	"github.com/tigera/tds-apiserver/lib/httpreply"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/pkg/http/handleradapters"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	"github.com/projectcalico/calico/dashboards/pkg/internal/security"
	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/projectcalico/calico/lma/pkg/k8s"
)

type AuthService struct {
	logger                         logging.Logger
	jwtAuth                        lmaauth.JWTAuth
	tenantID                       string
	authorizer                     security.Authorizer
	baseK8sConfig                  *rest.Config
	groupsClaimKey                 string
	productMode                    string
	multiClusterForwardingEndpoint string
	multiClusterForwardingCA       string
}

func NewAuthService(
	cfg *config.Config,
	logger logging.Logger,
	tenantID string,
	tenantClaim string,
	authorizer security.Authorizer,
	k8sClient kubernetes.Interface,
	k8sRestConfig *rest.Config,
	dexOptions ...lmaauth.DexOption,
) (*AuthService, error) {
	var opts []lmaauth.JWTAuthOption

	if cfg.OIDCAuthIssuer != "" {
		dexOptions = append(dexOptions,
			lmaauth.WithGroupsClaim(cfg.OIDCAuthGroupsClaim),
			lmaauth.WithUsernamePrefix(cfg.OIDCAuthUsernamePrefix),
			lmaauth.WithGroupsPrefix(cfg.OIDCAuthGroupsPrefix),
		)

		if tenantClaim != "" {
			dexOptions = append(dexOptions, lmaauth.WithCalicoCloudTenantClaim(tenantClaim))
		}

		if cfg.OIDCAuthJWKSURL != "" {
			dexOptions = append(dexOptions, lmaauth.WithJWKSURL(cfg.OIDCAuthJWKSURL))
		}

		dexAuth, err := lmaauth.NewDexAuthenticator(
			cfg.OIDCAuthIssuer,
			cfg.OIDCAuthClientID,
			cfg.OIDCAuthUsernameClaim,
			dexOptions...,
		)
		if err != nil {
			return nil, fmt.Errorf("unable to add an issuer to the authenticator: %v", err)
		}
		opts = append(opts, lmaauth.WithAuthenticator(cfg.OIDCAuthIssuer, dexAuth))
	}

	baseCfg := rest.CopyConfig(k8sRestConfig)
	jwtAuth, err := lmaauth.NewJWTAuth(baseCfg, k8sClient, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create jwtAuth: %v", err)
	}

	return &AuthService{
		logger:                         logger,
		tenantID:                       tenantID,
		jwtAuth:                        jwtAuth,
		authorizer:                     authorizer,
		productMode:                    cfg.ProductMode,
		baseK8sConfig:                  baseCfg,
		groupsClaimKey:                 cfg.OIDCAuthGroupsClaim,
		multiClusterForwardingEndpoint: cfg.MultiClusterForwardingEndpoint,
		multiClusterForwardingCA:       cfg.MultiClusterForwardingCA,
	}, nil
}

func (s *AuthService) NewUserAuthContextMapper() handleradapters.ReqMapper[security.Context] {
	return handleradapters.NewReqMapper[security.Context](
		func(w http.ResponseWriter, r *http.Request, p httprouter.Params) (security.Context, bool) {
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

func (s *AuthService) authenticateRequest(r *http.Request) (security.Context, error) {
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

	k8sRestConfig := rest.CopyConfig(s.baseK8sConfig)

	var groups []string
	// Configure the Kubernetes client based on product mode.
	switch s.productMode {
	case config.ProductModeEnterprise:
		// In Enterprise mode, we impersonate the authenticated user directly in the k8s client.
		k8sRestConfig.Impersonate = rest.ImpersonationConfig{
			UserName: userInfo.GetName(),
			Groups:   userInfo.GetGroups(),
		}
	case config.ProductModeCloud:
		// In Cloud mode, talk to voltron via the multi-cluster forwarding endpoint and CA so that voltron performs
		// impersonation on our behalf.
		// Create a new user auth k8s rest config to ensure authorisation against the user's bearer token.
		k8sRestConfig = &rest.Config{
			Host:        s.multiClusterForwardingEndpoint,
			BearerToken: strings.TrimPrefix(authHeader, "Bearer "),
		}

		if s.multiClusterForwardingCA != "" {
			k8sRestConfig.CAFile = s.multiClusterForwardingCA
		}

		requestJWT, err := jws.ParseJWTFromRequest(r)
		if err != nil {
			return nil, jws.ErrNoTokenInRequest
		}

		claimGroups := requestJWT.Claims().Get(s.groupsClaimKey)
		if anyGroups, ok := claimGroups.([]any); ok {
			for _, anyGroup := range anyGroups {
				if group, ok := anyGroup.(string); ok {
					groups = append(groups, group)
				}
			}
		}

	default:
		return nil, fmt.Errorf("unsupported product mode: %s", s.productMode)
	}

	k8sClient, err := kubernetes.NewForConfig(k8sRestConfig)
	if err != nil {
		return nil, err
	}

	clientSetFactory := k8s.NewClientSetFactoryWithConfig(
		k8sRestConfig,
		s.multiClusterForwardingCA,
		s.multiClusterForwardingEndpoint,
	)

	return security.NewUserAuthContext(r.Context(), userInfo, s.authorizer, k8sClient, authHeader, clientSetFactory, s.tenantID, groups), nil
}

func p[T any](v T) *T { return &v }
