// Copyright (c) 2020 Tigera, Inc. All rights reserved.

package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/lma/pkg/cache"
	"github.com/projectcalico/calico/pkg/nonclusterhost"
)

// Common claim names
const (
	ClaimNameIss           = "iss"
	ClaimNameSub           = "sub"
	ClaimNameExp           = "exp"
	ClaimNameName          = "name"
	ClaimNameEmail         = "email"
	ClaimNameAud           = "aud"
	ClaimNameEmailVerified = "email_verified"
	ClaimNameGroups        = "groups"
)

const (
	// ServiceAccountIss is the issuer value for Kubernetes service account tokens.
	ServiceAccountIss = "kubernetes/serviceaccount"

	// tigeraOperatorCAIssuer is the CommonName for the Tigera operator signed certificates.
	// NOTE: This value must match the Tigera operator source:
	// https://github.com/tigera/operator/blob/ef576c48ab9537ee8579f7c8cbe0c7430e5f1af4/pkg/render/common/meta/meta.go#L38
	tigeraOperatorCAIssuer = "tigera-operator-signer"
)

// JWTAuth replaces the now deprecated AggregateAuthenticator for the following reasons:
//   - It is faster. It extracts the issuer from the token and only authenticates based on that issuer.
//   - It takes impersonation headers into account.
//   - It uses token reviews in favour of authentication reviews. This is the k8s native way of authn and does not need
//     special RBAC permissions.
//
// JWTAuth should be constructed with a k8s client and interface for service account token auth and for the authorization
// checks that are related to impersonation. It then accepts extra authenticators for any other bearer JWT token issuers,
// as described in RFC-7519.
//
// Note: JWTAuth is for JWT bearer tokens and does not support basic auth or other tokens.
type JWTAuth interface {
	Authenticator

	RBACAuthorizer
}

// Authenticator authenticates a user based on an authorization header, whether the user uses basic auth or token auth.
type Authenticator interface {
	// Authenticate checks if a request is authenticated. It accepts only JWT bearer tokens (RFC-6750, RFC-7519).
	// If it has impersonation headers, it will also check if the authenticated user is authorized
	// to impersonate. The resulting user info will be that of the impersonated user.
	Authenticate(r *http.Request) (userInfo user.Info, httpStatusCode int, err error)
}

// JWTAuthOption can be provided to NewJWTAuth to configure the authenticator.
type JWTAuthOption func(config *jwtAuthConfig) error

type k8sAuthn struct {
	tokenReviewer tokenReviewer
}

// Authenticate expects an authorization header containing a bearer token and returns the authenticated user.
func (k *k8sAuthn) Authenticate(r *http.Request) (userInfo user.Info, httpStatusCode int, err error) {
	// This will return an error when:
	// - No authorization header is present
	// - No Bearer prefix is present in the authorization header
	// - No JWT is present
	_, err = jws.ParseJWTFromRequest(r)
	if err != nil {
		return nil, http.StatusUnauthorized, jws.ErrNoTokenInRequest
	}
	authHeader := r.Header.Get("Authorization")

	// Strip the "Bearer " part of the token.
	token := authHeader[7:]
	tknReviewStatus, err := k.tokenReviewer.Review(
		context.Background(),
		authnv1.TokenReviewSpec{Token: token},
	)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !tknReviewStatus.Authenticated {
		return nil, http.StatusUnauthorized, fmt.Errorf("user is not authenticated")
	}

	return &user.DefaultInfo{
		Name:   tknReviewStatus.User.Username,
		Groups: tknReviewStatus.User.Groups,
		Extra:  toExtra(tknReviewStatus.User.Extra),
	}, http.StatusOK, nil
}

type tigeraAuthn struct {
	k8sClient kubernetes.Interface
	publicKey *rsa.PublicKey
}

func (n *tigeraAuthn) Authenticate(r *http.Request) (userInfo user.Info, httpStatusCode int, err error) {
	_, err = jws.ParseJWTFromRequest(r)
	if err != nil {
		return nil, http.StatusUnauthorized, jws.ErrNoTokenInRequest
	}
	authHeader := r.Header.Get("Authorization")

	// Strip the "Bearer " part of the token.
	token := authHeader[7:]
	// Parse the JWT claims.
	claims := &jwt.RegisteredClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return n.publicKey, nil
	})
	// jwt.ParseWithClaims automatically validates time-based claims ("exp", "iat", "nbf")
	// by calling claims.Valid(). Therefore, token.Valid ensures these claims are checked.
	if err != nil || !tkn.Valid {
		return nil, http.StatusUnauthorized, err
	}

	// Must match Tigera issuer
	if claims.Issuer != nonclusterhost.TigeraIssuer {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid issuer")
	}
	// Audience must match tigera-manager
	if len(claims.Audience) != 1 || claims.Audience[0] != nonclusterhost.TigeraManagerAudience {
		return nil, http.StatusUnauthorized, fmt.Errorf("invalid audience")
	}

	// Service account must exist in the cluster
	namespace, name, err := serviceaccount.SplitUsername(claims.Subject)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	sa, err := n.k8sClient.CoreV1().ServiceAccounts(namespace).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	return &user.DefaultInfo{
		Name: claims.Subject,
		UID:  string(sa.UID),
		Groups: []string{
			serviceaccount.AllServiceAccountsGroup,
			"system:authenticated",
			fmt.Sprintf("%s%s", serviceaccount.ServiceAccountGroupPrefix, sa.Namespace),
		},
	}, http.StatusOK, nil
}

// WithAuthenticator adds an authenticator for a specific token issuer.
func WithAuthenticator(issuer string, authenticator Authenticator) JWTAuthOption {
	return func(a *jwtAuthConfig) error {
		a.authenticators[issuer] = authenticator
		return nil
	}
}

// WithTokenReviewCacheTTL adds caching to TokenReview requests that are used for authenticating Service Accounts
func WithTokenReviewCacheTTL(ctx context.Context, ttl time.Duration) JWTAuthOption {
	return func(c *jwtAuthConfig) error {
		if ttl <= 0 {
			return nil
		} else if ttl > TokenReviewCacheMaxTTL {
			return fmt.Errorf("configured cacheTTL of %v exceeds maximum permitted of %v", ttl, TokenReviewCacheMaxTTL)
		} else if c.tokenReviewCacheTTL > 0 {
			return fmt.Errorf("caching for TokenReview requests is already enabled with TTL of %v", c.tokenReviewCacheTTL)
		}

		expiringCache, err := cache.NewExpiring[string, authnv1.TokenReviewStatus](cache.ExpiringConfig{
			Context: ctx,
			Name:    "lma-token-reviewer",
			TTL:     ttl,
		})
		if err != nil {
			return err
		}
		c.tokenReviewer = newCachingTokenReviewer(expiringCache, c.tokenReviewer)
		c.tokenReviewCacheTTL = ttl
		return nil
	}
}

// WithAuthzCacheTTL enables caching for Authorize() requests when ttl > 0 up to a maximum of AuthzCacheMaxTTL.
func WithAuthzCacheTTL(ctx context.Context, ttl time.Duration) JWTAuthOption {
	return func(c *jwtAuthConfig) error {
		if ttl <= 0 {
			return nil
		} else if ttl > AuthzCacheMaxTTL {
			return fmt.Errorf("configured cacheTTL of %v exceeds maximum permitted of %v", ttl, AuthzCacheMaxTTL)
		} else if c.authzCacheTTL > 0 {
			return fmt.Errorf("caching for Authorize() requests is already enabled with TTL of %v", c.authzCacheTTL)
		}

		expiringCache, err := cache.NewExpiring[string, bool](cache.ExpiringConfig{
			Context: ctx,
			Name:    "lma-authz-cache",
			TTL:     ttl,
		})
		if err != nil {
			return fmt.Errorf("failed to create authz cache: %v", err)
		}
		c.authorizer = NewCachingAuthorizer(expiringCache, c.authorizer)
		c.authzCacheTTL = ttl
		logrus.Infof("lma-authz-cache is enabled for jwtAuth.Authorize() requests with TTL of %v", ttl)

		return nil
	}
}

func WithTigeraIssuerPublicKey(certPath string) JWTAuthOption {
	return func(c *jwtAuthConfig) error {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read certificate file: %w", err)
		}

		var block *pem.Block
		rest := certPEM
		for {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logrus.WithError(err).Warn("Invalid certificate encountered in PEM file, skipping")
				continue
			}

			if cert.Subject.CommonName == tigeraOperatorCAIssuer {
				pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
				if !ok {
					logrus.Warn("Certificate does not contain an RSA public key, skipping")
					continue
				}
				c.tigeraIssuerPublicKey = pubKey
				return nil
			}
		}
		return fmt.Errorf("no valid Tigera issuer public key found in bundle: %s", certPath)
	}
}

// NewJWTAuth creates an object adhering to the Auth interface. It can perform authN and authZ.
func NewJWTAuth(restConfig *rest.Config, k8sCli kubernetes.Interface, options ...JWTAuthOption) (JWTAuth, error) {
	// This will return an error when:
	// - No authorization header is present
	// - No Bearer prefix is present in the authorization header
	// - No JWT is present
	jwt, err := jws.ParseJWT([]byte(restConfig.BearerToken))
	if err != nil {
		return nil, err
	}

	// The rest config's issuer may be different from ServiceAccountIss. If this is the case, we need to add the authenticator
	// for this issuer as well. Impersonating users' bearer tokens will have this issuer.
	k8sIss, ok := jwt.Claims().Issuer()
	if !ok {
		return nil, fmt.Errorf("cannot derive issuer from in-cluster configuration: %v", jws.ErrIsNotJWT)
	}

	cfg := &jwtAuthConfig{
		authenticators: map[string]Authenticator{},
		tokenReviewer:  newK8sTokenReviewer(k8sCli),
		authorizer:     NewRBACAuthorizer(k8sCli),
	}
	for _, opt := range options {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	// tigeraAuthn is the authenticator for tokens issued by the Tigera issuer.
	cfg.authenticators[nonclusterhost.TigeraIssuer] = &tigeraAuthn{
		k8sClient: k8sCli,
		publicKey: cfg.tigeraIssuerPublicKey,
	}
	// k8sAuthn is the authenticator for tokens issued by the Kubernetes API server.
	authn := &k8sAuthn{cfg.tokenReviewer}

	jAuth := &jwtAuth{
		authenticators: map[string]Authenticator{
			// This issuer is used for tokens from service account secrets.
			ServiceAccountIss: authn,
			// This user is used for tokens from impersonating users.
			k8sIss: authn,
		},
		RBACAuthorizer: cfg.authorizer,
	}
	maps.Copy(jAuth.authenticators, cfg.authenticators)

	return jAuth, nil
}

type jwtAuth struct {
	authenticators map[string]Authenticator
	RBACAuthorizer
}

type jwtAuthConfig struct {
	authenticators map[string]Authenticator
	tokenReviewer  tokenReviewer
	authorizer     RBACAuthorizer

	// these values are stored to ensure their WithXXX functions are not run more than once
	tokenReviewCacheTTL time.Duration
	authzCacheTTL       time.Duration

	// TigeraAuthPublicKey is the public key used to verify JWTs issued by the Tigera issuer.
	tigeraIssuerPublicKey *rsa.PublicKey
}

// Authenticate checks if a request is authenticated. It accepts only JWT bearer tokens.
// If it has impersonation headers, it will also check if the authenticated user is authorized
// to impersonate. The resulting user info will be that of the impersonated user.
func (a *jwtAuth) Authenticate(req *http.Request) (user.Info, int, error) {
	// This will return an error when:
	// - No authorization header is present
	// - No Bearer prefix is present in the authorization header
	// - No JWT is present
	jwt, err := jws.ParseJWTFromRequest(req)
	if err != nil {
		return nil, http.StatusUnauthorized, jws.ErrNoTokenInRequest
	}

	issuer, ok := jwt.Claims().Issuer()
	if !ok {
		return nil, http.StatusUnauthorized, jws.ErrIsNotJWT
	}

	authn, ok := a.authenticators[issuer]
	var userInfo user.Info
	if ok {
		usr, stat, err := authn.Authenticate(req)
		if err != nil {
			return usr, stat, err
		}
		userInfo = usr
	} else {
		return nil, http.StatusBadRequest, fmt.Errorf("bearer token was not issued by a trusted issuer")
	}

	// If a user was impersonated, see if the impersonating user is allowed to impersonate.
	impersonatedUser, err := extractUserFromImpersonationHeaders(req)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	if impersonatedUser != nil {
		attributes := buildResourceAttributesForImpersonation(impersonatedUser)

		for _, resAtr := range attributes {
			ok, err = a.Authorize(userInfo, resAtr, nil)
			if err != nil {
				return nil, http.StatusInternalServerError, err
			} else if !ok {
				return nil, http.StatusUnauthorized, fmt.Errorf("user is not allowed to impersonate")
			}
		}
		userInfo = impersonatedUser
	}
	return userInfo, http.StatusOK, nil
}

// toExtra convenience func to convert the extra's from user.info's.
func toExtra(extra map[string]authnv1.ExtraValue) map[string][]string {
	ret := make(map[string][]string)
	for k, v := range extra {
		ret[k] = v
	}
	return ret
}

// extractUserFromImpersonationHeaders extracts the user info if a user is impersonated.
// See https://kubernetes.io/docs/reference/access-authn-authz/authentication/ for more information on how authn
// and authz come into play when authenticating.
func extractUserFromImpersonationHeaders(req *http.Request) (user.Info, error) {
	userName := req.Header.Get(authnv1.ImpersonateUserHeader)
	groups := req.Header[authnv1.ImpersonateGroupHeader]
	extras := make(map[string][]string)
	for headerName, value := range req.Header {
		if strings.HasPrefix(headerName, authnv1.ImpersonateUserExtraHeaderPrefix) {
			encodedKey := strings.ToLower(headerName[len(authnv1.ImpersonateUserExtraHeaderPrefix):])
			extraKey, err := url.PathUnescape(encodedKey)
			if err != nil {
				err := fmt.Errorf("malformed extra key for impersonation request")
				logrus.WithError(err).Errorf("Could not decode extra key %s", encodedKey)
			}
			extras[extraKey] = value
		}
	}

	if len(userName) == 0 && (len(groups) != 0 || len(extras) != 0) {
		return nil, fmt.Errorf("impersonation headers are missing impersonate user header")
	}

	if len(userName) != 0 {
		return &user.DefaultInfo{
			Name:   userName,
			Groups: groups,
			Extra:  extras,
		}, nil
	}
	return nil, nil
}

// buildResourceAttributesForImpersonation is a convenience func for performing authz checks when users are impersonated.
// See https://kubernetes.io/docs/reference/access-authn-authz/authentication/ for more information on how authn
// and authz come into play when authenticating.
func buildResourceAttributesForImpersonation(usr user.Info) []*authzv1.ResourceAttributes {
	var result []*authzv1.ResourceAttributes
	namespace, name, err := serviceaccount.SplitUsername(usr.GetName())
	if err == nil {
		result = append(result, &authzv1.ResourceAttributes{
			Verb:      "impersonate",
			Resource:  "serviceaccounts",
			Name:      name,
			Namespace: namespace,
		})
	} else {
		result = append(result, &authzv1.ResourceAttributes{
			Verb:     "impersonate",
			Resource: "users",
			Name:     usr.GetName(),
		})
	}

	for _, group := range usr.GetGroups() {
		result = append(result, &authzv1.ResourceAttributes{
			Verb:     "impersonate",
			Resource: "groups",
			Name:     group,
		})
	}

	for key, extra := range usr.GetExtra() {
		for _, value := range extra {
			result = append(result, &authzv1.ResourceAttributes{
				Verb:        "impersonate",
				Resource:    "userextras",
				Subresource: key,
				Name:        value,
			})
		}
	}

	return result
}
