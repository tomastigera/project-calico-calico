package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/SermoDigital/jose/jws"
	"github.com/coreos/go-oidc"
	"github.com/go-jose/go-jose/v4"
	log "github.com/sirupsen/logrus"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	signingAlg           = "RS256"
	defaultUsernameClaim = "sub"
	defaultGroupsClaim   = "groups"
	noUsernamePrefix     = "-"
)

type dexAuthenticator struct {
	// The issuer as it is added to the JWTs. Ex. https://tigera-manager/dex
	issuer string

	clientID string

	usernameClaim string

	groupsClaim string

	usernamePrefix *string

	groupsPrefix string

	verifier *oidc.IDTokenVerifier

	claimValidators []claimValidator
}

// claimValidator is not exported to avoid the need to safe copy the claims map before each call
type claimValidator func(claims map[string]any) error

// DexOption can be provided to NewDexAuthenticator to configure the authenticator.
type DexOption func(*dexAuthenticator) error

// NewDexAuthenticator creates an authenticator that uses DexIdp to validate authorization headers.
func NewDexAuthenticator(issuer, clientID, usernameClaim string, options ...DexOption) (Authenticator, error) {
	if issuer == "" {
		return nil, errors.New("issuer is a required field")
	}

	if clientID == "" {
		return nil, errors.New("clientID is a required field")
	}

	dex := &dexAuthenticator{
		issuer:        issuer,
		clientID:      clientID,
		groupsClaim:   defaultGroupsClaim,
		usernameClaim: usernameClaim,
	}

	if usernameClaim == "" {
		dex.usernameClaim = defaultUsernameClaim
	}

	for _, option := range options {
		if err := option(dex); err != nil {
			return nil, err
		}
	}

	if dex.usernamePrefix == nil {
		if err := WithUsernamePrefix("")(dex); err != nil {
			return nil, err
		}
	}

	return dex, nil
}

// WithJWKSURL The authenticator will validate JWT signatures based on the public keys that are available at this URL.
// Cannot be used in combination with WithKeySet().
func WithJWKSURL(jwksURL string) DexOption {
	return func(d *dexAuthenticator) error {
		if d.verifier != nil {
			return errors.New("can only use one of: [WithKeySet(), WithJWKSURL()]")
		}

		d.verifier = oidc.NewVerifier(d.issuer,
			oidc.NewRemoteKeySet(context.Background(), jwksURL),
			&oidc.Config{
				ClientID:             d.clientID,
				SkipClientIDCheck:    false,
				SkipExpiryCheck:      false,
				SupportedSigningAlgs: []string{signingAlg},
				SkipIssuerCheck:      false,
			})
		return nil
	}
}

// WithKeySet Provide your own keyset to validate JWT signatures. Useful for testing. Cannot be used in combination with
// WithJWKSURL().
func WithKeySet(keySet oidc.KeySet) DexOption {
	return func(d *dexAuthenticator) error {
		if d.verifier != nil {
			return errors.New("can only use one of the following options: [WithKeySet(), WithJWKSURL()]")
		}

		d.verifier = oidc.NewVerifier(d.issuer,
			keySet,
			&oidc.Config{
				ClientID:             d.clientID,
				SkipClientIDCheck:    false,
				SkipExpiryCheck:      false,
				SupportedSigningAlgs: []string{signingAlg},
				SkipIssuerCheck:      false,
			})
		return nil
	}
}

// WithGroupsClaim set the claim to extract groups from a JWT. Default: 'groups'.
func WithGroupsClaim(groupsClaim string) DexOption {
	return func(d *dexAuthenticator) error {
		d.groupsClaim = groupsClaim
		return nil
	}
}

func withClaimValidator(validator claimValidator) DexOption {
	return func(d *dexAuthenticator) error {
		d.claimValidators = append(d.claimValidators, validator)
		return nil
	}
}

// WithCalicoCloudTenantClaim adds required Calico Cloud Tenant claim
func WithCalicoCloudTenantClaim(requiredTenantID string) DexOption {
	return withClaimValidator(func(claims map[string]any) error {

		const claimName = "https://calicocloud.io/tenantIDs"

		if claimValue, ok := claims[claimName]; !ok {
			return fmt.Errorf("%s claim is missing", claimName)
		} else if tenantIDs, ok := claimValue.([]any); !ok {
			return fmt.Errorf("%s claims is a %T, expected []any", claimName, claimValue)
		} else if !slices.Contains(tenantIDs, any(requiredTenantID)) {
			return fmt.Errorf("%s claims '%v' do not contain '%v'", claimName, tenantIDs, requiredTenantID)
		}
		return nil
	})
}

// The value passed in as a prefix will be modified according to the kubernetes specs for UsernamePrefix for backwards
// compatibility purposes.
// See: kubernetes/pkg/kubeapiserver/authenticator/config.go or
// https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/ for more details.
func WithUsernamePrefix(usernamePrefix string) DexOption {
	return func(d *dexAuthenticator) error {
		prefix := usernamePrefix

		if usernamePrefix == "" && d.usernameClaim != "email" {
			// Old behavior. If a usernamePrefix isn't provided, prefix all claims other than "email"
			// with the issuerURL.
			//
			// See https://github.com/kubernetes/kubernetes/issues/31380
			prefix = d.issuer + "#"
		}

		if usernamePrefix == noUsernamePrefix {
			// Special value indicating usernames shouldn't be prefixed.
			prefix = ""
		}

		d.usernamePrefix = &prefix
		return nil
	}
}

// WithGroupsPrefix adds a prefix to every extracted group from a JWT.
func WithGroupsPrefix(groupsPrefix string) DexOption {
	return func(d *dexAuthenticator) error {
		d.groupsPrefix = groupsPrefix
		return nil
	}
}

// Authenticate returns user info if the authHeader has a valid token issued by Dex.
// Returns HTTP code 421 if the issuer is not Dex.
// Returns an error if the auth header does not contain a valid credential.
func (d *dexAuthenticator) Authenticate(r *http.Request) (user.Info, int, error) {
	// This will return an error when:
	// - No authorization header is present
	// - No Bearer prefix is present in the authorization header
	// - No JWT is present
	jwt, err := jws.ParseJWTFromRequest(r)
	if err != nil {
		return nil, http.StatusUnauthorized, jws.ErrNoTokenInRequest
	}
	authHeader := r.Header.Get("Authorization")

	// Strip the "Bearer " part of the token.
	tkn := authHeader[7:]
	tkn = strings.TrimSpace(tkn)

	tokenPayloadMap := jwt.Claims()

	iss := tokenPayloadMap["iss"].(string)
	if iss != d.issuer {
		return nil, http.StatusMisdirectedRequest, errors.New("not a dex header: issuer of JWT does not match the issuer url of dex")
	}

	// Now that we know the token was issued by dex, we can verify if it is (still) valid and extract the user.
	_, err = jose.ParseSigned(tkn, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512})
	if err != nil {
		return nil, http.StatusUnauthorized, errors.New("dex token has an invalid signature")
	}

	idTkn, err := d.verifier.Verify(context.Background(), tkn)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	var claims map[string]any
	if err := idTkn.Claims(&claims); err != nil {
		return nil, http.StatusInternalServerError, err
	}

	usr, ok := claims[d.usernameClaim]
	if !ok {
		return nil, http.StatusUnauthorized, fmt.Errorf("unable to extract username from JWT using claim %s", d.usernameClaim)
	}

	username, ok := usr.(string)
	if !ok {
		return nil, http.StatusBadRequest, errors.New("the username should be of type string")
	}

	if username == "" {
		return nil, http.StatusUnauthorized, errors.New("no user found in JWT")
	}
	username = fmt.Sprintf("%s%s", *d.usernamePrefix, usr)
	groups := []string{}

	if claims[d.groupsClaim] != nil {
		groupsClaims, ok := claims[d.groupsClaim].([]any)
		if !ok {
			return nil, http.StatusBadRequest, errors.New("unexpected type for groups claim")
		}

		for _, group := range groupsClaims {
			groupStr, ok := group.(string)
			if !ok {
				return nil, http.StatusBadRequest, errors.New("unexpected type for element in groups claim")
			}
			groups = append(groups, fmt.Sprintf("%s%s", d.groupsPrefix, groupStr))
		}
	}

	for _, validator := range d.claimValidators {
		if err := validator(claims); err != nil {
			log.WithFields(log.Fields{
				"username": username,
			}).
				WithError(err).
				Warn("invalid claim")
			return nil, http.StatusUnauthorized, fmt.Errorf("claim validation failed")
		}
	}

	// Setting issuer and subject as Extra, this can be used to identify userInfo authenticated by dex
	extra := make(map[string][]string)
	extra["iss"] = []string{iss}
	if subClaim, ok := claims[defaultUsernameClaim].(string); !ok {
		log.Warn("subject claim is not of type string")
	} else {
		extra["sub"] = []string{subClaim}
	}

	return &user.DefaultInfo{
		Name:   username,
		Groups: groups,
		Extra:  extra,
	}, http.StatusOK, nil
}
