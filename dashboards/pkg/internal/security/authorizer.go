package security

import (
	"context"
	"errors"
	"fmt"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/logging"
	tdsslices "github.com/tigera/tds-apiserver/lib/slices"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/dashboards/pkg/internal/config"
	lmacache "github.com/projectcalico/calico/lma/pkg/cache"
	"github.com/projectcalico/calico/ui-apis/pkg/authzreview"
)

const APIGroupLMATigera = "lma.tigera.io"

type Authorizer interface {
	Authorize(ctx Context, apiGroup string, resourceName []string, resource *string) (bool, error)
	GetAuthorizedResourceVerbs(ctx Context, managedClusterNames []string) (PermissionsResult, error)
}

var ErrAuthorizationReviewTimeout = errors.New("authorization review timeout")

type authorizedResourcesVerbsCacheItemResult struct {
	err       error
	resource  string
	cacheItem *authorizedResourcesVerbsCacheEntry
}

type rulesAuthorizer struct {
	cfg                          AuthorizerConfig
	logger                       logging.Logger
	namespace                    string
	reviewer                     authzreview.Reviewer
	rulesCache                   lmacache.LoadingCache[string, []authzv1.ResourceRule]
	authorizedResourceVerbsCache lmacache.LoadingCache[string, *authorizedResourcesVerbsCacheEntry]
}

type AuthorizerConfig struct {
	// Namespace controls the namespaced used to perform SelfSubjectRulesReviews on the management plane
	// Defaults to "default" if empty
	Namespace string

	// EnableNamespacedRBAC controls the namespaced RBAC feature that perform AuthorizationReviews on a managed plane
	EnableNamespacedRBAC bool

	// ProductMode determines whether the product is running in "enterprise" or "cloud" mode.
	ProductMode string

	// AuthorizedVerbsCacheHardTTL controls the TTL to expire cached authorizedResourcesVerbsCacheEntry items
	AuthorizedVerbsCacheHardTTL time.Duration

	// AuthorizedVerbsCacheSoftTTL controls the TTL to return cached authorizedResourcesVerbsCacheEntry without
	// performing new AuthorizationReviews to revalidate the cache entry
	AuthorizedVerbsCacheSoftTTL time.Duration

	// AuthorizedVerbsCacheRevalidateTimeout controls the timeout to return authorizedResourcesVerbs from the cache.
	// It will return stale authorizedResourcesVerbs if revalidation exceeds this timeout
	AuthorizedVerbsCacheRevalidateTimeout time.Duration

	// AuthorizedVerbsCacheReviewsTimeout controls the timeout to block authorization before proceeding with the set
	// of permissions that have become available
	AuthorizedVerbsCacheReviewsTimeout time.Duration
}

func NewAuthorizer(
	ctx context.Context,
	logger logging.Logger,
	lmaCacheTTL time.Duration,
	cfg AuthorizerConfig,
	reviewer authzreview.Reviewer,
) (Authorizer, error) {

	authorizer := &rulesAuthorizer{
		cfg:       cfg,
		logger:    logger,
		namespace: "default",
		reviewer:  reviewer,
	}

	if cfg.Namespace != "" {
		authorizer.namespace = cfg.Namespace
	}

	expiringCache, err := lmacache.NewExpiring[string, []authzv1.ResourceRule](lmacache.ExpiringConfig{
		Context: ctx,
		Name:    "lma-access-authorizer",
		TTL:     lmaCacheTTL,
	})
	if err != nil {
		return nil, err
	}

	authorizer.rulesCache = lmacache.NewLoadingCache(expiringCache)

	if cfg.EnableNamespacedRBAC {
		cache, err := lmacache.NewExpiring[string, *authorizedResourcesVerbsCacheEntry](
			lmacache.ExpiringConfig{
				Context: ctx,
				Name:    "authorized-verbs-authorizer",
				TTL:     cfg.AuthorizedVerbsCacheHardTTL,
			},
		)
		if err != nil {
			return nil, err
		}

		authorizer.authorizedResourceVerbsCache = lmacache.NewLoadingCache(cache)
	}

	return authorizer, nil
}

// Authorize perform an authorization check against the combination of apiGroup, resourceNames and resource for the user in ctx.UserInfo()
// A nil resource parameter will match any resource the user is authorized for, except for the "cluster" resource
func (a *rulesAuthorizer) Authorize(
	ctx Context,
	apiGroup string,
	resourceNames []string,
	resource *string,
) (bool, error) {

	cacheKey := toAuthorizeCacheKey(ctx.UserInfo())

	rules, err := a.rulesCache.GetOrLoad(cacheKey, func() ([]authzv1.ResourceRule, error) {
		return a.loadRules(ctx)
	})

	if err != nil {
		return false, err
	}

	authorized := isPermitted(rules, apiGroup, "get", resource, resourceNames)

	a.logger.DebugC(
		ctx,
		"authorize",
		logging.String("user", ctx.UserInfo().GetName()),
		logging.Bool("namespacedRBAC", a.cfg.EnableNamespacedRBAC),
		logging.Bool("authorized", authorized),
		logging.String("apiGroup", apiGroup),
		logging.String("namespace", a.namespace),
		logging.Stringp("resource", resource),
		logging.Strings("resourceNames", resourceNames),
	)

	return authorized, nil
}

// loadRules Return rules from a SelfSubjectRulesReview on the management plane
func (a *rulesAuthorizer) loadRules(ctx Context) ([]authzv1.ResourceRule, error) {

	selfSubjectRulesReview, err := ctx.KubernetesClient().AuthorizationV1().SelfSubjectRulesReviews().Create(
		ctx,
		&authzv1.SelfSubjectRulesReview{
			Spec: authzv1.SelfSubjectRulesReviewSpec{
				Namespace: a.namespace,
			},
		},
		metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return selfSubjectRulesReview.Status.ResourceRules, nil
}

// GetAuthorizedResourceVerbs returns a slice of AuthorizedResourceVerbs for the user from managed clusters set in the
// resources parameter
func (a *rulesAuthorizer) GetAuthorizedResourceVerbs(ctx Context, managedClusterNames []string) (PermissionsResult, error) {
	a.logger.DebugC(
		ctx,
		"GetAuthorizedResourceVerbs",
		logging.String("user", ctx.UserInfo().GetName()),
		logging.Bool("namespacedRBAC", a.cfg.EnableNamespacedRBAC),
	)

	if !a.cfg.EnableNamespacedRBAC {
		// Return a nil permission slice when namespaced RBAC is disabled
		// an empty or nil slice results in no namespace restrictions (i.e. all namespaces are authorized)
		// see https://github.com/tigera/calico-private/blob/8d1da1f9e79cdf01a775038202e51f93baf8b1df/linseed/pkg/backend/legacy/logtools/query.go#L32
		return PermissionsResult{}, nil
	}

	if a.cfg.ProductMode == config.ProductModeCloud {
		groupsAuthorizedForAllNamespaces := []string{
			fmt.Sprintf("tigera-auth-%s-admin", ctx.Tenant()),
			fmt.Sprintf("tigera-auth-%s-dashboards-admin", ctx.Tenant()),
			fmt.Sprintf("tigera-auth-%s-read-only", ctx.Tenant()),
		}

		if tdsslices.AnyMatch(ctx.Groups(), func(group string) bool {
			return tdsslices.Contains(groupsAuthorizedForAllNamespaces, group)
		}) {
			// an empty or nil slice results in no namespace restrictions (i.e. all namespaces are authorized)
			// see https://github.com/tigera/calico-private/blob/8d1da1f9e79cdf01a775038202e51f93baf8b1df/linseed/pkg/backend/legacy/logtools/query.go#L32
			return PermissionsResult{}, nil
		}
	}

	// Use a buffered channel to prevent goroutines blocking in case this function returns early
	chPermissions := make(chan authorizedResourcesVerbsCacheItemResult, len(managedClusterNames))
	for _, managedClusterName := range managedClusterNames {
		// Load permissions for every resource (managed cluster) on a goroutine and write it to chPermissions
		go func(resource string) {
			cacheKey := toAuthorizeCacheKeyForResource(ctx.UserInfo(), managedClusterName)
			cacheItem, err := a.getOrLoadAuthorizedResourceVerbs(ctx, cacheKey, managedClusterName)

			chPermissions <- authorizedResourcesVerbsCacheItemResult{
				err:       err,
				resource:  managedClusterName,
				cacheItem: cacheItem,
			}
		}(managedClusterName)
	}

	waitForAuthorizationReviewsStart := time.Now()
	// Set a timeout based on a.authorizationReviewTimeout to ensure any AuthorizationReview create request taking
	// too long to return will not block authorization indefinitely (on timeout, this function returns all
	// AuthorizedResourceVerbs available at that point).
	authorizationReviewsTimer := time.NewTimer(a.cfg.AuthorizedVerbsCacheReviewsTimeout)

	result := PermissionsResult{
		Errors: make(map[string][]error),
	}

	for _, managedClusterName := range managedClusterNames {
		result.Errors[managedClusterName] = []error{ErrAuthorizationReviewTimeout}
	}

GetAuthorizedResourceVerbsLoop:
	for resourcesResultCount := 0; resourcesResultCount < len(managedClusterNames); {
		select {
		case <-ctx.Done():
			return PermissionsResult{}, ctx.Err()
		case <-authorizationReviewsTimer.C:
			a.logger.DebugC(ctx,
				"AuthorizationReviewsTimeout expired. Returning partial results",
				logging.Duration("elapsed", time.Since(waitForAuthorizationReviewsStart)),
				logging.Any("authorizedResourceVerbs", result.AuthorizedResourceVerbs),
			)
			// authorizationReviewsTimer expired, return available partial results in authorizedResourceVerbs
			break GetAuthorizedResourceVerbsLoop
		case acItemResult := <-chPermissions:
			resourcesResultCount++

			a.logger.DebugC(ctx, "received AuthorizedResourceVerbs",
				logging.Error(acItemResult.err),
				logging.String("resource", acItemResult.resource),
				logging.Duration("elapsed", time.Since(waitForAuthorizationReviewsStart)),
			)

			if acItemResult.err != nil {
				// Successful results are still expected to be returned even if multiple resources have errors
				// Replace ErrAuthorizationReviewTimeout with the actual error
				result.Errors[acItemResult.resource] = []error{acItemResult.err}
				continue
			}

			// Set the ManagedCluster field to the resource (managed cluster name)
			// Linseed uses the resourceGroup.ManagedCluster field to restrict namespace filters to the cluster set in
			// ManagedCluster (if unset, namespaces filters would apply to all managed clusters)
			for _, authorizedResourceVerb := range acItemResult.cacheItem.GetAuthorizedResourceVerbs() {
				for i := range authorizedResourceVerb.Verbs {
					for j := range authorizedResourceVerb.Verbs[i].ResourceGroups {
						authorizedResourceVerb.Verbs[i].ResourceGroups[j].ManagedCluster = acItemResult.resource
					}
				}
				result.AuthorizedResourceVerbs = append(result.AuthorizedResourceVerbs, authorizedResourceVerb)
			}
			delete(result.Errors, acItemResult.resource)
		}
	}

	// Ensure AuthorizedResourceVerbs slice is not empty by setting it to a rule that authorizes no resources/resourceNames
	// because an empty or nil permissions slice is considered as no restrictions on namespaces (i.e. all namespaces are authorized)
	// see https://github.com/tigera/calico-private/blob/ed1b58bf24512b8c9d5c3326c8c5aee0ed6ca3ed/linseed/pkg/backend/legacy/logtools/query.go#L32
	if len(result.AuthorizedResourceVerbs) == 0 {
		result.AuthorizedResourceVerbs = []v3.AuthorizedResourceVerbs{{APIGroup: "projectcalico.org"}}
	}

	a.logger.DebugC(
		ctx,
		"GetAuthorizedResourceVerbs",
		logging.String("user", ctx.UserInfo().GetName()),
		logging.Any("errors", result.Errors),
		logging.Any("authorizedResourceVerbs", result.AuthorizedResourceVerbs),
	)

	return result, nil
}

func (a *rulesAuthorizer) getOrLoadAuthorizedResourceVerbs(
	ctx Context,
	cacheKey string,
	managedClusterName string,
) (*authorizedResourcesVerbsCacheEntry, error) {
	cacheItem, err := a.authorizedResourceVerbsCache.GetOrLoad(cacheKey, func() (*authorizedResourcesVerbsCacheEntry, error) {
		// GetOrLoad ensures a single authorizedResourcesVerbsCacheEntry is shared by all goroutines using the same cacheKey
		return newAuthorizedResourcesVerbsCacheEntry(ctx, a.logger, managedClusterName, a.cfg.AuthorizedVerbsCacheSoftTTL, a.cfg.AuthorizedVerbsCacheRevalidateTimeout, a.reviewer)
	})
	if err != nil {
		return nil, err
	}

	if cacheItem.isStale(a.cfg.AuthorizedVerbsCacheSoftTTL) {
		if err := cacheItem.Revalidate(ctx, a.logger, managedClusterName, a.cfg.AuthorizedVerbsCacheSoftTTL, a.cfg.AuthorizedVerbsCacheRevalidateTimeout); err != nil {
			// avoid returning error to ensure stale cacheItem is reused for authorization
			a.logger.WarnC(ctx, "AuthorizedResourceVerbs revalidation failed", logging.Error(err))
		}
	}

	return cacheItem, nil
}

// isPermitted checks if the apiGroup, verb, resource and resourceNames are contained within rules
// a nil resource parameter will match any rules[].resource except for the "cluster" value
func isPermitted(rules []authzv1.ResourceRule, apiGroup, verb string, resource *string, resourceNames []string) bool {

	return tdsslices.AnyMatch(rules, func(rule authzv1.ResourceRule) bool {
		return tdsslices.AnyMatch(rule.APIGroups, func(ruleAPIGroup string) bool {
			// Match rule.APIGroups against apiGroup and '*'
			return ruleAPIGroup == apiGroup || ruleAPIGroup == "*"
		}) && tdsslices.AnyMatch(rule.Verbs, func(ruleVerb string) bool {
			// Match rule.Verbs against verb and '*'
			return ruleVerb == verb || verb == "*"
		}) && tdsslices.AnyMatch(rule.ResourceNames, func(ruleResourceName string) bool {
			// Match rule.ResourceNames against resourceNames and '*'
			return ruleResourceName == "*" || tdsslices.Contains(resourceNames, ruleResourceName)
		}) && tdsslices.AnyMatch(rule.Resources, func(ruleResource string) bool {
			// Match rule.Resources against resource (if not nil) and '*'
			if ruleResource == "cluster" { // ignore "cluster" entries
				return false
			} else if resource == nil {
				return true // matched "any" resource
			}

			return ruleResource == "*" || ruleResource == *resource
		})
	})
}

// toAuthorizeCacheKey returns a cache key string based on userInfo
func toAuthorizeCacheKey(userInfo user.Info) string {
	return fmt.Sprintf("%+v", user.DefaultInfo{
		Name:   userInfo.GetName(),
		UID:    userInfo.GetUID(),
		Groups: userInfo.GetGroups(),
		Extra:  userInfo.GetExtra(),
	})
}

// toAuthorizeCacheKeyForResource returns a cache key string based on userInfo and resource
func toAuthorizeCacheKeyForResource(userInfo user.Info, resource string) string {
	return fmt.Sprintf("%s:%s", toAuthorizeCacheKey(userInfo), resource)
}
