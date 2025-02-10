package security

import (
	"context"
	"fmt"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	lmacache "github.com/projectcalico/calico/lma/pkg/cache"
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security/cache"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
)

type Authorizer interface {
	Authorize(ctx Context, apiGroup string, resourceName []string, resource *string) (bool, error)
}

type rulesAuthorizer struct {
	logger     logging.Logger
	namespace  string
	rulesCache cache.LoadingCache[string, []authzv1.ResourceRule]
}

func NewAuthorizer(
	ctx context.Context,
	logger logging.Logger,
	namespace string,
	cacheTTL time.Duration,
) (Authorizer, error) {

	if namespace == "" {
		namespace = "default"
	}

	authorizer := &rulesAuthorizer{
		logger:    logger,
		namespace: namespace,
	}

	expiringCache, err := lmacache.NewExpiring[string, []authzv1.ResourceRule](lmacache.ExpiringConfig{
		Context: ctx,
		Name:    "lma-access-authorizer",
		TTL:     cacheTTL,
	})
	if err != nil {
		return nil, err
	}

	authorizer.rulesCache = cache.NewLoadingCache(expiringCache)

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
		logging.Bool("authorized", authorized),
		logging.String("apiGroup", apiGroup),
		logging.String("namespace", a.namespace),
		logging.Stringp("resource", resource),
		logging.Strings("resourceNames", resourceNames),
	)

	return authorized, nil
}

func (a *rulesAuthorizer) loadRules(ctx Context) ([]authzv1.ResourceRule, error) {

	selfSubjectRulesReview, err := ctx.KubernetesClient().AuthorizationV1().SelfSubjectRulesReviews().Create(ctx, &authzv1.SelfSubjectRulesReview{
		Spec: authzv1.SelfSubjectRulesReviewSpec{
			Namespace: a.namespace,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return selfSubjectRulesReview.Status.ResourceRules, nil
}

// isPermitted check if the apiGroup, verb, resource and resourceNames are contained within rules
// a nil resource parameter will match any rules[].resource except for the "cluster" value
func isPermitted(rules []authzv1.ResourceRule, apiGroup, verb string, resource *string, resourceNames []string) bool {

	return slices.AnyMatch(rules, func(rule authzv1.ResourceRule) bool {
		return slices.AnyMatch(rule.APIGroups, func(ruleAPIGroup string) bool {
			// Match rule.APIGroups against apiGroup and '*'
			return ruleAPIGroup == apiGroup || ruleAPIGroup == "*"
		}) && slices.AnyMatch(rule.Verbs, func(ruleVerb string) bool {
			// Match rule.Verbs against verb and '*'
			return ruleVerb == verb || verb == "*"
		}) && slices.AnyMatch(rule.ResourceNames, func(ruleResourceName string) bool {
			// Match rule.ResourceNames against resourceNames and '*'
			return ruleResourceName == "*" || slices.Contains(resourceNames, ruleResourceName)
		}) && slices.AnyMatch(rule.Resources, func(ruleResource string) bool {
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
