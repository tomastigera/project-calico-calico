// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package auth

import (
	"fmt"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/projectcalico/calico/lma/pkg/cache"
)

const (
	TokenReviewCacheMaxTTL = 20 * time.Second
	AuthzCacheMaxTTL       = 20 * time.Second
)

type cachingAuthorizer struct {
	delegate RBACAuthorizer
	cache    cache.LoadingCache[string, bool]
}

func NewCachingAuthorizer(cache cache.Cache[string, bool], delegate RBACAuthorizer) RBACAuthorizer {
	return newCachingAuthorizer(cache, delegate)
}

func newCachingAuthorizer(backingCache cache.Cache[string, bool], delegate RBACAuthorizer) *cachingAuthorizer {
	return &cachingAuthorizer{
		delegate: delegate,
		cache:    cache.NewLoadingCache(backingCache),
	}
}

// Authorize caches the results of calls to the delegate RBACAuthorizer.Authorize in the case where `resources!=nil && nonResources==nil`.
//
// Concurrent requests for the same uncached key will all be forwarded to the delegate and the cache updated for each result. Ideally
// a single request would be forwarded and the result shared amongst the callers but this increases the complexity for a probable small
// gain, so we will avoid that complexity until production metrics tell us otherwise.
func (a *cachingAuthorizer) Authorize(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
	if resources == nil || nonResources != nil {
		return a.delegate.Authorize(usr, resources, nonResources)
	}

	key := toAuthorizeCacheKey(usr, resources)
	return a.cache.GetOrLoad(key, func() (bool, error) {
		return a.delegate.Authorize(usr, resources, nonResources)
	})
}

func toAuthorizeCacheKey(uer user.Info, resources *authzv1.ResourceAttributes) string {
	type key struct {
		userName   string
		userUID    string
		userGroups []string
		userExtra  map[string][]string
		attrs      authzv1.ResourceAttributes
	}

	return fmt.Sprintf("%+v", key{
		userName:   uer.GetName(),
		userUID:    uer.GetUID(),
		userGroups: uer.GetGroups(),
		userExtra:  uer.GetExtra(),
		attrs:      *resources,
	})
}
