package security

import (
	"sync"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"

	"github.com/projectcalico/calico/lma/pkg/auth"
)

// authorizedResourcesVerbsCacheEntry A cache entry containing v3.AuthorizedResourceVerbs associated by cache key with
// a user and a resource (managed cluster name)
type authorizedResourcesVerbsCacheEntry struct {
	// authorizedResourceVerbs contains a slice of AuthorizedResourceVerbs from AuthorizationReview status
	authorizedResourceVerbs []v3.AuthorizedResourceVerbs

	// revalidateAt controls the time to revalidate AuthorizedResourceVerbs
	revalidateAt time.Time

	// rwMutex contains a Mutex for reading/writing fields
	rwMutex sync.RWMutex

	// m contains a Goroutine mutex for loading AuthorizedResourceVerbs for this particular struct object
	m sync.Mutex
}

func newAuthorizedResourcesVerbsCacheEntry(ctx Context, logger logging.Logger, resource string, revalidateTTL, revalidateTimeout time.Duration) (*authorizedResourcesVerbsCacheEntry, error) {
	a := &authorizedResourcesVerbsCacheEntry{}
	if err := a.Revalidate(ctx, logger, resource, revalidateTTL, revalidateTimeout); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *authorizedResourcesVerbsCacheEntry) GetAuthorizedResourceVerbs() []v3.AuthorizedResourceVerbs {
	a.rwMutex.RLock()
	defer a.rwMutex.RUnlock()

	return a.authorizedResourceVerbs
}

func (a *authorizedResourcesVerbsCacheEntry) Revalidate(ctx Context, logger logging.Logger, resource string, revalidateTTL, revalidateTimeout time.Duration) error {
	ch := make(chan error, 1)
	// Load from AuthorizationReview
	go func(ctx Context, resource string, cacheItem *authorizedResourcesVerbsCacheEntry) {
		cacheItem.m.Lock() // ensure a single AuthorizationReview per authorizedResourcesVerbsCacheEntry
		defer cacheItem.m.Unlock()

		var err error
		// Check if authorizedResourceVerbs has just been updated by another goroutine successfully
		if cacheItem.isStale(revalidateTTL) {
			revalidateStart := time.Now()
			var authorizedResourceVerbs []v3.AuthorizedResourceVerbs
			authorizedResourceVerbs, err = getAuthorizedResourceVerbs(ctx, resource)
			logger.DebugC(ctx, "AuthorizationReview cache entry revalidated",
				logging.Any("authorizedResourceVerbs", authorizedResourceVerbs),
				logging.Error(err),
				logging.String("user", ctx.UserInfo().GetName()),
				logging.String("resource", resource),
				logging.Duration("elapsed", time.Since(revalidateStart)),
			)

			if err == nil {
				a.rwMutex.Lock()
				defer a.rwMutex.Unlock()

				a.revalidateAt = time.Now()
				a.authorizedResourceVerbs = nil
				for _, verbs := range authorizedResourceVerbs {
					verbs.Verbs = slices.FilterBy(verbs.Verbs, func(verb v3.AuthorizedResourceVerb) bool {
						return verb.Verb == "list"
					})

					if len(verbs.Verbs) > 0 {
						a.authorizedResourceVerbs = append(a.authorizedResourceVerbs, verbs)
					}
				}
			}
		}

		ch <- err
	}(ctx, resource, a)

	select {
	case err := <-ch:
		// cacheItem revalidated successfully or an error occurred
		return err
	case <-time.After(revalidateTimeout):
		// revalidateTimeout expired. Return a stale cacheItemResult.cacheItem (at the end of this method)
	}

	return nil
}

func (a *authorizedResourcesVerbsCacheEntry) isStale(TTL time.Duration) bool {
	a.rwMutex.RLock()
	defer a.rwMutex.RUnlock()

	return a.revalidateAt.Add(TTL).Before(time.Now())
}

func (a *authorizedResourcesVerbsCacheEntry) expireRevalidateAt() {
	a.rwMutex.Lock()
	defer a.rwMutex.Unlock()

	a.revalidateAt = time.Time{}
}

// getAuthorizedResourceVerbs perform AuthorizationReview on a resource
func getAuthorizedResourceVerbs(ctx Context, resource string) ([]v3.AuthorizedResourceVerbs, error) {
	clientSet, err := ctx.ClientSetFactory().NewClientSetForApplication(resource)
	if err != nil {
		return nil, err
	}

	return auth.PerformAuthorizationReviewWithContext(
		ctx,
		clientSet,
		[]v3.AuthorizationReviewResourceAttributes{
			{
				APIGroup:  "projectcalico.org",
				Resources: []string{"hostendpoints", "networksets", "globalnetworksets"},
				Verbs:     []string{"list"},
			}, {
				APIGroup:  "",
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
		},
	)
}
