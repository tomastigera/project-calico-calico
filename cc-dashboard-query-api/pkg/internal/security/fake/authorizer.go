package fake

import (
	"reflect"

	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
	"github.com/tigera/tds-apiserver/lib/slices"
)

type MatchingResource struct {
	APIGroup      string
	ResourceNames []string
	Resource      *string
}

type fakeAuthorizer struct {
	authorized        bool
	matchingResources []MatchingResource
}

func NewAuthorizer(authorized bool) security.Authorizer {
	return &fakeAuthorizer{authorized: authorized}
}

func NewAuthorizerForMatchingResources(matchingResources []MatchingResource) security.Authorizer {
	return &fakeAuthorizer{authorized: false, matchingResources: matchingResources}
}

func (f *fakeAuthorizer) Authorize(
	ctx security.Context,
	apiGroup string,
	resourceNames []string,
	resource *string,
) (bool, error) {

	for _, matchingResource := range f.matchingResources {
		if matchingResource.APIGroup == apiGroup &&
			slices.Equal(matchingResource.ResourceNames, resourceNames) &&
			reflect.DeepEqual(resource, matchingResource.Resource) {
			return true, nil
		}
	}

	return f.authorized, nil
}
