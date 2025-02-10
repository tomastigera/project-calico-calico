package fake

import (
	"github.com/tigera/calico-cloud/cc-dashboard-query-api/pkg/internal/security"
)

type fakeAuthorizer struct {
	authorized bool
}

func NewAuthorizer(authorized bool) security.Authorizer {
	return &fakeAuthorizer{authorized: authorized}
}

func (f *fakeAuthorizer) Authorize(
	ctx security.Context,
	apiGroup string,
	resourceNames []string,
	resource *string,
) (bool, error) {
	return f.authorized, nil
}
