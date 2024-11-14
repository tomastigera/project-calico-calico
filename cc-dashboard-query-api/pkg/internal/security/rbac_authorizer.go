package security

import (
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
)

type RBACAuthorizerFunc func(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error)

var _ lmaauth.RBACAuthorizer = RBACAuthorizerFunc(func(user.Info, *authzv1.ResourceAttributes, *authzv1.NonResourceAttributes) (bool, error) {
	return false, nil
})

func (f RBACAuthorizerFunc) Authorize(usr user.Info, resources *authzv1.ResourceAttributes, nonResources *authzv1.NonResourceAttributes) (bool, error) {
	return f(usr, resources, nonResources)
}
