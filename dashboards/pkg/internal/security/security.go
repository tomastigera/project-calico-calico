package security

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/lma/pkg/k8s"
)

type PermissionsResult struct {
	Errors                  map[string][]error
	AuthorizedResourceVerbs []v3.AuthorizedResourceVerbs
}

type Context interface {
	context.Context

	UserInfo() user.Info
	Authorization() string

	// IsAnyPermitted Verify whether the user has lma.tigera.io authorization for any resource
	IsAnyPermitted(apiGroup string, resourceNames []string) (bool, error)

	// IsResourcePermitted Verify whether the user has lma.tigera.io authorization for a particular resource
	IsResourcePermitted(apiGroup, resourceName, resource string) (bool, error)

	// GetPermissions Returns AuthorizedResourceVerbs permissions for namespaced RBAC
	GetPermissions(managedClusterNames []string) (PermissionsResult, error)

	// KubernetesClient Returns a client for the management cluster k8s API
	KubernetesClient() kubernetes.Interface

	// ClientSetFactory Returns a ClientSetFactory for managed cluster k8s API
	ClientSetFactory() k8s.ClientSetFactory

	// Groups Returns authorization token OIDC groups
	Groups() []string

	// Tenant returns the current tenant
	Tenant() string
}

type userAuthContext struct {
	context.Context
	userInfo         user.Info
	k8sClient        kubernetes.Interface
	authorizer       Authorizer
	authorization    string
	clientSetFactory k8s.ClientSetFactory
	groups           []string
	tenant           string
}

func NewUserAuthContext(
	parent context.Context,
	userInfo user.Info,
	authorizer Authorizer,
	k8sClient kubernetes.Interface,
	authorization string,
	clientSetFactory k8s.ClientSetFactory,
	tenant string,
	groups []string,
) Context {

	return &userAuthContext{
		groups:           groups,
		tenant:           tenant,
		Context:          parent,
		userInfo:         userInfo,
		k8sClient:        k8sClient,
		authorizer:       authorizer,
		authorization:    authorization,
		clientSetFactory: clientSetFactory,
	}
}

func (u *userAuthContext) UserInfo() user.Info {
	return u.userInfo
}

func (u *userAuthContext) KubernetesClient() kubernetes.Interface {
	return u.k8sClient
}

func (u *userAuthContext) ClientSetFactory() k8s.ClientSetFactory {
	return u.clientSetFactory
}

func (u *userAuthContext) Authorization() string {
	return u.authorization
}

func (u *userAuthContext) IsAnyPermitted(apiGroup string, resourceNames []string) (bool, error) {
	return u.authorizer.Authorize(u, apiGroup, resourceNames, nil)
}

func (u *userAuthContext) IsResourcePermitted(apiGroup, resourceName, resource string) (bool, error) {
	return u.authorizer.Authorize(u, apiGroup, []string{resourceName}, &resource)
}

func (u *userAuthContext) GetPermissions(managedClusterNames []string) (PermissionsResult, error) {
	return u.authorizer.GetAuthorizedResourceVerbs(u, managedClusterNames)
}

func (u *userAuthContext) Groups() []string {
	return u.groups
}

func (u *userAuthContext) Tenant() string {
	return u.tenant
}
