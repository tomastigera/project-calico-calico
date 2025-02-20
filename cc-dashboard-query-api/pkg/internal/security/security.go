package security

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
)

type Context interface {
	context.Context
	UserInfo() user.Info

	KubernetesClient() kubernetes.Interface
	IsAnyPermitted(apiGroup string, resourceNames []string) (bool, error)
	IsResourcePermitted(apiGroup, resourceName, resource string) (bool, error)
}

type userAuthContext struct {
	context.Context
	clusterID  string
	userInfo   user.Info
	k8sClient  kubernetes.Interface
	authorizer Authorizer
}

func NewUserAuthContext(
	parent context.Context,
	userInfo user.Info,
	authorizer Authorizer,
	k8sClient kubernetes.Interface,
) Context {

	return &userAuthContext{
		Context:    parent,
		userInfo:   userInfo,
		k8sClient:  k8sClient,
		authorizer: authorizer,
	}
}

func (u *userAuthContext) UserInfo() user.Info {
	return u.userInfo
}

func (u *userAuthContext) KubernetesClient() kubernetes.Interface {
	return u.k8sClient
}

func (u *userAuthContext) IsAnyPermitted(apiGroup string, resourceNames []string) (bool, error) {
	return u.authorizer.Authorize(u, apiGroup, resourceNames, nil)
}

func (u *userAuthContext) IsResourcePermitted(apiGroup, resourceName, resource string) (bool, error) {
	return u.authorizer.Authorize(u, apiGroup, []string{resourceName}, &resource)
}
