package security

import (
	"context"

	"go.uber.org/zap"

	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	lmaauth "github.com/projectcalico/calico/lma/pkg/auth"
	"github.com/tigera/tds-apiserver/pkg/logging"
)

type AuthContext interface {
	context.Context
	ClusterID() string // Temporary cluster-id. TODO: Remove once linseed supports multi-cluster queries
	UserInfo() user.Info
	TenantNamespace() string
	IsResourcePermitted(logger logging.Logger, apiGroup, resource, resourceName string) (bool, error)
}

type userAuthContext struct {
	context.Context
	clusterID       string
	userInfo        user.Info
	rbacAuthorizer  lmaauth.RBACAuthorizer
	tenantNamespace string
}

func NewUserAuthContext(parent context.Context, userInfo user.Info, rbacAuthorizer lmaauth.RBACAuthorizer, tenantNamespace, clusterID string) AuthContext {
	if parent == nil {
		parent = context.Background()
	}

	return &userAuthContext{
		Context:         parent,
		clusterID:       clusterID,
		userInfo:        userInfo,
		rbacAuthorizer:  rbacAuthorizer,
		tenantNamespace: tenantNamespace,
	}
}

func (u *userAuthContext) UserInfo() user.Info {
	return u.userInfo
}

func (u *userAuthContext) TenantNamespace() string {
	return u.tenantNamespace
}

func (u *userAuthContext) ClusterID() string {
	return u.clusterID
}

func (u *userAuthContext) IsResourcePermitted(logger logging.Logger, apiGroup, resource, resourceName string) (bool, error) {
	authorized, err := u.rbacAuthorizer.Authorize(u.UserInfo(), &authzv1.ResourceAttributes{
		Name:      resourceName,
		Verb:      "get",
		Group:     apiGroup,
		Resource:  resource,
		Namespace: u.TenantNamespace(),
	}, nil)
	if err != nil {
		return false, err
	}

	if authorized {
		logger.DebugC(
			u,
			"user is authorized",
			zap.String("apiGroup", apiGroup),
			zap.String("resource", resource),
			zap.String("resourceName", resourceName),
			zap.String("namespace", u.tenantNamespace),
			zap.String("user", u.UserInfo().GetName()),
		)
	} else {
		logger.DebugC(
			u,
			"user is not authorized",
			zap.String("apiGroup", apiGroup),
			zap.String("resource", resource),
			zap.String("resourceName", resourceName),
			zap.String("namespace", u.tenantNamespace),
			zap.String("user", u.UserInfo().GetName()),
		)
	}
	return authorized, nil
}
