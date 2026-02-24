// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package authorizationreview

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/rbac"
)

type REST struct {
	calculator rbac.Calculator
}

// EmptyObject returns an empty instance
func (r *REST) New() runtime.Object {
	return &v3.AuthorizationReview{}
}

func (r *REST) Destroy() {

}

// Takes the userinfo that the authn delegate has put into the context and returns it.
func (r *REST) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	in := obj.(*v3.AuthorizationReview)
	out := &v3.AuthorizationReview{
		TypeMeta:   in.TypeMeta,
		ObjectMeta: in.ObjectMeta,
		Spec:       in.Spec,
	}

	var userInfo user.Info

	if in.Spec.User != "" {
		// Extract user from spec
		userInfo = &user.DefaultInfo{
			Name:   in.Spec.User,
			UID:    in.Spec.UID,
			Groups: in.Spec.Groups,
		}
	} else {
		// Extract user info from the request context.
		var ok bool
		userInfo, ok = request.UserFrom(ctx)
		if !ok {
			return out, nil
		}
	}

	// Expand the request into a set of ResourceVerbs as input to the RBAC calculator.
	rvs := rbac.RequestToResourceVerbs(in.Spec.ResourceAttributes)

	// Calculate the set of permissions.
	results, err := r.calculator.CalculatePermissions(userInfo, rvs)
	if err != nil {
		return nil, err
	}

	// Transfer the results to the status.
	out.Status = rbac.PermissionsToStatus(results)

	return out, nil
}

func (r *REST) GetSingularName() string {
	return "authorizationreview"
}

func (r *REST) NamespaceScoped() bool {
	return false
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &v3.AuthorizationReviewList{}
}

// NewREST returns a RESTStorage object that will work against API services.
func NewREST(calculator rbac.Calculator) *REST {
	return &REST{calculator: calculator}
}
