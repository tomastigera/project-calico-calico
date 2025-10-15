// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package egressgatewaypolicy

import (
	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
)

// REST implements a RESTStorage for API services against etcd
type REST struct {
	*registry.Store
	shortNames []string
}

func (r *REST) ShortNames() []string {
	return r.shortNames
}

func (r *REST) Categories() []string {
	return []string{""}
}

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &calico.EgressGatewayPolicy{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.EgressGatewayPolicyList{}
}

// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, opts server.Options) (*REST, error) {
	strategy := NewStrategy(scheme)

	prefix := "/" + opts.ResourcePrefix()
	// We adapt the store's keyFunc so that we can use it with the StorageDecorator
	// without making any assumptions about where objects are stored in etcd
	keyFunc := func(obj runtime.Object) (string, error) {
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return "", err
		}
		return registry.NoNamespaceKeyFunc(
			genericapirequest.NewContext(),
			prefix,
			accessor.GetName(),
		)
	}
	storageInterface, dFunc, err := opts.GetStorage(
		prefix,
		keyFunc,
		strategy,
		func() runtime.Object { return &calico.EgressGatewayPolicy{} },
		func() runtime.Object { return &calico.EgressGatewayPolicyList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &calico.EgressGatewayPolicy{} },
		NewListFunc: func() runtime.Object { return &calico.EgressGatewayPolicyList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.EgressGatewayPolicy).Name, nil
		},
		PredicateFunc:            MatchEgressGatewayPolicy,
		DefaultQualifiedResource: calico.Resource("egressgatewaypolicies"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	return &REST{store, opts.ShortNames}, nil
}
