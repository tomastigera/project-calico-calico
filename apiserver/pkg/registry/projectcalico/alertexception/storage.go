// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package alertexception

import (
	"context"

	calico "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"

	"github.com/projectcalico/calico/apiserver/pkg/registry/projectcalico/server"
)

// rest implements a RESTStorage for API services against etcd
type REST struct {
	*registry.Store
}

// EmptyObject returns an empty instance
func EmptyObject() runtime.Object {
	return &calico.AlertException{}
}

// NewList returns a new shell of a binding list
func NewList() runtime.Object {
	return &calico.AlertException{}
}

// StatusREST implements the REST endpoint for changing the status of a deployment
type StatusREST struct {
	store *registry.Store
}

func (r *StatusREST) New() runtime.Object {
	return &calico.AlertException{}
}

func (r *StatusREST) Destroy() {
	r.store.Destroy()
}

// Get retrieves the object from the storage. It is required to support Patch.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, forceAllowCreate, options)
}

// NewREST returns a RESTStorage object that will work against API services.
func NewREST(scheme *runtime.Scheme, opts server.Options) (*REST, *StatusREST, error) {
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
		func() runtime.Object { return &calico.AlertException{} },
		func() runtime.Object { return &calico.AlertExceptionList{} },
		GetAttrs,
		nil,
		nil,
	)
	if err != nil {
		return nil, nil, err
	}
	store := &registry.Store{
		NewFunc:     func() runtime.Object { return &calico.AlertException{} },
		NewListFunc: func() runtime.Object { return &calico.AlertExceptionList{} },
		KeyRootFunc: opts.KeyRootFunc(false),
		KeyFunc:     opts.KeyFunc(false),
		ObjectNameFunc: func(obj runtime.Object) (string, error) {
			return obj.(*calico.AlertException).Name, nil
		},
		PredicateFunc:            MatchAlertException,
		DefaultQualifiedResource: calico.Resource("alertexceptions"),

		CreateStrategy:          strategy,
		UpdateStrategy:          strategy,
		DeleteStrategy:          strategy,
		EnableGarbageCollection: true,

		Storage:     storageInterface,
		DestroyFunc: dFunc,
	}

	statusStore := *store
	statusStore.UpdateStrategy = NewStatusStrategy(strategy)

	return &REST{store}, &StatusREST{&statusStore}, nil
}
