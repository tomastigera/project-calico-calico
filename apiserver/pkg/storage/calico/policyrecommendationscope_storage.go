// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package calico

import (
	"context"
	"reflect"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	features "github.com/projectcalico/calico/licensing/client/features"
)

// NewPolicyRecommendationScopeStorage creates a new libcalico-based storage.Interface implementation for PolicyRecommendationScopes
func NewPolicyRecommendationScopeStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.PolicyRecommendationScope)

		return c.PolicyRecommendationScopes().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.PolicyRecommendationScope)
		return c.PolicyRecommendationScopes().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.PolicyRecommendationScopes().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.PolicyRecommendationScopes().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.PolicyRecommendationScopes().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.PolicyRecommendationScopes().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return !opts.LicenseMonitor.GetFeatureStatus(features.PolicyRecommendation)
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.PolicyRecommendationScope](),
		aapiListType:      reflect.TypeFor[v3.PolicyRecommendationScopeList](),
		libCalicoType:     reflect.TypeFor[v3.PolicyRecommendationScope](),
		libCalicoListType: reflect.TypeFor[v3.PolicyRecommendationScopeList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "PolicyRecommendationScope",
		converter:         PolicyRecommendationScopeConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type PolicyRecommendationScopeConverter struct {
}

func (gc PolicyRecommendationScopeConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiPolicyRecommendationScope := aapiObj.(*v3.PolicyRecommendationScope)
	lcgPolicyRecommendationScope := &v3.PolicyRecommendationScope{}
	lcgPolicyRecommendationScope.TypeMeta = aapiPolicyRecommendationScope.TypeMeta
	lcgPolicyRecommendationScope.Kind = v3.KindPolicyRecommendationScope
	lcgPolicyRecommendationScope.APIVersion = v3.GroupVersionCurrent
	lcgPolicyRecommendationScope.ObjectMeta = aapiPolicyRecommendationScope.ObjectMeta
	lcgPolicyRecommendationScope.Spec = aapiPolicyRecommendationScope.Spec
	lcgPolicyRecommendationScope.Status = aapiPolicyRecommendationScope.Status
	return lcgPolicyRecommendationScope
}

func (gc PolicyRecommendationScopeConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgPolicyRecommendationScope := libcalicoObject.(*v3.PolicyRecommendationScope)
	aapiPolicyRecommendationScope := aapiObj.(*v3.PolicyRecommendationScope)
	aapiPolicyRecommendationScope.Spec = lcgPolicyRecommendationScope.Spec
	aapiPolicyRecommendationScope.Status = lcgPolicyRecommendationScope.Status
	aapiPolicyRecommendationScope.TypeMeta = lcgPolicyRecommendationScope.TypeMeta
	aapiPolicyRecommendationScope.ObjectMeta = lcgPolicyRecommendationScope.ObjectMeta
}

func (gc PolicyRecommendationScopeConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgPolicyRecommendationScopeList := libcalicoListObject.(*v3.PolicyRecommendationScopeList)
	aapiPolicyRecommendationScopeList := aapiListObj.(*v3.PolicyRecommendationScopeList)
	if libcalicoListObject == nil {
		aapiPolicyRecommendationScopeList.Items = []v3.PolicyRecommendationScope{}
		return
	}
	aapiPolicyRecommendationScopeList.TypeMeta = lcgPolicyRecommendationScopeList.TypeMeta
	aapiPolicyRecommendationScopeList.ListMeta = lcgPolicyRecommendationScopeList.ListMeta
	for _, item := range lcgPolicyRecommendationScopeList.Items {
		aapiPolicyRecommendationScope := v3.PolicyRecommendationScope{}
		gc.convertToAAPI(&item, &aapiPolicyRecommendationScope)
		if matched, err := pred.Matches(&aapiPolicyRecommendationScope); err == nil && matched {
			aapiPolicyRecommendationScopeList.Items = append(aapiPolicyRecommendationScopeList.Items, aapiPolicyRecommendationScope)
		}
	}
}
