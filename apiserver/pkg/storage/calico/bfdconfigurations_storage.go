// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
)

// NewBFDConfigurationStorage creates a new libcalico-based storage.Interface implementation for BFDConfigurations
func NewBFDConfigurationStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.BFDConfiguration)
		return c.BFDConfigurations().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.BFDConfiguration)
		return c.BFDConfigurations().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.BFDConfigurations().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.BFDConfigurations().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.BFDConfigurations().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.BFDConfigurations().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return false
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.BFDConfiguration](),
		aapiListType:      reflect.TypeFor[v3.BFDConfigurationList](),
		libCalicoType:     reflect.TypeFor[v3.BFDConfiguration](),
		libCalicoListType: reflect.TypeFor[v3.BFDConfigurationList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "BFDConfiguration",
		converter:         BFDConfigurationConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type BFDConfigurationConverter struct{}

func (gc BFDConfigurationConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiBFDConfiguration := aapiObj.(*v3.BFDConfiguration)
	lcgBFDConfiguration := &v3.BFDConfiguration{}
	lcgBFDConfiguration.TypeMeta = aapiBFDConfiguration.TypeMeta
	lcgBFDConfiguration.ObjectMeta = aapiBFDConfiguration.ObjectMeta
	lcgBFDConfiguration.Kind = v3.KindBFDConfiguration
	lcgBFDConfiguration.APIVersion = v3.GroupVersionCurrent
	lcgBFDConfiguration.Spec = aapiBFDConfiguration.Spec
	return lcgBFDConfiguration
}

func (gc BFDConfigurationConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgBFDConfiguration := libcalicoObject.(*v3.BFDConfiguration)
	aapiBFDConfiguration := aapiObj.(*v3.BFDConfiguration)
	aapiBFDConfiguration.Spec = lcgBFDConfiguration.Spec
	aapiBFDConfiguration.TypeMeta = lcgBFDConfiguration.TypeMeta
	aapiBFDConfiguration.ObjectMeta = lcgBFDConfiguration.ObjectMeta
}

func (gc BFDConfigurationConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgBFDConfigurationList := libcalicoListObject.(*v3.BFDConfigurationList)
	aapiBFDConfigurationList := aapiListObj.(*v3.BFDConfigurationList)
	if libcalicoListObject == nil {
		aapiBFDConfigurationList.Items = []v3.BFDConfiguration{}
		return
	}
	aapiBFDConfigurationList.TypeMeta = lcgBFDConfigurationList.TypeMeta
	aapiBFDConfigurationList.ListMeta = lcgBFDConfigurationList.ListMeta
	for _, item := range lcgBFDConfigurationList.Items {
		aapiBFDConfiguration := v3.BFDConfiguration{}
		gc.convertToAAPI(&item, &aapiBFDConfiguration)
		if matched, err := pred.Matches(&aapiBFDConfiguration); err == nil && matched {
			aapiBFDConfigurationList.Items = append(aapiBFDConfigurationList.Items, aapiBFDConfiguration)
		}
	}
}
