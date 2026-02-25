// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

// NewUISettingsGroupStorage creates a new storage. Interface implementation for UISettingsGroups.
func NewUISettingsGroupStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.UISettingsGroup)
		return c.UISettingsGroups().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.UISettingsGroup)
		return c.UISettingsGroups().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.UISettingsGroups().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.UISettingsGroups().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.UISettingsGroups().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.UISettingsGroups().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return false
	}

	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.UISettingsGroup](),
		aapiListType:      reflect.TypeFor[v3.UISettingsGroupList](),
		libCalicoType:     reflect.TypeFor[v3.UISettingsGroup](),
		libCalicoListType: reflect.TypeFor[v3.UISettingsGroupList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "UISettingsGroup",
		converter:         UISettingsGroupConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type UISettingsGroupConverter struct {
}

func (gc UISettingsGroupConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiUISettingsGroup := aapiObj.(*v3.UISettingsGroup)
	lcgUISettingsGroup := &v3.UISettingsGroup{}
	lcgUISettingsGroup.TypeMeta = aapiUISettingsGroup.TypeMeta
	lcgUISettingsGroup.ObjectMeta = aapiUISettingsGroup.ObjectMeta
	lcgUISettingsGroup.Kind = v3.KindUISettingsGroup
	lcgUISettingsGroup.APIVersion = v3.GroupVersionCurrent
	lcgUISettingsGroup.Spec = aapiUISettingsGroup.Spec
	return lcgUISettingsGroup
}

func (gc UISettingsGroupConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgUISettingsGroup := libcalicoObject.(*v3.UISettingsGroup)
	aapiUISettingsGroup := aapiObj.(*v3.UISettingsGroup)
	aapiUISettingsGroup.Spec = lcgUISettingsGroup.Spec
	aapiUISettingsGroup.TypeMeta = lcgUISettingsGroup.TypeMeta
	aapiUISettingsGroup.ObjectMeta = lcgUISettingsGroup.ObjectMeta
}

func (gc UISettingsGroupConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgUISettingsGroupList := libcalicoListObject.(*v3.UISettingsGroupList)
	aapiUISettingsGroupList := aapiListObj.(*v3.UISettingsGroupList)
	if libcalicoListObject == nil {
		aapiUISettingsGroupList.Items = []v3.UISettingsGroup{}
		return
	}
	aapiUISettingsGroupList.TypeMeta = lcgUISettingsGroupList.TypeMeta
	aapiUISettingsGroupList.ListMeta = lcgUISettingsGroupList.ListMeta
	for _, item := range lcgUISettingsGroupList.Items {
		aapiUISettingsGroup := v3.UISettingsGroup{}
		gc.convertToAAPI(&item, &aapiUISettingsGroup)
		if matched, err := pred.Matches(&aapiUISettingsGroup); err == nil && matched {
			aapiUISettingsGroupList.Items = append(aapiUISettingsGroupList.Items, aapiUISettingsGroup)
		}
	}
}
