// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

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

// NewUISettingsStorage creates a new storage. Interface implementation for UISettings.
func NewUISettingsStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.UISettings)
		return c.UISettings().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.UISettings)
		return c.UISettings().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.UISettings().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.UISettings().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.UISettings().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.UISettings().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return false
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.UISettings](),
		aapiListType:      reflect.TypeFor[v3.UISettingsList](),
		libCalicoType:     reflect.TypeFor[v3.UISettings](),
		libCalicoListType: reflect.TypeFor[v3.UISettingsList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "UISettings",
		converter:         UISettingsConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type UISettingsConverter struct {
}

func (gc UISettingsConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiUISettings := aapiObj.(*v3.UISettings)
	lcgUISettings := &v3.UISettings{}
	lcgUISettings.TypeMeta = aapiUISettings.TypeMeta
	lcgUISettings.ObjectMeta = aapiUISettings.ObjectMeta
	lcgUISettings.Kind = v3.KindUISettings
	lcgUISettings.APIVersion = v3.GroupVersionCurrent
	lcgUISettings.Spec = aapiUISettings.Spec
	return lcgUISettings
}

func (gc UISettingsConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgUISettings := libcalicoObject.(*v3.UISettings)
	aapiUISettings := aapiObj.(*v3.UISettings)
	aapiUISettings.Spec = lcgUISettings.Spec
	aapiUISettings.TypeMeta = lcgUISettings.TypeMeta
	aapiUISettings.ObjectMeta = lcgUISettings.ObjectMeta
}

func (gc UISettingsConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgUISettingsList := libcalicoListObject.(*v3.UISettingsList)
	aapiUISettingsList := aapiListObj.(*v3.UISettingsList)
	if libcalicoListObject == nil {
		aapiUISettingsList.Items = []v3.UISettings{}
		return
	}
	aapiUISettingsList.TypeMeta = lcgUISettingsList.TypeMeta
	aapiUISettingsList.ListMeta = lcgUISettingsList.ListMeta
	for _, item := range lcgUISettingsList.Items {
		aapiUISettings := v3.UISettings{}
		gc.convertToAAPI(&item, &aapiUISettings)
		if matched, err := pred.Matches(&aapiUISettings); err == nil && matched {
			aapiUISettingsList.Items = append(aapiUISettingsList.Items, aapiUISettings)
		}
	}
}
