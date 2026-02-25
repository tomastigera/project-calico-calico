// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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

// NewGlobalAlertStorage creates a new libcalico-based storage.Interface implementation for GlobalAlerts
func NewGlobalAlertStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalAlert)

		return c.GlobalAlerts().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalAlert)
		return c.GlobalAlerts().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.GlobalAlerts().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.GlobalAlerts().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalAlerts().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalAlerts().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return !opts.LicenseMonitor.GetFeatureStatus(features.AlertManagement)
	}
	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.GlobalAlert](),
		aapiListType:      reflect.TypeFor[v3.GlobalAlertList](),
		libCalicoType:     reflect.TypeFor[v3.GlobalAlert](),
		libCalicoListType: reflect.TypeFor[v3.GlobalAlertList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "GlobalAlert",
		converter:         GlobalAlertConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type GlobalAlertConverter struct {
}

func (gc GlobalAlertConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiGlobalAlert := aapiObj.(*v3.GlobalAlert)
	lcgGlobalAlert := &v3.GlobalAlert{}
	lcgGlobalAlert.TypeMeta = aapiGlobalAlert.TypeMeta
	lcgGlobalAlert.Kind = v3.KindGlobalAlert
	lcgGlobalAlert.APIVersion = v3.GroupVersionCurrent
	lcgGlobalAlert.ObjectMeta = aapiGlobalAlert.ObjectMeta
	lcgGlobalAlert.Spec = aapiGlobalAlert.Spec
	lcgGlobalAlert.Status = aapiGlobalAlert.Status
	return lcgGlobalAlert
}

func (gc GlobalAlertConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgGlobalAlert := libcalicoObject.(*v3.GlobalAlert)
	aapiGlobalAlert := aapiObj.(*v3.GlobalAlert)
	aapiGlobalAlert.Spec = lcgGlobalAlert.Spec
	aapiGlobalAlert.Status = lcgGlobalAlert.Status
	aapiGlobalAlert.TypeMeta = lcgGlobalAlert.TypeMeta
	aapiGlobalAlert.ObjectMeta = lcgGlobalAlert.ObjectMeta
}

func (gc GlobalAlertConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgGlobalAlertList := libcalicoListObject.(*v3.GlobalAlertList)
	aapiGlobalAlertList := aapiListObj.(*v3.GlobalAlertList)
	if libcalicoListObject == nil {
		aapiGlobalAlertList.Items = []v3.GlobalAlert{}
		return
	}
	aapiGlobalAlertList.TypeMeta = lcgGlobalAlertList.TypeMeta
	aapiGlobalAlertList.ListMeta = lcgGlobalAlertList.ListMeta
	for _, item := range lcgGlobalAlertList.Items {
		aapiGlobalAlert := v3.GlobalAlert{}
		gc.convertToAAPI(&item, &aapiGlobalAlert)
		if matched, err := pred.Matches(&aapiGlobalAlert); err == nil && matched {
			aapiGlobalAlertList.Items = append(aapiGlobalAlertList.Items, aapiGlobalAlert)
		}
	}
}
