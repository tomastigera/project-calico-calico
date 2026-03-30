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

// NewAlertExceptionStorage creates a new libcalico-based storage.Interface implementation for AlertException
func NewAlertExceptionStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.AlertException)
		return c.AlertExceptions().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.AlertException)
		return c.AlertExceptions().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.AlertExceptions().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.AlertExceptions().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.AlertExceptions().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.AlertExceptions().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return opts.LicenseMonitor.IsFeatureRestricted(features.AlertManagement)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.AlertException](),
		aapiListType:      reflect.TypeFor[v3.AlertExceptionList](),
		libCalicoType:     reflect.TypeFor[v3.AlertException](),
		libCalicoListType: reflect.TypeFor[v3.AlertExceptionList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "AlertException",
		converter:         AlertExceptionConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type AlertExceptionConverter struct {
}

func (gc AlertExceptionConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiAlertException := aapiObj.(*v3.AlertException)
	lcgAlertException := &v3.AlertException{}
	lcgAlertException.TypeMeta = aapiAlertException.TypeMeta
	lcgAlertException.Kind = v3.KindAlertException
	lcgAlertException.APIVersion = v3.GroupVersionCurrent
	lcgAlertException.ObjectMeta = aapiAlertException.ObjectMeta
	lcgAlertException.Spec = aapiAlertException.Spec
	lcgAlertException.Status = aapiAlertException.Status
	return lcgAlertException
}

func (gc AlertExceptionConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgAlertException := libcalicoObject.(*v3.AlertException)
	aapiAlertException := aapiObj.(*v3.AlertException)
	aapiAlertException.Spec = lcgAlertException.Spec
	aapiAlertException.Status = lcgAlertException.Status
	aapiAlertException.TypeMeta = lcgAlertException.TypeMeta
	aapiAlertException.ObjectMeta = lcgAlertException.ObjectMeta
}

func (gc AlertExceptionConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgAlertExceptionList := libcalicoListObject.(*v3.AlertExceptionList)
	aapiAlertExceptionList := aapiListObj.(*v3.AlertExceptionList)
	if libcalicoListObject == nil {
		aapiAlertExceptionList.Items = []v3.AlertException{}
		return
	}
	aapiAlertExceptionList.TypeMeta = lcgAlertExceptionList.TypeMeta
	aapiAlertExceptionList.ListMeta = lcgAlertExceptionList.ListMeta
	for _, item := range lcgAlertExceptionList.Items {
		aapiAlertException := v3.AlertException{}
		gc.convertToAAPI(&item, &aapiAlertException)
		if matched, err := pred.Matches(&aapiAlertException); err == nil && matched {
			aapiAlertExceptionList.Items = append(aapiAlertExceptionList.Items, aapiAlertException)
		}
	}
}
