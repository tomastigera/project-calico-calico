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

// NewGlobalReportTypeStorage creates a new libcalico-based storage.Interface implementation for GlobalReportTypes
func NewGlobalReportTypeStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalReportType)
		return c.GlobalReportTypes().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalReportType)
		return c.GlobalReportTypes().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.GlobalReportTypes().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.GlobalReportTypes().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalReportTypes().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalReportTypes().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return !opts.LicenseMonitor.GetFeatureStatus(features.ComplianceReports)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.GlobalReportType](),
		aapiListType:      reflect.TypeFor[v3.GlobalReportTypeList](),
		libCalicoType:     reflect.TypeFor[v3.GlobalReportType](),
		libCalicoListType: reflect.TypeFor[v3.GlobalReportTypeList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "GlobalReportType",
		converter:         GlobalReportTypeConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type GlobalReportTypeConverter struct {
}

func (gc GlobalReportTypeConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiGlobalReportType := aapiObj.(*v3.GlobalReportType)
	lcgGlobalReportType := &v3.GlobalReportType{}
	lcgGlobalReportType.TypeMeta = aapiGlobalReportType.TypeMeta
	lcgGlobalReportType.ObjectMeta = aapiGlobalReportType.ObjectMeta
	lcgGlobalReportType.Kind = v3.KindGlobalReportList
	lcgGlobalReportType.APIVersion = v3.GroupVersionCurrent
	lcgGlobalReportType.Spec = aapiGlobalReportType.Spec
	return lcgGlobalReportType
}

func (gc GlobalReportTypeConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgGlobalReportType := libcalicoObject.(*v3.GlobalReportType)
	aapiGlobalReportType := aapiObj.(*v3.GlobalReportType)
	aapiGlobalReportType.Spec = lcgGlobalReportType.Spec
	aapiGlobalReportType.TypeMeta = lcgGlobalReportType.TypeMeta
	aapiGlobalReportType.ObjectMeta = lcgGlobalReportType.ObjectMeta
}

func (gc GlobalReportTypeConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgGlobalReportTypeList := libcalicoListObject.(*v3.GlobalReportTypeList)
	aapiGlobalReportTypeList := aapiListObj.(*v3.GlobalReportTypeList)
	if libcalicoListObject == nil {
		aapiGlobalReportTypeList.Items = []v3.GlobalReportType{}
		return
	}
	aapiGlobalReportTypeList.TypeMeta = lcgGlobalReportTypeList.TypeMeta
	aapiGlobalReportTypeList.ListMeta = lcgGlobalReportTypeList.ListMeta
	for _, item := range lcgGlobalReportTypeList.Items {
		aapiGlobalReportType := v3.GlobalReportType{}
		gc.convertToAAPI(&item, &aapiGlobalReportType)
		if matched, err := pred.Matches(&aapiGlobalReportType); err == nil && matched {
			aapiGlobalReportTypeList.Items = append(aapiGlobalReportTypeList.Items, aapiGlobalReportType)
		}
	}
}
