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
	"github.com/projectcalico/calico/licensing/client/features"
)

// NewGlobalReportStorage creates a new libcalico-based storage.Interface implementation for GlobalReports
func NewGlobalReportStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalReport)
		return c.GlobalReports().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalReport)
		return c.GlobalReports().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.GlobalReports().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.GlobalReports().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalReports().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalReports().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return !opts.LicenseMonitor.GetFeatureStatus(features.ComplianceReports)
	}
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.GlobalReport](),
		aapiListType:      reflect.TypeFor[v3.GlobalReportList](),
		libCalicoType:     reflect.TypeFor[v3.GlobalReport](),
		libCalicoListType: reflect.TypeFor[v3.GlobalReportList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "GlobalReport",
		converter:         GlobalReportConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type GlobalReportConverter struct {
}

func (gc GlobalReportConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiGlobalReport := aapiObj.(*v3.GlobalReport)
	lcgGlobalReport := &v3.GlobalReport{}
	lcgGlobalReport.TypeMeta = aapiGlobalReport.TypeMeta
	lcgGlobalReport.ObjectMeta = aapiGlobalReport.ObjectMeta
	lcgGlobalReport.Kind = v3.KindGlobalReport
	lcgGlobalReport.APIVersion = v3.GroupVersionCurrent
	lcgGlobalReport.Spec = aapiGlobalReport.Spec
	lcgGlobalReport.Status = aapiGlobalReport.Status
	return lcgGlobalReport
}

func (gc GlobalReportConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgGlobalReport := libcalicoObject.(*v3.GlobalReport)
	aapiGlobalReport := aapiObj.(*v3.GlobalReport)
	aapiGlobalReport.Spec = lcgGlobalReport.Spec
	aapiGlobalReport.Status = lcgGlobalReport.Status
	aapiGlobalReport.TypeMeta = lcgGlobalReport.TypeMeta
	aapiGlobalReport.ObjectMeta = lcgGlobalReport.ObjectMeta
}

func (gc GlobalReportConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgGlobalReportList := libcalicoListObject.(*v3.GlobalReportList)
	aapiGlobalReportList := aapiListObj.(*v3.GlobalReportList)
	if libcalicoListObject == nil {
		aapiGlobalReportList.Items = []v3.GlobalReport{}
		return
	}
	aapiGlobalReportList.TypeMeta = lcgGlobalReportList.TypeMeta
	aapiGlobalReportList.ListMeta = lcgGlobalReportList.ListMeta
	for _, item := range lcgGlobalReportList.Items {
		aapiGlobalReport := v3.GlobalReport{}
		gc.convertToAAPI(&item, &aapiGlobalReport)
		if matched, err := pred.Matches(&aapiGlobalReport); err == nil && matched {
			aapiGlobalReportList.Items = append(aapiGlobalReportList.Items, aapiGlobalReport)
		}
	}
}
