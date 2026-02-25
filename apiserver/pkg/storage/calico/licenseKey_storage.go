// Copyright (c) 2017-2019 Tigera, Inc. All rights reserved.

package calico

import (
	"context"
	"reflect"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/apiserver/pkg/helpers"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
	licClient "github.com/projectcalico/calico/licensing/client"
)

// NewLicenseKeyStorage creates a new libcalico-based storage.Interface implementation for LicenseKeys
func NewLicenseKeyStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.LicenseKey)
		return c.LicenseKey().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.LicenseKey)
		return c.LicenseKey().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.LicenseKey().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.LicenseKey().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.LicenseKey().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.LicenseKey().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return false
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.LicenseKey](),
		aapiListType:      reflect.TypeFor[v3.LicenseKeyList](),
		libCalicoType:     reflect.TypeFor[v3.LicenseKey](),
		libCalicoListType: reflect.TypeFor[v3.LicenseKeyList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "LicenseKey",
		converter:         LicenseKeyConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type LicenseKeyConverter struct {
}

func (gc LicenseKeyConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiLicenseKey := aapiObj.(*v3.LicenseKey)
	lcgLicenseKey := &v3.LicenseKey{}
	lcgLicenseKey.TypeMeta = aapiLicenseKey.TypeMeta
	lcgLicenseKey.ObjectMeta = aapiLicenseKey.ObjectMeta
	lcgLicenseKey.Kind = v3.KindLicenseKey
	lcgLicenseKey.APIVersion = v3.GroupVersionCurrent
	lcgLicenseKey.Spec = aapiLicenseKey.Spec
	lcgLicenseKey.Status = aapiLicenseKey.Status
	return lcgLicenseKey
}

func (gc LicenseKeyConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgLicenseKey := libcalicoObject.(*v3.LicenseKey)
	aapiLicenseKey := aapiObj.(*v3.LicenseKey)
	aapiLicenseKey.Spec = lcgLicenseKey.Spec
	aapiLicenseKey.TypeMeta = lcgLicenseKey.TypeMeta
	aapiLicenseKey.ObjectMeta = lcgLicenseKey.ObjectMeta
	//Decode License information from datastore and return status
	licClaims, err := licClient.Decode(*lcgLicenseKey)
	if err == nil {
		if licClaims.Validate() != licClient.NoLicenseLoaded {
			aapiLicenseKey.Status = v3.LicenseKeyStatus{
				Expiry:   metav1.Time{Time: licClaims.Expiry.Time()},
				MaxNodes: *licClaims.Nodes,
				Package:  helpers.ConvertToPackageType(licClaims.Features),
				Features: helpers.ExpandFeatureNames(licClaims.Features)}
		}
	}
}

func (gc LicenseKeyConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgLicenseKeyList := libcalicoListObject.(*v3.LicenseKeyList)
	aapiLicenseKeyList := aapiListObj.(*v3.LicenseKeyList)
	if libcalicoListObject == nil {
		aapiLicenseKeyList.Items = []v3.LicenseKey{}
		return
	}
	aapiLicenseKeyList.TypeMeta = lcgLicenseKeyList.TypeMeta
	aapiLicenseKeyList.ListMeta = lcgLicenseKeyList.ListMeta
	for _, item := range lcgLicenseKeyList.Items {
		aapiLicenseKey := v3.LicenseKey{}
		gc.convertToAAPI(&item, &aapiLicenseKey)
		if matched, err := pred.Matches(&aapiLicenseKey); err == nil && matched {
			aapiLicenseKeyList.Items = append(aapiLicenseKeyList.Items, aapiLicenseKey)
		}
	}
}
