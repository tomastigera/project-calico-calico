// Copyright (c) 2022 Tigera, Inc. All rights reserved.

package calico

import (
	"context"
	"reflect"

	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/storagebackend/factory"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NewExternalNetworkStorage creates a new libcalico-based storage.Interface implementation for ExternalNetwork
func NewExternalNetworkStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.ExternalNetwork)
		return c.ExternalNetworks().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*api.ExternalNetwork)
		return c.ExternalNetworks().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.ExternalNetworks().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.ExternalNetworks().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.ExternalNetworks().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.ExternalNetworks().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return false
	}

	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[api.ExternalNetwork](),
		aapiListType:      reflect.TypeFor[api.ExternalNetworkList](),
		libCalicoType:     reflect.TypeFor[api.ExternalNetwork](),
		libCalicoListType: reflect.TypeFor[api.ExternalNetworkList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "ExternalNetwork",
		converter:         ExternalNetworkConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type ExternalNetworkConverter struct {
}

func (gc ExternalNetworkConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiExternalNetwork := aapiObj.(*api.ExternalNetwork)
	lcgExternalNetwork := &api.ExternalNetwork{}
	lcgExternalNetwork.TypeMeta = aapiExternalNetwork.TypeMeta
	lcgExternalNetwork.ObjectMeta = aapiExternalNetwork.ObjectMeta
	lcgExternalNetwork.Kind = api.KindExternalNetwork
	lcgExternalNetwork.APIVersion = api.GroupVersionCurrent
	lcgExternalNetwork.Spec = aapiExternalNetwork.Spec
	return lcgExternalNetwork
}

func (gc ExternalNetworkConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgExternalNetwork := libcalicoObject.(*api.ExternalNetwork)
	aapiExternalNetwork := aapiObj.(*api.ExternalNetwork)
	aapiExternalNetwork.Spec = lcgExternalNetwork.Spec
	aapiExternalNetwork.TypeMeta = lcgExternalNetwork.TypeMeta
	aapiExternalNetwork.ObjectMeta = lcgExternalNetwork.ObjectMeta
}

func (gc ExternalNetworkConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgExternalNetworkList := libcalicoListObject.(*api.ExternalNetworkList)
	aapiExternalNetworkList := aapiListObj.(*api.ExternalNetworkList)
	if libcalicoListObject == nil {
		aapiExternalNetworkList.Items = []api.ExternalNetwork{}
		return
	}
	aapiExternalNetworkList.TypeMeta = lcgExternalNetworkList.TypeMeta
	aapiExternalNetworkList.ListMeta = lcgExternalNetworkList.ListMeta
	for _, item := range lcgExternalNetworkList.Items {
		aapiExternalNetwork := api.ExternalNetwork{}
		gc.convertToAAPI(&item, &aapiExternalNetwork)
		if matched, err := pred.Matches(&aapiExternalNetwork); err == nil && matched {
			aapiExternalNetworkList.Items = append(aapiExternalNetworkList.Items, aapiExternalNetwork)
		}
	}
}
