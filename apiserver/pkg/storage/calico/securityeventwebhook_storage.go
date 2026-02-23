// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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

// NewSecurityEventWebhookStorage creates a new libcalico-based storage.Interface implementation for SecurityEventWebhooks
func NewSecurityEventWebhookStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.SecurityEventWebhook)
		return c.SecurityEventWebhook().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.SecurityEventWebhook)
		return c.SecurityEventWebhook().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.SecurityEventWebhook().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.SecurityEventWebhook().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.SecurityEventWebhook().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.SecurityEventWebhook().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return !opts.LicenseMonitor.GetFeatureStatus(features.AlertManagement)
	}
	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.SecurityEventWebhook](),
		aapiListType:      reflect.TypeFor[v3.SecurityEventWebhookList](),
		libCalicoType:     reflect.TypeFor[v3.SecurityEventWebhook](),
		libCalicoListType: reflect.TypeFor[v3.SecurityEventWebhookList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "SecurityEventWebhook",
		converter:         SecurityEventWebhookConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type SecurityEventWebhookConverter struct {
}

func (gc SecurityEventWebhookConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapi := aapiObj.(*v3.SecurityEventWebhook)
	lcg := &v3.SecurityEventWebhook{}
	lcg.TypeMeta = aapi.TypeMeta
	lcg.Kind = v3.KindSecurityEventWebhook
	lcg.APIVersion = v3.GroupVersionCurrent
	lcg.ObjectMeta = aapi.ObjectMeta
	lcg.Spec = aapi.Spec
	lcg.Status = aapi.Status
	return lcg
}

func (gc SecurityEventWebhookConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcg := libcalicoObject.(*v3.SecurityEventWebhook)
	aapi := aapiObj.(*v3.SecurityEventWebhook)
	aapi.Spec = lcg.Spec
	aapi.Status = lcg.Status
	aapi.TypeMeta = lcg.TypeMeta
	aapi.ObjectMeta = lcg.ObjectMeta
}

func (gc SecurityEventWebhookConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgList := libcalicoListObject.(*v3.SecurityEventWebhookList)
	aapiList := aapiListObj.(*v3.SecurityEventWebhookList)
	if libcalicoListObject == nil {
		aapiList.Items = []v3.SecurityEventWebhook{}
		return
	}
	aapiList.TypeMeta = lcgList.TypeMeta
	aapiList.ListMeta = lcgList.ListMeta
	for _, item := range lcgList.Items {
		aapi := v3.SecurityEventWebhook{}
		gc.convertToAAPI(&item, &aapi)
		if matched, err := pred.Matches(&aapi); err == nil && matched {
			aapiList.Items = append(aapiList.Items, aapi)
		}
	}
}
