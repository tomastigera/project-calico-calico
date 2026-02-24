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

// NewGlobalThreatFeedStorage creates a new libcalico-based storage.Interface implementation for GlobalThreatFeeds
func NewGlobalThreatFeedStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
	c := CreateClientFromConfig()
	createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalThreatFeed)
		return c.GlobalThreatFeeds().Create(ctx, res, oso)
	}
	updateFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
		oso := opts.(options.SetOptions)
		res := obj.(*v3.GlobalThreatFeed)
		return c.GlobalThreatFeeds().Update(ctx, res, oso)
	}
	getFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		ogo := opts.(options.GetOptions)
		return c.GlobalThreatFeeds().Get(ctx, name, ogo)
	}
	deleteFn := func(ctx context.Context, c clientv3.Interface, ns string, name string, opts clientOpts) (resourceObject, error) {
		odo := opts.(options.DeleteOptions)
		return c.GlobalThreatFeeds().Delete(ctx, name, odo)
	}
	listFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (resourceListObject, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalThreatFeeds().List(ctx, olo)
	}
	watchFn := func(ctx context.Context, c clientv3.Interface, opts clientOpts) (watch.Interface, error) {
		olo := opts.(options.ListOptions)
		return c.GlobalThreatFeeds().Watch(ctx, olo)
	}
	hasRestrictionsFn := func(obj resourceObject) bool {
		return !opts.LicenseMonitor.GetFeatureStatus(features.ThreatDefense)
	}
	// TODO(doublek): Inject codec, client for nicer testing.
	dryRunnableStorage := registry.DryRunnableStorage{Storage: &resourceStore{
		client:            c,
		codec:             opts.RESTOptions.StorageConfig.Codec,
		versioner:         APIObjectVersioner{},
		aapiType:          reflect.TypeFor[v3.GlobalThreatFeed](),
		aapiListType:      reflect.TypeFor[v3.GlobalThreatFeedList](),
		libCalicoType:     reflect.TypeFor[v3.GlobalThreatFeed](),
		libCalicoListType: reflect.TypeFor[v3.GlobalThreatFeedList](),
		isNamespaced:      false,
		create:            createFn,
		update:            updateFn,
		get:               getFn,
		delete:            deleteFn,
		list:              listFn,
		watch:             watchFn,
		resourceName:      "GlobalThreatFeed",
		converter:         GlobalThreatFeedConverter{},
		hasRestrictions:   hasRestrictionsFn,
	}, Codec: opts.RESTOptions.StorageConfig.Codec}
	return dryRunnableStorage, func() {}
}

type GlobalThreatFeedConverter struct {
}

func (gc GlobalThreatFeedConverter) convertToLibcalico(aapiObj runtime.Object) resourceObject {
	aapiGlobalThreatFeed := aapiObj.(*v3.GlobalThreatFeed)
	lcgGlobalThreatFeed := &v3.GlobalThreatFeed{}
	lcgGlobalThreatFeed.TypeMeta = aapiGlobalThreatFeed.TypeMeta
	lcgGlobalThreatFeed.ObjectMeta = aapiGlobalThreatFeed.ObjectMeta
	lcgGlobalThreatFeed.Kind = v3.KindGlobalThreatFeed
	lcgGlobalThreatFeed.APIVersion = v3.GroupVersionCurrent
	lcgGlobalThreatFeed.Spec = aapiGlobalThreatFeed.Spec
	lcgGlobalThreatFeed.Status = aapiGlobalThreatFeed.Status
	return lcgGlobalThreatFeed
}

func (gc GlobalThreatFeedConverter) convertToAAPI(libcalicoObject resourceObject, aapiObj runtime.Object) {
	lcgGlobalThreatFeed := libcalicoObject.(*v3.GlobalThreatFeed)
	aapiGlobalThreatFeed := aapiObj.(*v3.GlobalThreatFeed)
	aapiGlobalThreatFeed.Spec = lcgGlobalThreatFeed.Spec
	aapiGlobalThreatFeed.Status = lcgGlobalThreatFeed.Status
	aapiGlobalThreatFeed.TypeMeta = lcgGlobalThreatFeed.TypeMeta
	aapiGlobalThreatFeed.ObjectMeta = lcgGlobalThreatFeed.ObjectMeta
}

func (gc GlobalThreatFeedConverter) convertToAAPIList(libcalicoListObject resourceListObject, aapiListObj runtime.Object, pred storage.SelectionPredicate) {
	lcgGlobalThreatFeedList := libcalicoListObject.(*v3.GlobalThreatFeedList)
	aapiGlobalThreatFeedList := aapiListObj.(*v3.GlobalThreatFeedList)
	if libcalicoListObject == nil {
		aapiGlobalThreatFeedList.Items = []v3.GlobalThreatFeed{}
		return
	}
	aapiGlobalThreatFeedList.TypeMeta = lcgGlobalThreatFeedList.TypeMeta
	aapiGlobalThreatFeedList.ListMeta = lcgGlobalThreatFeedList.ListMeta
	for _, item := range lcgGlobalThreatFeedList.Items {
		aapiGlobalThreatFeed := v3.GlobalThreatFeed{}
		gc.convertToAAPI(&item, &aapiGlobalThreatFeed)
		if matched, err := pred.Matches(&aapiGlobalThreatFeed); err == nil && matched {
			aapiGlobalThreatFeedList.Items = append(aapiGlobalThreatFeedList.Items, aapiGlobalThreatFeed)
		}
	}
}
