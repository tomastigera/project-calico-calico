package managedcluster

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// NewManagedClusterListWatcher returns an implementation of the ListWatch interface capable of being used to
// build an informer based on a controller-runtime client. Using the controller-runtime client allows us to build
// an Informer that works for both namespaced and cluster-scoped ManagedCluster resources regardless of whether
// it is a multi-tenant cluster or not.
func NewManagedClusterListWatcher(ctx context.Context, c ctrlclient.WithWatch, namespace string) *cache.ListWatch {
	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			list := &v3.ManagedClusterList{}
			err := c.List(ctx, list, &ctrlclient.ListOptions{Raw: &options, Namespace: namespace})
			return list, err
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			list := &v3.ManagedClusterList{}
			return c.Watch(ctx, list, &ctrlclient.ListOptions{Raw: &options, Namespace: namespace})
		},
	}
}
