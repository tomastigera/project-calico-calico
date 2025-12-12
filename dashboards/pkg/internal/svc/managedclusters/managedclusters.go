package managedclusters

import (
	"context"
	"fmt"
	"time"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/tds-apiserver/lib/logging"
	"github.com/tigera/tds-apiserver/lib/slices"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/dashboards/pkg/internal/domain/query"
)

type NameLister interface {
	List(ctx context.Context) ([]query.ManagedClusterName, error)
}

type NameListerFunc func(ctx context.Context) ([]query.ManagedClusterName, error)

type nameLister struct {
	logger               logging.Logger
	managedClusterLister cache.GenericLister
}

func NewNameLister(ctx context.Context, logger logging.Logger, dynamicClient dynamic.Interface, tenantNamespace string) (NameLister, error) {

	// Note: github.com/tigera/api/pkg/client/informers_generated/externalversions's
	// NewSharedInformerFactoryWithOptions did not work on multi-tenant clusters

	informerFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, time.Hour, tenantNamespace, nil)
	// Improvement: WithTransform could be used to minimize memory usage
	// see https://pkg.go.dev/k8s.io/client-go@v0.34.1/tools/cache#TransformFunc

	managedClusterInformer := informerFactory.ForResource(v3.SchemeGroupVersion.WithResource("managedclusters"))

	informerFactory.Start(ctx.Done())
	informerFactory.WaitForCacheSync(ctx.Done())

	return &nameLister{
		logger:               logger,
		managedClusterLister: managedClusterInformer.Lister(),
	}, nil
}

func (n *nameLister) List(ctx context.Context) ([]query.ManagedClusterName, error) {
	managedClusters, err := n.managedClusterLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	return slices.MapOrError(managedClusters, func(object runtime.Object) (query.ManagedClusterName, error) {
		if managedCluster, ok := object.(*unstructured.Unstructured); ok {
			return query.ManagedClusterName(managedCluster.GetName()), nil
		}
		n.logger.ErrorC(ctx, "failed to list managed cluster", logging.Any("object", object))
		return "", fmt.Errorf("failed to list managed clusters")
	})
}

func (n NameListerFunc) List(ctx context.Context) ([]query.ManagedClusterName, error) {
	return n(ctx)
}
