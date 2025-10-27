package managedcluster

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

type MockClientWithWatch struct {
	rest.RESTClient
}

type MockRestMapper struct{}

var Clusters = map[string]*v3.ManagedCluster{
	"test-cluster": {
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "default",
		},
		Status: v3.ManagedClusterStatus{
			Conditions: []v3.ManagedClusterStatusCondition{
				{
					Type:   v3.ManagedClusterStatusTypeConnected,
					Status: v3.ManagedClusterStatusValueTrue,
				},
			},
		},
	},
	"WAF-test-cluster": {
		ObjectMeta: v1.ObjectMeta{
			Name:      "WAF-test-cluster",
			Namespace: "default",
		},
		Status: v3.ManagedClusterStatus{
			Conditions: []v3.ManagedClusterStatusCondition{
				{
					Type:   v3.ManagedClusterStatusTypeConnected,
					Status: v3.ManagedClusterStatusValueTrue,
				},
			},
		},
	},
	"test-cluster-2": {
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster-2",
			Namespace: "default",
		},
		Status: v3.ManagedClusterStatus{
			Conditions: []v3.ManagedClusterStatusCondition{
				{
					Type:   v3.ManagedClusterStatusTypeConnected,
					Status: v3.ManagedClusterStatusValueTrue,
				},
			},
		},
	},
	"WAF-test-cluster-2": {
		ObjectMeta: v1.ObjectMeta{
			Name:      "WAF-test-cluster-2",
			Namespace: "default",
		},
		Status: v3.ManagedClusterStatus{
			Conditions: []v3.ManagedClusterStatusCondition{
				{
					Type:   v3.ManagedClusterStatusTypeConnected,
					Status: v3.ManagedClusterStatusValueTrue,
				},
			},
		},
	},
}

func (MockClientWithWatch) Get(c context.Context, ns types.NamespacedName, client client.Object, options ...client.GetOption) error {
	cluster := Clusters[ns.Name]
	var clusterClient *v3.ManagedCluster
	clusterClient, ok := client.(*v3.ManagedCluster)
	if !ok {
		panic("not ok")
	}
	*clusterClient = *cluster
	return nil
}

func (MockClientWithWatch) Create(context.Context, client.Object, ...client.CreateOption) error {
	return nil
}

func (MockClientWithWatch) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return nil
}

func (MockClientWithWatch) Patch(context.Context, client.Object, client.Patch, ...client.PatchOption) error {
	return nil
}

func (MockClientWithWatch) Apply(context.Context, runtime.ApplyConfiguration, ...client.ApplyOption) error {
	return nil
}

func (MockClientWithWatch) Update(context.Context, client.Object, ...client.UpdateOption) error {
	return nil
}

func (MockClientWithWatch) Watch(context.Context, client.ObjectList, ...client.ListOption) (watch.Interface, error) {
	return MockWatchInterface{}, nil
}

func (MockClientWithWatch) Status() client.SubResourceWriter {
	return nil
}

func (MockClientWithWatch) SubResource(string) client.SubResourceClient {
	return nil
}

func (MockClientWithWatch) Delete(context.Context, client.Object, ...client.DeleteOption) error {
	return nil
}

func (MockClientWithWatch) DeleteAllOf(context.Context, client.Object, ...client.DeleteAllOfOption) error {
	return nil
}

// Scheme returns the scheme this client is using.
func (MockClientWithWatch) Scheme() *runtime.Scheme {
	return &runtime.Scheme{}
}

func (MockClientWithWatch) RESTMapper() meta.RESTMapper {
	return MockRestMapper{}
}

func (MockClientWithWatch) GroupVersionKindFor(obj runtime.Object) (schema.GroupVersionKind, error) {
	return schema.GroupVersionKind{}, nil
}

func (MockClientWithWatch) IsObjectNamespaced(obj runtime.Object) (bool, error) {
	return false, nil
}

type MockWatchInterface struct{}

func (MockWatchInterface) Stop() {}

// ResultChan returns a chan which will receive all the events. If an error occurs
// or Stop() is called, the implementation will close this channel and
// release any resources used by the watch.
func (MockWatchInterface) ResultChan() <-chan watch.Event {
	return make(<-chan watch.Event)
}

// KindFor takes a partial resource and returns the single match.  Returns an error if there are multiple matches
func (MockRestMapper) KindFor(resource schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	return schema.GroupVersionKind{}, nil
}

// KindsFor takes a partial resource and returns the list of potential kinds in priority order
func (MockRestMapper) KindsFor(resource schema.GroupVersionResource) ([]schema.GroupVersionKind, error) {
	return []schema.GroupVersionKind{}, nil
}

// ResourceFor takes a partial resource and returns the single match.  Returns an error if there are multiple matches
func (MockRestMapper) ResourceFor(input schema.GroupVersionResource) (schema.GroupVersionResource, error) {
	return schema.GroupVersionResource{}, nil
}

// ResourcesFor takes a partial resource and returns the list of potential resource in priority order
func (MockRestMapper) ResourcesFor(input schema.GroupVersionResource) ([]schema.GroupVersionResource, error) {
	return []schema.GroupVersionResource{}, nil
}

// RESTMapping identifies a preferred resource mapping for the provided group kind.
func (MockRestMapper) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	return &meta.RESTMapping{}, nil
}

// RESTMappings returns all resource mappings for the provided group kind if no
// version search is provided. Otherwise identifies a preferred resource mapping for
// the provided version(s).
func (MockRestMapper) RESTMappings(gk schema.GroupKind, versions ...string) ([]*meta.RESTMapping, error) {
	return []*meta.RESTMapping{}, nil
}

func (MockRestMapper) ResourceSingularizer(resource string) (singular string, err error) {
	return "", nil
}
