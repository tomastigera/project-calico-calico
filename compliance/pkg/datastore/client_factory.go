package datastore

import (
	"net/http"
	"sync"

	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/calico/lma/pkg/auth"
	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

// ClusterCtxK8sClientFactory is a factory that creates various k8s clients that communicate with specific clusters. The
// create methods for the clients require a cluster id which is used to create a client that communicates with the cluster
// identified by that id.
type ClusterCtxK8sClientFactory interface {
	RestConfigForCluster(clusterID string) *rest.Config
	ClientSetForCluster(clusterID string) (ClientSet, error)
	RBACAuthorizerForCluster(clusterId string) (auth.RBACAuthorizer, error)
	Impersonate(user *user.DefaultInfo) ClusterCtxK8sClientFactory
}

// clientSetFactory is an implementation of the ClusterCtxK8sClientFactory interface that creates clients that send their
// requests to a proxy (as specified by multiClusterForwardingEndpoint) that accepts the "x-cluster-id" header to route
// requests to the appropriate cluster.
//
// Note that this factory does not cache the clients. The reasoning behind this is that it is not clear how many clusters
// will be connect and how long these clusters will live for, and without extra logic there is no way to clean out the outdated
// clients for clusters that no longer exist. The responsibility of whether a client is held is is the responsibility of
// the caller, who is expected to hold the client and not create request a new client from this factory if they want a long
// lived client.
type clientSetFactory struct {
	sync.Mutex
	baseRestConfig                 *rest.Config
	multiClusterForwardingCA       string
	multiClusterForwardingEndpoint string
}

// NewClusterCtxK8sClientFactory creates an implementation of the ClusterCtxK8sClientFactory whose created clients use a proxy
// (as specified by the multiClusterForwardingEndpoint parameter) to proxy k8s requests to the appropriate cluster. That
// proxy accepts the "x-cluster-id" header and uses that header to figure out which cluster to send the k8s request to.
func NewClusterCtxK8sClientFactory(baseRestConfig *rest.Config, multiClusterForwardingCA, multiClusterForwardingEndpoint string) ClusterCtxK8sClientFactory {
	return &clientSetFactory{
		baseRestConfig:                 baseRestConfig,
		multiClusterForwardingCA:       multiClusterForwardingCA,
		multiClusterForwardingEndpoint: multiClusterForwardingEndpoint,
	}
}

// ClientSetForCluster creates a new ClientSet that sends requests to k8s cluster identified with clusterID.
func (f *clientSetFactory) ClientSetForCluster(clusterID string) (ClientSet, error) {
	k8sConfig := f.RestConfigForCluster(clusterID)
	calicoConfig := rest.CopyConfig(k8sConfig)

	calicoCli, err := clientset.NewForConfig(calicoConfig)
	if err != nil {
		return nil, err
	}

	k8sCli, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}

	return &clientSet{
		calicoInterface: calicoCli.ProjectcalicoV3(),
		k8sInterface:    k8sCli,
	}, nil
}

// RBACAuthorizerForCluster creates a new auth.RBACAuthorizer that sends requests to k8s cluster identified with
// clusterID.
func (f *clientSetFactory) RBACAuthorizerForCluster(clusterId string) (auth.RBACAuthorizer, error) {
	cs, err := f.ClientSetForCluster(clusterId)
	if err != nil {
		return nil, err
	}

	return auth.NewRBACAuthorizer(cs), nil
}

func (f *clientSetFactory) RestConfigForCluster(clusterID string) *rest.Config {
	restConfig := f.copyRESTConfig()
	if clusterID != "" && clusterID != lmak8s.DefaultCluster {
		restConfig.Host = f.multiClusterForwardingEndpoint
		restConfig.CAFile = f.multiClusterForwardingCA
		restConfig.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			return &addHeaderRoundTripper{
				headers: map[string][]string{lmak8s.XClusterIDHeader: {clusterID}},
				rt:      rt,
			}
		}
	}

	return restConfig
}

// Impersonate makes a copy of the factory and adds HTTP Impersonation headers if provided user info is non-nil. If user
// info is nil the original factory is returned.
func (f *clientSetFactory) Impersonate(user *user.DefaultInfo) ClusterCtxK8sClientFactory {
	if user == nil {
		return f
	}
	newRestConfig := f.copyRESTConfig()
	newRestConfig.Impersonate = rest.ImpersonationConfig{
		UserName: user.Name,
		Groups:   user.Groups,
		Extra:    user.Extra,
		UID:      user.UID,
	}
	return NewClusterCtxK8sClientFactory(newRestConfig, f.multiClusterForwardingCA, f.multiClusterForwardingEndpoint)
}

func (f *clientSetFactory) copyRESTConfig() *rest.Config {
	f.Lock()
	defer f.Unlock()
	return rest.CopyConfig(f.baseRestConfig)
}

// addHeaderRoundTripper implements the http.RoundTripper interface and inserts the headers in headers field
// into the request made with an http.Client that uses this RoundTripper
type addHeaderRoundTripper struct {
	headers map[string][]string
	rt      http.RoundTripper
}

func (ha *addHeaderRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := new(http.Request)
	*r2 = *r

	// To set extra headers, we must make a copy of the Request so
	// that we don't modify the Request we were given. This is required by the
	// specification of http.RoundTripper.
	//
	// Since we are going to modify only req.Header here, we only need a deep copy
	// of req.Header.
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}

	for key, values := range ha.headers {
		r2.Header[key] = values
	}

	return ha.rt.RoundTrip(r2)
}
