// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package k8s

import (
	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tigera/api/pkg/client/clientset_generated/clientset"
	projectcalicov3 "github.com/tigera/api/pkg/client/clientset_generated/clientset/typed/projectcalico/v3"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// Default cluster name for standalone and management cluster.
	DefaultCluster = "cluster"

	// The cluster ID to include in the x-headers of the modified HTTP client.
	XClusterIDHeader = "x-cluster-id"

	// The tenant ID to include in the x-headers of the modified HTTP client.
	XTenantIDHeader = "x-tenant-id"
)

type ClientSetFactory interface {
	// Returns a client set authenticated by the app impersonating the user.
	NewClientSetForUser(user user.Info, clusterID string) (ClientSet, error)

	// Returns a client set authenticated by the app.
	NewClientSetForApplication(cluster string) (ClientSet, error)

	// Returns rest config for the application.
	NewRestConfigForApplication(clusterID string) *rest.Config

	// Adds impersonation headers to the ClientSetFactory's baseRestConfig for the provided user
	Impersonate(user *user.DefaultInfo) ClientSetFactory
}

// ClientSet is a combined Calico/Kubernetes client set interface.
type ClientSet interface {
	kubernetes.Interface
	ProjectcalicoV3() projectcalicov3.ProjectcalicoV3Interface
}

// clientSetFactory is a factory for creating user-specific and cluster specific kubernetes/calico clientsets.
type clientSetFactory struct {
	sync.Mutex
	baseRestConfig                 *rest.Config
	multiClusterForwardingCA       string
	multiClusterForwardingEndpoint string
}

// The client set struct implementing the client set interface.
type clientSet struct {
	kubernetes.Interface
	projectcalicov3 projectcalicov3.ProjectcalicoV3Interface
}

func (c *clientSet) ProjectcalicoV3() projectcalicov3.ProjectcalicoV3Interface {
	return c.projectcalicov3
}

// NewClientSetFactory creates an implementation of the ClientSetHandlers.
func NewClientSetFactory(multiClusterForwardingCA, multiClusterForwardingEndpoint string) ClientSetFactory {
	return NewClientSetFactoryWithConfig(MustGetConfig(), multiClusterForwardingCA, multiClusterForwardingEndpoint)
}

func NewClientSetFactoryWithConfig(rc *rest.Config, multiClusterForwardingCA, multiClusterForwardingEndpoint string) ClientSetFactory {
	return &clientSetFactory{
		baseRestConfig:                 rc,
		multiClusterForwardingCA:       multiClusterForwardingCA,
		multiClusterForwardingEndpoint: multiClusterForwardingEndpoint,
	}
}

// NewClientSetForApplication creates a client set for the application in the specified cluster. If no cluster is
// specified this defaults to the management cluster ("cluster").
func (f *clientSetFactory) NewClientSetForApplication(clusterID string) (ClientSet, error) {
	return f.getClientSet(nil, clusterID)
}

// NewClientSetForUserRequest creates a client set for the user (as per request) in the specified cluster. If no cluster
// is specified this defaults to the management cluster ("cluster").
func (f *clientSetFactory) NewClientSetForUser(user user.Info, clusterID string) (ClientSet, error) {
	return f.getClientSet(user, clusterID)
}

// Impersonate makes a copy of the factory and adds HTTP Impersonation headers if provided user info is non-nil. If user
// info is nil the original factory is returned.
func (f *clientSetFactory) Impersonate(user *user.DefaultInfo) ClientSetFactory {
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
	return NewClientSetFactoryWithConfig(newRestConfig, f.multiClusterForwardingCA, f.multiClusterForwardingEndpoint)
}

// NewRestConfigForApplication returns a K8S *rest.Config tailored for a particular cluster. Managed clusters will forward
// requests to the multicluster forwarding endpoint and add x-cluster-id header. If no cluster
// is specified this defaults to the management cluster ("cluster").
func (f *clientSetFactory) NewRestConfigForApplication(clusterID string) *rest.Config {
	restConfig := f.copyRESTConfig()
	if clusterID != "" && clusterID != DefaultCluster {
		restConfig.Host = f.multiClusterForwardingEndpoint
		restConfig.CAFile = f.multiClusterForwardingCA
		restConfig.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			return &addHeaderRoundTripper{
				headers: map[string][]string{XClusterIDHeader: {clusterID}},
				rt:      rt,
			}
		}
	}
	return restConfig
}

func (f *clientSetFactory) getClientSet(user user.Info, clusterID string) (ClientSet, error) {
	// Copy the rest config.
	restConfig := f.copyRESTConfig()

	// Determine which headers to override.
	headers := map[string][]string{}

	// If not the default cluster then add a cluster header.
	if clusterID != "" && clusterID != DefaultCluster {
		headers[XClusterIDHeader] = []string{clusterID}

		// In this case, update the host and cert for inter-cluster forwarding.
		restConfig.Host = f.multiClusterForwardingEndpoint
		restConfig.CAFile = f.multiClusterForwardingCA
	}

	// If the user has been specified then we are after a user-specific client set, so set the impersonation info.
	if user != nil {
		restConfig.Impersonate = rest.ImpersonationConfig{
			UserName: user.GetName(),
			Groups:   user.GetGroups(),
		}
	}

	// Wrap to add the supplied headers if any.
	if len(headers) > 0 {
		restConfig.Wrap(func(rt http.RoundTripper) http.RoundTripper {
			return &addHeaderRoundTripper{
				headers: headers,
				rt:      rt,
			}
		})
	}

	calicoCli, err := clientset.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	k8sCli, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	return &clientSet{
		projectcalicov3: calicoCli.ProjectcalicoV3(),
		Interface:       k8sCli,
	}, nil
}

// copyRESTConfig returns a copy of the base rest config.
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

func (rt *addHeaderRoundTripper) WrappedRoundTripper() http.RoundTripper { return rt.rt }

// MustGetConfig returns the rest Config for the local cluster.
func MustGetConfig() *rest.Config {
	kubeconfig := os.Getenv("KUBECONFIG")
	var config *rest.Config
	var err error
	if kubeconfig == "" {
		// creates the in-cluster config
		config, err = rest.InClusterConfig()
		if err != nil {
			log.WithError(err).Panic("Error getting in-cluster config")
		}
	} else {
		// creates a config from supplied kubeconfig
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			log.WithError(err).Panic("Error processing kubeconfig file in environment variable KUBECONFIG")
		}
	}
	config.Timeout = 15 * time.Second
	return config
}
