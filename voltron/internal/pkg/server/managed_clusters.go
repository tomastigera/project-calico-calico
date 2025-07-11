package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	tigeraapi "github.com/tigera/api/pkg/client/clientset_generated/clientset"
	"golang.org/x/net/http2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
)

type ManagedClusterQuerierFactory interface {
	New(dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)) (ManagedClusterQuerier, error)
}

type ManagedClusterQuerier interface {
	GetVersion() (string, error)
}

type DefaultManagedClusterQuerierFactory struct{}

func (f *DefaultManagedClusterQuerierFactory) New(dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)) (ManagedClusterQuerier, error) {
	return &ManagedClusterDataQuerier{
		dialFunc: dialFunc,
	}, nil
}

type ManagedClusterDataQuerier struct {
	dialFunc func(network, addr string, cfg *tls.Config) (net.Conn, error)
}

// GetVersion fetches the Managed cluster's version information via the existing tunnel.
func (mc *ManagedClusterDataQuerier) GetVersion() (string, error) {
	tlsConfig := calicotls.NewTLSConfig()
	tlsConfig.InsecureSkipVerify = true

	restConfig := &rest.Config{
		Host: "https://kubernetes.default.svc:443",
		Transport: &http2.Transport{
			DialTLS:         mc.dialFunc,
			TLSClientConfig: tlsConfig,
			AllowHTTP:       true,
		},
	}

	calicoClient, err := tigeraapi.NewForConfig(restConfig)
	if err != nil {
		return "", fmt.Errorf("failed to create Calico client: %w", err)
	}

	ci, err := calicoClient.ProjectcalicoV3().
		ClusterInformations().
		Get(context.Background(), "default", metav1.GetOptions{})

	if err != nil {
		return "", err
	}

	return ci.Spec.CNXVersion, nil
}
