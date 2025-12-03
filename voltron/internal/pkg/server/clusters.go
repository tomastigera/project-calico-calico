// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/lma/pkg/logutils"
	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
	"github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	vtls "github.com/projectcalico/calico/voltron/pkg/tls"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
)

// AnnotationActiveCertificateFingerprint is an annotation that is used to store the fingerprint for
// managed cluster certificate that is allowed to initiate connections.
const (
	AnnotationActiveCertificateFingerprint = "certs.tigera.io/active-fingerprint"
	contextTimeout                         = 30 * time.Second
)

type cluster struct {
	// ID is intended to store the unique resource name for a ManagedCluster resource
	// We have chosen to use the resource name instead of the UID for a resource
	// because (1) we use the resource name to identify the cluster specific ElasticSearch
	// indexes (2) to be consistent we want to use the same cluster identifier across
	// all use cases (i.e. avoid creating overhead of mapping UID to resource name)
	ID string `json:"id"`
	// ActiveFingerprint stores the a hash extracted from the generated client certificate
	// assigned to a managed cluster. Only connections that present the certificate that matches the
	// active fingerprint will be accepted
	ActiveFingerprint string `json:"activeFingerprint,omitempty"`
	// Certificate stores managed cluster certificate.
	Certificate []byte `json:"certificate,omitempty"`

	sync.RWMutex

	tunnelManager tunnel.Manager

	statusUpdateFunc func(name string, status v3.ManagedClusterStatusValue)

	// Kubernetes client used for querying and watching ManagedCluster resources.
	k8sCLI bootstrap.K8sClient
	client ctrlclient.WithWatch

	// outboundTLSProxy is a reverse outboundTLSProxy for handling connections to Voltron from the management cluster
	// that should be directed down the tunnel to the managed cluster.
	outboundTLSProxy *httputil.ReverseProxy

	// inboundTLSProxy is the proxy that handles incoming TLS connections from the managed cluster.
	// These connections are routed via the server field in the TLS header. Connections via this proxy that
	// target Voltron itself will be handled by the proxy's inner TLS server.
	inboundTLSProxy vtls.Proxy

	// Pointer to general Voltron configuration.
	voltronCfg *config.Config

	// Version stores managed cluster's version information.
	version string

	managedClusterQuerier ManagedClusterQuerier
}

// updateActiveFingerprint updates the active fingerprint annotation for a ManagedCluster resource
// in the management cluster.
func (c *cluster) updateActiveFingerprint(fingerprint string) error {
	mc := &v3.ManagedCluster{}
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()

	// Client Get act as single tenant when the TenantNamespace is empty
	err := c.client.Get(ctx, types.NamespacedName{Name: c.ID, Namespace: c.voltronCfg.TenantNamespace}, mc)
	if err != nil {
		return err
	}

	mc.Annotations[AnnotationActiveCertificateFingerprint] = fingerprint

	err = c.client.Update(ctx, mc)
	if err != nil {
		return err
	}

	c.ActiveFingerprint = fingerprint

	return nil
}

type clusters struct {
	sync.RWMutex
	clusters      map[string]*cluster
	sniServiceMap map[string]string
	k8sCLI        bootstrap.K8sClient
	client        ctrlclient.WithWatch

	// parameters for forwarding guardian requests to a default server
	forwardingEnabled               bool
	defaultForwardServerName        string
	defaultForwardDialRetryAttempts int
	defaultForwardDialRetryInterval time.Duration

	// Pointer to general Voltron config.
	voltronCfg *config.Config

	// TLS configuration to use for inner tunnel HTTPS servers.
	tlsConfig *tls.Config

	// Proxier to use for connections from managed clusters.
	innerProxy *proxy.Proxy

	// Pool used for client certificate verification.
	clientCertificatePool *x509.CertPool

	statusUpdateFunc func(name string, status v3.ManagedClusterStatusValue)

	managedClusterQuerierFactory ManagedClusterQuerierFactory
}

func (cs *clusters) makeInnerTLSConfig() error {
	cfg, err := calicotls.NewTLSConfig()
	if err != nil {
		return err
	}
	if cs.voltronCfg.LinseedServerKey != "" && cs.voltronCfg.LinseedServerCert != "" {
		certBytes, err := os.ReadFile(cs.voltronCfg.LinseedServerCert)
		if err != nil {
			return err
		}
		keyBytes, err := os.ReadFile(cs.voltronCfg.LinseedServerKey)
		if err != nil {
			return err
		}
		cert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			return err
		}
		cfg.Certificates = append(cfg.Certificates, cert)
	}
	cs.tlsConfig = cfg
	return nil
}

func (cs *clusters) add(mc v3.ManagedCluster) error {
	if cs.clusters[mc.Name] != nil {
		return fmt.Errorf("cluster id %q already exists", mc.Name)
	}

	c := &cluster{
		ID:                mc.Name,
		ActiveFingerprint: mc.Annotations[AnnotationActiveCertificateFingerprint],
		Certificate:       mc.Spec.Certificate,
		tunnelManager:     tunnel.NewManager(),
		k8sCLI:            cs.k8sCLI,
		client:            cs.client,
		voltronCfg:        cs.voltronCfg,
		statusUpdateFunc:  cs.statusUpdateFunc,
	}

	var err error
	c.managedClusterQuerier, err = cs.managedClusterQuerierFactory.New(c.DialTLS2)
	if err != nil {
		return fmt.Errorf("failed to create managed cluster querier for cluster %s: %w", c.ID, err)
	}

	// Append the new certificate to the client certificate pool.
	cs.clientCertificatePool.AppendCertsFromPEM(c.Certificate)
	logrus.Infof("Appended certificate for cluster %s to client certificate pool", c.ID)

	if cs.forwardingEnabled {
		var opts []InnerHandlerOption
		if cs.voltronCfg.GoldmaneEnabled {
			opts = append(opts, WithTokenPath(voltronToken))

			// A simple rate limited to prevent abuse of the tunnel. We know that Goldmane will only publish flows every 5 minutes
			// during normal operation. This may occur slightly more frequently if we hit retry / restart scenarios, so set a limit of
			// one request every 30 seconds, with a burst of 10 requests.
			opts = append(opts, WithRateLimiter(rate.NewLimiter(rate.Every(30*time.Second), 10)))
		}

		// Create a proxy to use for connections received over the tunnel that aren't
		// directed via SNI. This is just used for Linseed connections from managed clusters.
		// We use the same TLS configuration as the main tunnel. We will proxy the connection
		// presenting Voltron's internal management cluster certificate, as Linseed requires mTLS.
		//
		// This handler will only be used for requests from managed clusters over the mTLS tunnel
		// with a server name of "tigera-linseed.tigera-elasticsearch".
		innerServer := &http.Server{
			Handler:     NewInnerHandler(cs.voltronCfg.TenantID, mc.Name, cs.innerProxy, opts...).Handler(),
			TLSConfig:   cs.tlsConfig,
			ReadTimeout: DefaultReadTimeout,
			ErrorLog:    log.New(logutils.NewLogrusWriter(logrus.WithFields(logrus.Fields{"server": "innerServer"})), "", log.LstdFlags),
		}

		inboundProxy, err := vtls.NewProxy(
			vtls.WithDefaultServiceURL(cs.defaultForwardServerName),
			vtls.WithProxyOnSNI(true),
			vtls.WithSNIServiceMap(cs.sniServiceMap),
			vtls.WithConnectionRetryAttempts(cs.defaultForwardDialRetryAttempts),
			vtls.WithConnectionRetryInterval(cs.defaultForwardDialRetryInterval),
			vtls.WithInnerServer(innerServer),
		)
		if err != nil {
			return err
		}
		c.inboundTLSProxy = inboundProxy
	}

	cs.clusters[mc.Name] = c
	return nil
}

func (cs *clusters) update(mc v3.ManagedCluster) error {
	cs.Lock()
	defer cs.Unlock()
	return cs.updateLocked(mc)
}

func (cs *clusters) updateLocked(mc v3.ManagedCluster) error {
	if c, ok := cs.clusters[mc.Name]; ok {
		c.Lock()
		clog := logrus.WithField("cluster", c.ID)
		clog.Info("Updating the managed cluster")

		oldCert := c.Certificate
		newCert := mc.Spec.Certificate

		// Update the managed cluster
		c.Certificate = newCert
		c.ActiveFingerprint = mc.Annotations[AnnotationActiveCertificateFingerprint]

		// Update the certificate pool if the certificate has changed
		err, updated := cs.updateCertPool(newCert, oldCert)
		if err != nil {
			clog.WithError(err).Error("failed to update the client certificate pool")
			// Close the tunnel to disconnect
			if err := c.closeTunnel(); err != nil {
				clog.WithError(err).Error("failed to close tunnel")
				c.Unlock()

				return err
			}
			c.Unlock()

			return err
		}

		if updated {
			clog.Info("Updated the client certificate pool, closing tunnel")
			// Close the tunnel to disconnect
			if err := c.closeTunnel(); err != nil {
				clog.WithError(err).Error("failed to close tunnel")
				c.Unlock()

				return err
			}
		}
		c.Unlock()

		return nil
	}

	return cs.add(mc)
}

func (cs *clusters) remove(mc v3.ManagedCluster) error {
	cs.Lock()

	c, ok := cs.clusters[mc.Name]
	if !ok {
		cs.Unlock()
		msg := fmt.Sprintf("Cluster id %q does not exist", mc.Name)
		logrus.Debug(msg)
		return errors.New(msg)
	}

	// remove from the map so nobody can get it, but whoever uses it can
	// keep doing so
	delete(cs.clusters, mc.Name)
	cs.Unlock()
	c.stop()
	logrus.Infof("Cluster id %q removed", mc.Name)

	return nil
}

// get returns the cluster
func (cs *clusters) get(id string) *cluster {
	cs.RLock()
	defer cs.RUnlock()
	return cs.clusters[id]
}

func (cs *clusters) watchK8sFrom(ctx context.Context, last string) error {
	watcher, err := cs.client.Watch(ctx, &v3.ManagedClusterList{},
		&ctrlclient.ListOptions{
			Namespace: cs.voltronCfg.TenantNamespace,
			Raw: &metav1.ListOptions{
				ResourceVersion: last,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create k8s watch: %s", err)
	}

	for {
		select {
		case r, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("watcher stopped unexpectedly")
			}
			mc, ok := r.Object.(*v3.ManagedCluster)
			if !ok {
				logrus.Debugf("Unexpected object type %T", r.Object)
				continue
			}

			logrus.Debugf("Watching K8s resource type: %s for cluster %s", r.Type, mc.Name)

			var err error

			switch r.Type {
			case watch.Added, watch.Modified:
				logrus.Infof("Adding/Updating %s", mc.Name)
				err = cs.update(*mc)
			case watch.Deleted:
				logrus.Infof("Deleting %s", mc.Name)
				err = cs.remove(*mc)
			default:
				err = fmt.Errorf("watch event %s unsupported", r.Type)
			}

			if err != nil {
				logrus.Errorf("ManagedClusters watch event %s failed: %s", r.Type, err)
			}
		case <-ctx.Done():
			watcher.Stop()
			return fmt.Errorf("watcher exiting: %s", ctx.Err())
		}
	}
}

func (cs *clusters) resyncWithK8s(ctx context.Context, startupSync bool) (string, error) {
	list := &v3.ManagedClusterList{}
	err := cs.client.List(ctx, list, &ctrlclient.ListOptions{Namespace: cs.voltronCfg.TenantNamespace})
	if err != nil {
		return "", fmt.Errorf("failed to get k8s list: %s", err)
	}

	known := make(map[string]struct{})

	cs.Lock()
	defer cs.Unlock()

	for _, mc := range list.Items {
		known[mc.Name] = struct{}{}

		logrus.Debugf("Sync K8s watch for cluster : %s", mc.Name)
		err = cs.updateLocked(mc)
		if err != nil {
			logrus.Errorf("ManagedClusters listing failed: %s", err)
		}

		if startupSync && isConnectedStatus(mc, v3.ManagedClusterStatusValueTrue) {
			if c, ok := cs.clusters[mc.Name]; ok {
				c.sendStatusUpdate(v3.ManagedClusterStatusValueFalse)
			}
		}
	}

	// remove all the active clusters not in the list since we must have missed
	// the DELETE watch event
	for id, c := range cs.clusters {
		if _, ok := known[id]; ok {
			continue
		}
		delete(cs.clusters, id)
		c.stop()
		logrus.Infof("Cluster id %q removed", id)
	}

	return list.ResourceVersion, nil
}

func (cs *clusters) watchK8s(ctx context.Context) error {
	// Initial sync for new server
	startupSync := true
	for {
		last, err := cs.resyncWithK8s(ctx, startupSync)
		if err == nil {
			startupSync = false
			err = cs.watchK8sFrom(ctx, last)
			if err != nil {
				err = errors.WithMessage(err, "k8s watch failed")
			}
		} else {
			err = errors.WithMessage(err, "k8s list failed")
		}
		logrus.Debugf("ManagedClusters: could not sync watch due to %s", err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("watcher exiting: %s", ctx.Err())
		default:
		}
	}
}

// updateCertPool updates the client cert pool if the new (non-empty) certificate is different from
// the old one.
func (cs *clusters) updateCertPool(newCertPEM, oldCertPEM []byte) (error, bool) {
	updated := false
	if len(newCertPEM) == 0 {
		// No pool update necessary for an empty certificate.
		logrus.Debugf("No pool update necessary for an empty certificate.")
		return nil, updated
	}

	newCert, err := parseCertificatePEMBlock(newCertPEM)
	if err != nil {
		return err, updated
	}

	if len(oldCertPEM) != 0 {
		oldCert, err := parseCertificatePEMBlock(oldCertPEM)
		if err != nil {
			return err, updated
		}

		if oldCert.Equal(newCert) {
			// No pool update necessary if the certificates are the same.
			logrus.Debugf("No pool update necessary if the certificates are the same.")
			return nil, updated
		}
	}

	cs.clientCertificatePool.AddCert(newCert)
	updated = true
	logrus.Infof("Updated client cert pool with new value.")

	return nil, updated
}

func (c *cluster) checkTunnelState() {
	err := <-c.tunnelManager.ListenForErrors()

	c.Lock()
	defer c.Unlock()

	clog := logrus.WithField("cluster", c.ID)

	c.outboundTLSProxy = nil
	if err := c.tunnelManager.CloseTunnel(); err != nil && err != tunnel.ErrTunnelClosed {
		logrus.WithError(err).Error("an error occurred closing the tunnel")
	}
	c.sendStatusUpdate(v3.ManagedClusterStatusValueFalse)

	if err != nil {
		clog.WithError(err).Error("Cluster tunnel is broken, deleted")
		return
	}
	clog.Info("Cluster tunnel is closed")
}

func (c *cluster) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return c.tunnelManager.Open()
}

func (c *cluster) DialTLS2(network, addr string, cfg *tls.Config) (net.Conn, error) {
	return c.tunnelManager.OpenTLS(cfg)
}

func (c *cluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.RLock()
	proxy := c.outboundTLSProxy
	c.RUnlock()

	if proxy == nil {
		logrus.Debugf("Cannot proxy to cluster %s, no tunnel", c.ID)
		writeHTTPError(w, clusterNotConnectedError(c.ID))
		return
	}

	proxy.ServeHTTP(w, r)
}

// assignTunnel may read and write state, so it must be called with c.Lock called.
func (c *cluster) assignTunnel(t tunnel.Tunnel) error {
	c.Lock()
	defer c.Unlock()

	if len(c.Certificate) != 0 {
		if err := validateCertificate(t.Certificate(), c.Certificate); err != nil {
			closeTunnel(t)
			return fmt.Errorf("failed to verify certificate for cluster %s: %w", t.ClusterID(), err)
		}
	} else {
		if len(c.ActiveFingerprint) == 0 {
			closeTunnel(t)
			return fmt.Errorf("no fingerprint has been stored against the current connection")
		}
		// Before Calico Enterprise v3.15, we use md5 hash algorithm for the managed cluster
		// certificate fingerprint. md5 is known to cause collisions and it is not approved in
		// FIPS mode. From v3.15, we are upgrading the active fingerprint to use sha256 hash algorithm.
		if hex.DecodedLen(len(c.ActiveFingerprint)) == sha256.Size {
			if t.Fingerprint() != c.ActiveFingerprint {
				closeTunnel(t)
				return fmt.Errorf("stored fingerprint does not match provided fingerprint")
			}
		} else {
			// check pre-v3.15 fingerprint (md5)
			if t.MD5Fingerprint() != c.ActiveFingerprint {
				closeTunnel(t)
				return fmt.Errorf("stored fingerprint does not match provided fingerprint")
			}

			// update to v3.15 fingerprint hash (sha256) when matched
			if err := c.updateActiveFingerprint(t.Fingerprint()); err != nil {
				closeTunnel(t)
				return fmt.Errorf("failed to update cluster %s stored fingerprint: %w", t.ClusterID(), err)
			}

			logrus.Infof("Cluster %s stored fingerprint is successfully updated", t.ClusterID())
		}
	}
	if err := c.tunnelManager.SetTunnel(t); err != nil {
		return err
	}

	// Set up the outbound proxy, which handles traffic from the management cluster designated.
	// to the managed cluster over the tunnel.
	outboundTLSConfig, err := calicotls.NewTLSConfig()
	if err != nil {
		return err
	}
	outboundTLSConfig.InsecureSkipVerify = true // todo: not sure where this comes from, but this should be dealt with.
	c.outboundTLSProxy = &httputil.ReverseProxy{
		Director:      proxyVoidDirector,
		FlushInterval: -1,
		ErrorLog:      log.New(logutils.NewLogrusWriter(logrus.WithFields(logrus.Fields{"proxy": "outbound"})), "", log.LstdFlags),
		Transport: &http2.Transport{
			DialTLS:         c.DialTLS2,
			TLSClientConfig: outboundTLSConfig,
			AllowHTTP:       true,
		},
	}

	if c.inboundTLSProxy != nil {
		go func() {
			logrus.Debugf("server has started listening for connections from cluster %s", c.ID)
			// This loop only stops trying to listen if the tunnel or manager was closed
			for {
				shouldStop := false
				func() {
					listener, err := c.tunnelManager.Listener()
					if err != nil {
						if err == tunnel.ErrTunnelClosed || err == tunnel.ErrManagerClosed {
							shouldStop = true
							return
						}
						logrus.WithError(err).Error("failed to listen over the tunnel")
						return
					}
					defer func() { _ = listener.Close() }()

					if err := c.inboundTLSProxy.ListenAndProxy(listener); err != nil {
						if err != tunnel.ErrTunnelClosed {
							logrus.WithError(err).Error("failed to listen for incoming requests through the tunnel")
						} else {
							logrus.Info("failed to listen for incoming requests through the tunnel, tunnel closed")
						}
					}
				}()

				if shouldStop {
					break
				}
				time.Sleep(1 * time.Second)
			}
			logrus.Debugf("server has stopped listening for connections from %s", c.ID)
		}()
	}

	logrus.Info("Fetching the managed cluster version information for ", c.ID)
	// Fetch managed cluster version before marking it as connected.
	mcVersion, err := c.managedClusterQuerier.GetVersion()
	if err != nil {
		// Managed clusters older than v3.22 may lack RBAC to fetch ClusterInformation.
		// In such cases, leave the version empty for now.
		if k8serrors.IsForbidden(err) {
			logrus.Debugf("Forbidden error while fetching ClusterInformation for %s :%v", c.ID, err)
		} else {
			// We don't want to block tunnel establishment due to this error — just log a warning and proceed.
			// This information is only needed for UI rendering, and restarting the guardian should resolve the issue.
			// The tunnel, however, is critical for Fluentd to push logs to Elasticsearch.
			logrus.Warn("Error while fetching ClusterInformation:", c.ID, err)
		}
	} else {
		logrus.Debugf("Fetched cluster version information for %s : %s", c.ID, mcVersion)
		c.version = mcVersion
	}

	c.sendStatusUpdate(v3.ManagedClusterStatusValueTrue)

	// will clean up the tunnel if it breaks, will exit once the tunnel is gone
	go c.checkTunnelState()

	return nil
}

func closeTunnel(t tunnel.Tunnel) {
	err := t.Close()
	if err != nil {
		logrus.WithError(err).Error("Could not close tunnel")
	}
}

func (c *cluster) sendStatusUpdate(status v3.ManagedClusterStatusValue) {
	c.statusUpdateFunc(c.ID, status)
}

func (c *cluster) stop() {
	// close the tunnel to disconnect. Closing is thread save, but we need
	// to hold the RLock to access the tunnel
	c.RLock()
	if c.tunnelManager != nil {
		if err := c.tunnelManager.Close(); err != nil {
			logrus.WithError(err).Error("an error occurred closing the tunnelManager")
		}
	}
	c.RUnlock()
}

// closeTunnel closes the tunnel to disconnect. Is not thread safe, so the caller
// must hold the RLock to access the tunnel.
func (c *cluster) closeTunnel() error {
	if c.tunnelManager != nil {
		// Close the tunnel to disconnect.
		if err := c.tunnelManager.CloseTunnel(); err != nil {
			if err != tunnel.ErrTunnelClosed {
				logrus.WithError(err).Error("an error occurred closing tunnel")
				return err
			}
		}
	}

	return nil
}

func proxyVoidDirector(*http.Request) {
	// do nothing with the request, we pass it forward as is, the other side of
	// the tunnel should do whatever it needs to proxy it further
}

// parseCertificatePEMBlock decodes a PEM encoded certificate and returns the parsed x509 certificate.
// The PEM cert is assumed to be a single block.
func parseCertificatePEMBlock(certPEM []byte) (*x509.Certificate, error) {
	// Decode PEM content
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func isConnectedStatus(mc v3.ManagedCluster, status v3.ManagedClusterStatusValue) bool {
	for _, c := range mc.Status.Conditions {
		if c.Type == v3.ManagedClusterStatusTypeConnected {
			return c.Status == status
		}
	}
	return false
}
