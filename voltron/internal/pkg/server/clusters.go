// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	calicotls "github.com/projectcalico/calico/crypto/pkg/tls"
	"github.com/projectcalico/calico/lma/pkg/logutils"
	"github.com/projectcalico/calico/voltron/internal/pkg/bootstrap"
	jclust "github.com/projectcalico/calico/voltron/internal/pkg/clusters"
	"github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/proxy"
	vtls "github.com/projectcalico/calico/voltron/pkg/tls"
	"github.com/projectcalico/calico/voltron/pkg/tunnel"
	"github.com/projectcalico/calico/voltron/pkg/tunnelmgr"
)

// AnnotationActiveCertificateFingerprint is an annotation that is used to store the fingerprint for
// managed cluster certificate that is allowed to initiate connections.
const (
	AnnotationActiveCertificateFingerprint = "certs.tigera.io/active-fingerprint"
	contextTimeout                         = 30 * time.Second
)

type cluster struct {
	jclust.ManagedCluster

	sync.RWMutex

	tunnelManager tunnelmgr.Manager

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
}

func (cs *clusters) makeInnerTLSConfig() error {
	cfg := calicotls.NewTLSConfig()
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

func (cs *clusters) add(mc *jclust.ManagedCluster) (*cluster, error) {
	if cs.clusters[mc.ID] != nil {
		return nil, fmt.Errorf("cluster id %q already exists", mc.ID)
	}

	c := &cluster{
		ManagedCluster:   *mc,
		tunnelManager:    tunnelmgr.NewManager(),
		k8sCLI:           cs.k8sCLI,
		client:           cs.client,
		voltronCfg:       cs.voltronCfg,
		statusUpdateFunc: cs.statusUpdateFunc,
	}

	// Append the new certificate to the client certificate pool.
	cs.clientCertificatePool.AppendCertsFromPEM(mc.Certificate)
	logrus.Infof("Appended certificate for cluster %s to client certificate pool", mc.ID)

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
			Handler:     NewInnerHandler(cs.voltronCfg.TenantID, mc, cs.innerProxy, opts...).Handler(),
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
			return nil, err
		}
		c.inboundTLSProxy = inboundProxy
	}

	cs.clusters[mc.ID] = c
	return c, nil
}

// List all clusters in sorted order by ID field (which is the resource name)
func (cs *clusters) List() []jclust.ManagedCluster {
	cs.RLock()
	defer cs.RUnlock()

	clusterList := make([]jclust.ManagedCluster, 0, len(cs.clusters))
	for _, c := range cs.clusters {
		// Only include non-sensitive fields

		c.RLock()
		clusterList = append(clusterList, c.ManagedCluster)
		c.RUnlock()
	}

	sort.Slice(clusterList, func(i, j int) bool {
		return clusterList[i].ID < clusterList[j].ID
	})

	logrus.Debugf("Listing current %d clusters.", len(clusterList))
	for _, cluster := range clusterList {
		logrus.Debugf("ID = %s", cluster.ID)
	}
	return clusterList
}

func (cs *clusters) addNew(mc *jclust.ManagedCluster) error {
	logrus.Infof("Adding cluster ID: %q", mc.ID)

	_, err := cs.add(mc)
	if err != nil {
		return err
	}

	return nil
}

func (cs *clusters) addRecovered(mc *jclust.ManagedCluster) error {
	logrus.Infof("Recovering cluster ID: %q", mc.ID)

	_, err := cs.add(mc)
	return err
}

func (cs *clusters) update(mc *jclust.ManagedCluster) error {
	cs.Lock()
	defer cs.Unlock()
	return cs.updateLocked(mc, false)
}

func (cs *clusters) updateLocked(mc *jclust.ManagedCluster, recovery bool) error {
	if c, ok := cs.clusters[mc.ID]; ok {
		c.Lock()
		clog := logrus.WithField("cluster", c.ID)
		clog.Info("Updating the managed cluster")

		oldCert := c.ManagedCluster.Certificate
		newCert := mc.Certificate

		// Update the managed cluster
		c.ManagedCluster = *mc

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

	if recovery {
		return cs.addRecovered(mc)
	}

	return cs.addNew(mc)
}

func (cs *clusters) remove(mc *jclust.ManagedCluster) error {
	cs.Lock()

	c, ok := cs.clusters[mc.ID]
	if !ok {
		cs.Unlock()
		msg := fmt.Sprintf("Cluster id %q does not exist", mc.ID)
		logrus.Debug(msg)
		return errors.New(msg)
	}

	// remove from the map so nobody can get it, but whoever uses it can
	// keep doing so
	delete(cs.clusters, mc.ID)
	cs.Unlock()
	c.stop()
	logrus.Infof("Cluster id %q removed", mc.ID)

	return nil
}

// get returns the cluster
func (cs *clusters) get(id string) *cluster {
	cs.RLock()
	defer cs.RUnlock()
	return cs.clusters[id]
}

func (cs *clusters) watchK8sFrom(ctx context.Context, syncC chan<- error, last string) error {
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
			mcResource, ok := r.Object.(*v3.ManagedCluster)
			if !ok {
				logrus.Debugf("Unexpected object type %T", r.Object)
				continue
			}

			mc := &jclust.ManagedCluster{
				ID:                mcResource.ObjectMeta.Name,
				ActiveFingerprint: mcResource.ObjectMeta.Annotations[AnnotationActiveCertificateFingerprint],
				Certificate:       mcResource.Spec.Certificate,
				// TODO: Update Voltron to fetch the managed cluster version info and store it directly
				// in the cluster memory, instead of using the ManagedCluster resource.
				Version: mcResource.Status.Version,
			}

			logrus.Debugf("Watching K8s resource type: %s for cluster %s", r.Type, mc.ID)

			var err error

			switch r.Type {
			case watch.Added, watch.Modified:
				logrus.Infof("Adding/Updating %s", mc.ID)
				err = cs.update(mc)
			case watch.Deleted:
				logrus.Infof("Deleting %s", mc.ID)
				err = cs.remove(mc)
			default:
				err = fmt.Errorf("watch event %s unsupported", r.Type)
			}

			if err != nil {
				logrus.Errorf("ManagedClusters watch event %s failed: %s", r.Type, err)
			}

			if syncC != nil {
				select {
				case syncC <- err:
				case <-ctx.Done():
					watcher.Stop()
					return fmt.Errorf("watcher exiting: %s", ctx.Err())
				}
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

	for _, managedCluster := range list.Items {
		id := managedCluster.ObjectMeta.Name

		mc := &jclust.ManagedCluster{
			ID:                id,
			ActiveFingerprint: managedCluster.ObjectMeta.Annotations[AnnotationActiveCertificateFingerprint],
			Certificate:       managedCluster.Spec.Certificate,
		}

		known[id] = struct{}{}

		logrus.Debugf("Sync K8s watch for cluster : %s", mc.ID)
		err = cs.updateLocked(mc, true)
		if err != nil {
			logrus.Errorf("ManagedClusters listing failed: %s", err)
		}

		if startupSync && isConnectedStatus(&managedCluster, v3.ManagedClusterStatusValueTrue) {
			if c, ok := cs.clusters[id]; ok {
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

	return list.ListMeta.ResourceVersion, nil
}

func (cs *clusters) watchK8s(ctx context.Context, syncC chan<- error) error {
	// Initial sync for new server
	startupSync := true
	for {
		last, err := cs.resyncWithK8s(ctx, startupSync)
		if err == nil {
			startupSync = false
			err = cs.watchK8sFrom(ctx, syncC, last)
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
func (c *cluster) assignTunnel(t *tunnel.Tunnel) error {
	if err := c.tunnelManager.SetTunnel(t); err != nil {
		return err
	}

	// Set up the outbound proxy, which handles traffic from the management cluster desinted
	// to the managed cluster over the tunnel.
	outboundTLSConfig := calicotls.NewTLSConfig()
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
						if err == tunnel.ErrTunnelClosed || err == tunnelmgr.ErrManagerClosed {
							shouldStop = true
							return
						}
						logrus.WithError(err).Error("failed to listen over the tunnel")
						return
					}
					defer listener.Close()

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

	c.sendStatusUpdate(v3.ManagedClusterStatusValueTrue)

	// will clean up the tunnel if it breaks, will exit once the tunnel is gone
	go c.checkTunnelState()

	return nil
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

func isConnectedStatus(mc *v3.ManagedCluster, status v3.ManagedClusterStatusValue) bool {
	if mc == nil {
		return false
	}
	for _, c := range mc.Status.Conditions {
		if c.Type == v3.ManagedClusterStatusTypeConnected {
			return c.Status == status
		}
	}
	return false
}
