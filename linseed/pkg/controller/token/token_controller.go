// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package token

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/utils"
	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
	"github.com/projectcalico/calico/lma/pkg/k8s"
)

const (
	LinseedIssuer        string = "linseed.tigera.io"
	defaultTokenLifetime        = 24 * time.Hour
	allClustersRetryKey         = "all-clusters-retry-key"
)

type Controller interface {
	Run(<-chan struct{}) error
}

type ControllerOption func(*controller) error

func WithPrivateKey(k *rsa.PrivateKey) ControllerOption {
	return func(c *controller) error {
		c.privateKey = k
		return nil
	}
}

// WithControllerRuntimeClient configures the controller runtime client used to access managed cluster resources.
func WithControllerRuntimeClient(client ctrlclient.WithWatch) ControllerOption {
	return func(c *controller) error {
		c.client = client
		return nil
	}
}

func WithK8sClient(kc kubernetes.Interface) ControllerOption {
	return func(c *controller) error {
		c.managementK8sClient = kc
		return nil
	}
}

func WithSecretsToCopy(secrets []corev1.Secret) ControllerOption {
	return func(c *controller) error {
		c.secretsToCopy = secrets
		return nil
	}
}

func WithTenant(tenant string) ControllerOption {
	return func(c *controller) error {
		c.tenant = tenant
		return nil
	}
}

func WithTenantNamespaceForUsers(tenant string) ControllerOption {
	return func(c *controller) error {
		c.tenant = tenant
		return nil
	}
}

func WithImpersonation(info *user.DefaultInfo) ControllerOption {
	return func(c *controller) error {
		c.impersonationInfo = info
		return nil
	}
}

// WithIssuer sets the issuer of the generated tokens.
func WithIssuer(iss string) ControllerOption {
	return func(c *controller) error {
		c.issuer = iss
		return nil
	}
}

// WithIssuerName sets the name of the token issuer, used when generating
// names for token secrets in managed clusters.
func WithIssuerName(name string) ControllerOption {
	return func(c *controller) error {
		c.issuerName = name
		return nil
	}
}

// WithExpiry sets the duration that generated tokens should be valid for.
func WithExpiry(d time.Duration) ControllerOption {
	return func(c *controller) error {
		c.expiry = d
		return nil
	}
}

// WithFactory sets the factory to use for generating per-cluster clients.
func WithFactory(f k8s.ClientSetFactory) ControllerOption {
	return func(c *controller) error {
		c.factory = f
		return nil
	}
}

func WithInformerStopChan(m map[string]chan struct{}) ControllerOption {
	return func(c *controller) error {
		c.informerStopChans = m
		return nil
	}
}

func WithLinseedTokenTargetNamespaces(ns []string) ControllerOption {
	return func(c *controller) error {
		c.linseedTokenTargetNamespaces = ns
		return nil
	}
}

// WithInitialReconciliationDelay sets the duration to wait before initiating the token reconciliation process with the managed cluster.
// This delay allows the necessary RBAC resources to be created before attempting to access the namespace.
func WithInitialReconciliationDelay(d time.Duration) ControllerOption {
	return func(c *controller) error {
		c.initialReconciliationDelay = &d
		return nil
	}
}

type UserInfo struct {
	Name                    string
	Namespace               string
	TenantNamespaceOverride string
}

// WithUserInfos sets the users in each managed cluster that this controller
// should generate tokens for.
func WithUserInfos(s []UserInfo) ControllerOption {
	return func(c *controller) error {
		for _, sa := range s {
			if sa.Name == "" {
				return fmt.Errorf("missing Name field in UserInfo")
			}
			if sa.Namespace == "" {
				return fmt.Errorf("missing Namespace field in UserInfo")
			}

		}
		c.userInfos = s
		return nil
	}
}

func WithReconcilePeriod(t time.Duration) ControllerOption {
	return func(c *controller) error {
		c.reconcilePeriod = &t
		return nil
	}
}

// WithBaseRetryPeriod sets the base retry period for retrying failed operations.
// The actual retry period is calculated as baseRetryPeriod * 2^retryCount.
func WithBaseRetryPeriod(t time.Duration) ControllerOption {
	return func(c *controller) error {
		c.baseRetryPeriod = &t
		return nil
	}
}

func WithMaxRetries(n int) ControllerOption {
	return func(c *controller) error {
		c.maxRetries = &n
		return nil
	}
}

func WithHealthReport(reportHealth func(*health.HealthReport)) ControllerOption {
	return func(c *controller) error {
		c.reportHealth = reportHealth
		return nil
	}
}

func WithNamespace(ns string) ControllerOption {
	return func(c *controller) error {
		c.namespace = ns
		return nil
	}
}

func NewController(opts ...ControllerOption) (Controller, error) {
	c := &controller{
		permissionMap: make(map[string]bool),
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	// Default anything not set.
	if c.reconcilePeriod == nil {
		d := 60 * time.Minute
		c.reconcilePeriod = &d
	}
	if c.baseRetryPeriod == nil {
		d := 1 * time.Second
		c.baseRetryPeriod = &d
	}
	if c.maxRetries == nil {
		n := 20
		c.maxRetries = &n
	}

	if c.initialReconciliationDelay == nil {
		d := 0 * time.Second
		c.initialReconciliationDelay = &d
	}

	if c.informerStopChans == nil {
		c.informerStopChans = make(map[string]chan struct{})
	}

	// Verify necessary options set.
	if c.client == nil {
		return nil, fmt.Errorf("must provide a management cluster controller runtime client")
	}
	if c.privateKey == nil {
		return nil, fmt.Errorf("must provide a private key")
	}
	if c.issuer == "" {
		return nil, fmt.Errorf("must provide an issuer")
	}
	if c.issuerName == "" {
		return nil, fmt.Errorf("must provide an issuer name")
	}
	if len(c.userInfos) == 0 {
		return nil, fmt.Errorf("must provide at least one user info")
	}
	if c.factory == nil {
		return nil, fmt.Errorf("must provide a clientset factory")
	}
	if c.managementK8sClient == nil {
		return nil, fmt.Errorf("must provide a management Kubernetes client")
	}
	return c, nil
}

type controller struct {
	// Input configuration.
	privateKey          *rsa.PrivateKey
	tenant              string
	namespace           string
	issuer              string
	issuerName          string
	client              ctrlclient.WithWatch
	managementK8sClient kubernetes.Interface
	secretsToCopy       []corev1.Secret
	expiry              time.Duration
	reconcilePeriod     *time.Duration
	baseRetryPeriod     *time.Duration
	maxRetries          *int
	reportHealth        func(*health.HealthReport)
	factory             k8s.ClientSetFactory

	// userInfos in the managed cluster that we should provision tokens for.
	userInfos []UserInfo

	// impersonationInfo contains the information necessary to populate the HTTP impersonation headers needed to perform
	// certain actions on behalf of the managed cluster (eg. copying secrets)
	impersonationInfo *user.DefaultInfo

	// informerStopChans tracks the managed cluster's informers and their stop channels.
	informerStopChans map[string]chan struct{}

	// linseedTokenTargetNamespaces holds the names of namespaces where the Linseed token should be copied.
	linseedTokenTargetNamespaces []string

	initialReconciliationDelay *time.Duration

	// permissionMap tracks whether the managed cluster has permissions for Linseed to watch namespaces.
	permissionMap map[string]bool
}

type ReconcileAction int

const (
	ReconcileAll ReconcileAction = iota
	ReconcileTokens
	ReconcileSecrets
)

type ManagedClusterOperation string

const (
	ManagedClusterOperationCreate       ManagedClusterOperation = "create"
	ManagedClusterOperationDelete       ManagedClusterOperation = "delete"
	ManagedClusterOperationConnected    ManagedClusterOperation = "connected"
	ManagedClusterOperationDisconnected ManagedClusterOperation = "disconnected"
)

// tokenEvent represents an event indicating that tokens and optionally secrets should be reconciled based on the provided fields.
type tokenEvent struct {
	mc                      *v3.ManagedCluster
	namespace               string
	reconcileAction         ReconcileAction
	managedClusterOperation ManagedClusterOperation
}

func (c *controller) Run(stopCh <-chan struct{}) error {
	// TODO: Support multiple copies of this running.

	// Start a watch on ManagedClusters, wait for it to sync, and then proceed.
	// We'll trigger events whenever a new cluster is added, causing us to check whether
	// we need to provision token secrets in that cluster.
	logrus.Info("Starting token controller")

	// Make channels for sending updates.
	managedClusterChan := make(chan *tokenEvent, 100)
	secretChan := make(chan *corev1.Secret, 100)
	defer close(managedClusterChan)
	defer close(secretChan)

	managedClusterHandler := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			if mc, ok := obj.(*v3.ManagedCluster); ok {
				// Populate the deleteChan to remove the managed cluster entry from informerStopChans and permissionMap.
				managedClusterChan <- &tokenEvent{
					mc:                      mc,
					managedClusterOperation: ManagedClusterOperationDelete,
				}
			}
		},
		AddFunc: func(obj interface{}) {
			if mc, ok := obj.(*v3.ManagedCluster); ok && isConnected(mc) {
				mcObj := &tokenEvent{
					mc:                      mc,
					managedClusterOperation: ManagedClusterOperationCreate,
				}
				managedClusterChan <- mcObj
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if mc, ok := obj.(*v3.ManagedCluster); ok {
				mcObj := &tokenEvent{
					mc: mc,
				}
				if isConnected(mc) {
					mcObj.managedClusterOperation = ManagedClusterOperationConnected
				} else {
					mcObj.managedClusterOperation = ManagedClusterOperationDisconnected
				}
				managedClusterChan <- mcObj
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listWatcher := newManagedClusterListWatcher(ctx, c.client, c.namespace)
	mcInformer := cache.NewSharedIndexInformer(listWatcher, &v3.ManagedCluster{}, 0, cache.Indexers{})
	_, err := mcInformer.AddEventHandler(managedClusterHandler)
	if err != nil {
		logrus.WithError(err).Error("Failed to add ManagedCluster event handler")
		return err
	}

	secretFactory := informers.NewSharedInformerFactory(c.managementK8sClient, 0)
	secretInformer := secretFactory.Core().V1().Secrets().Informer()
	secretHandler := cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {}, // TODO: Clean up deleted secrets in the managed cluster
		AddFunc: func(obj interface{}) {
			if s, ok := obj.(*corev1.Secret); ok {
				for _, secret := range c.secretsToCopy {
					if s.Name == secret.Name && s.Namespace == secret.Namespace {
						secretChan <- s
						break
					}
				}
			}
		},
		UpdateFunc: func(_, obj interface{}) {
			if s, ok := obj.(*corev1.Secret); ok {
				for _, secret := range c.secretsToCopy {
					if s.Name == secret.Name && s.Namespace == secret.Namespace {
						secretChan <- s
						break
					}
				}
			}
		},
	}
	_, err = secretInformer.AddEventHandler(secretHandler)
	if err != nil {
		logrus.WithError(err).Error("Failed to add Secret event handler")
		return err
	}

	go mcInformer.Run(stopCh)
	go secretInformer.Run(stopCh)

	logrus.Info("Waiting for token controller to sync with ManagedCluster informer")
	for !mcInformer.HasSynced() {
		time.Sleep(1 * time.Second)
	}
	logrus.Info("Token controller has synced with ManagedCluster informer")

	logrus.Info("Waiting for token controller to sync with Secret informer")
	for !secretInformer.HasSynced() {
		time.Sleep(1 * time.Second)
	}
	logrus.Info("Token controller has synced with Secret informer")

	// Start the token manager.
	c.ManageTokens(
		stopCh,
		managedClusterChan,
		secretChan,
		mcInformer,
	)

	return nil
}

func isConnected(mc *v3.ManagedCluster) bool {
	for _, s := range mc.Status.Conditions {
		if s.Type == v3.ManagedClusterStatusTypeConnected {
			return s.Status == v3.ManagedClusterStatusValueTrue
		}
	}
	logrus.WithField("cluster", mc.Name).Debug("ManagedCluster is not connected")
	return false
}

func retryUpdate[T corev1.Secret | tokenEvent](rc *retryCalculator, id string, obj T, objChan chan *T, stop <-chan struct{}) {
	updateType := fmt.Sprintf("%T", obj)
	log := logrus.WithField(updateType, id)

	// Check if we should retry this update.
	retry, dur := rc.duration(id)
	if !retry {
		log.Warnf("Giving up on %s", updateType)
		return
	}

	// Schedule a retry.
	go func() {
		log.WithField("wait", dur).Infof("Scheduling retry for failed sync after %.0f seconds", dur.Seconds())
		time.Sleep(dur)

		// Use select to prevent accidentally sending to a closed channel if the controller initiated a shut down
		// while this routine was sleeping.
		select {
		case <-stop:
		default:
			objChan <- &obj
		}
	}()
}

func (c *controller) ManageTokens(stop <-chan struct{}, updateChan chan *tokenEvent, secretChan chan *corev1.Secret, mcInformer cache.SharedIndexInformer) {
	defer logrus.Info("Token manager shutting down")

	// reconcileChan handles reconcilation of tokens and secrets.
	reconcileChan := make(chan *tokenEvent, 2000)
	defer close(reconcileChan)

	ticker := time.After(*c.reconcilePeriod)
	rc := NewRetryCalculator(*c.baseRetryPeriod, *c.maxRetries)

	// Main loop.
	for {
		select {
		case <-stop:
			for _, mcStopCh := range c.informerStopChans {
				close(mcStopCh)
			}
			return
		case <-ticker:
			// ticker triggers reconcilation of tokens and secrets for all clusters at the reconcilePeriod interval, defaulting to 60 minutes.
			logrus.Debug("Reconciling tokens and copying secrets for all clusters")

			// Get all clusters.
			mcs := mcInformer.GetStore().List()

			// Start a new ticker.
			ticker = time.After(*c.reconcilePeriod)

			for _, obj := range mcs {
				mc, ok := obj.(*v3.ManagedCluster)
				if !ok {
					logrus.Warnf("Received unexpected type %T", obj)
					continue
				}
				if err := isValid(mc); err == nil && isConnected(mc) {
					// Queue managed cluster for reconciliation.
					reconcileChan <- &tokenEvent{
						mc: mc,
					}
				}
			}

			if c.reportHealth != nil {
				c.reportHealth(&health.HealthReport{Live: true, Ready: true})
			}
		case event := <-updateChan:
			log := c.loggerForManagedCluster(event.mc)

			switch event.managedClusterOperation {
			case ManagedClusterOperationDelete, ManagedClusterOperationDisconnected:
				c.deleteManagedCluster(event.mc.Name)
				continue
			case ManagedClusterOperationCreate, ManagedClusterOperationConnected:
				// updateChan triggers reconciliation of tokens and secrets, when a managed cluster is added or updated (connected or disconnected).
				retry := retryUpdate[tokenEvent]

				// Ensure cluster exists before proceeding with the reconciliation.
				// This prevents reconcilation of token and secrets for deleted managed clusters.
				if _, ok, _ := mcInformer.GetStore().Get(event.mc); !ok {
					log.Info("Managed cluster does not exist")
					continue
				}

				// Workaround to handle version skew where older managed clusters (<=3.19) might lack RBAC permissions to watch namespaces.
				// TODO: cleanup this workaround around the 3.22 release.
				hasPermission, err := c.supportNamespaceWatches(event.mc)
				if err != nil {
					log.WithError(err).Error("failed to check if namespace RBAC exist on the managed cluster")
					retry(rc, event.mc.Name, *event, updateChan, stop)
					continue
				}

				newEvent := &tokenEvent{
					mc: event.mc,
				}

				// Check if the managed cluster has the required RBAC for Linseed to access its namespaces.
				if hasPermission {
					if _, exist := c.informerStopChans[event.mc.Name]; !exist {
						// Create managed cluster informer if it does not exist.
						// This would trigger reconciliation of tokens for all relevant namespaces.
						namespaceInformer, err := c.createInformer(event.mc, reconcileChan)
						if err != nil {
							log.WithError(err).Error("failed to create namespace informer")
							continue
						}
						// Track the informers to clean up when the managed cluster is deleted.
						mcStopCh := make(chan struct{})
						c.informerStopChans[event.mc.Name] = mcStopCh
						err = namespaceInformer.SetWatchErrorHandler(func(r *cache.Reflector, err error) {
							log.WithError(err).Errorf("Watch for %v failed ", r.TypeDescription())
						})
						if err != nil {
							log.WithError(err).Error("failed to create watch error cluster informer")
							return
						}
						go namespaceInformer.Run(mcStopCh)

						// The informer creation will handle token reconciliation within the managed clusters.
						// Now trigger an event to reconcile only the secrets.
						newEvent.reconcileAction = ReconcileSecrets
					}

				}

				reconcileChan <- newEvent
			}

		case event := <-reconcileChan:
			retry := retryUpdate[tokenEvent]
			log := c.loggerForManagedCluster(event.mc)

			// Ensure cluster exists before proceeding with the reconciliation.
			if _, ok, _ := mcInformer.GetStore().Get(event.mc); !ok {
				log.Info("Manager cluster does not exist")
				continue
			}

			managedClient, err := c.factory.Impersonate(c.impersonationInfo).NewClientSetForApplication(event.mc.Name)
			if err != nil {
				log.WithError(err).Error("failed to get client for cluster")
				retry(rc, event.mc.Name, *event, updateChan, stop)
				continue
			}

			var needRetry bool
			if event.reconcileAction == ReconcileTokens || event.reconcileAction == ReconcileAll {
				if err = c.reconcileTokensForCluster(event.mc, managedClient, event.namespace); err != nil {
					log.WithError(err).Error("failed to reconcile tokens for cluster")
					needRetry = true
				}
			}

			if event.reconcileAction == ReconcileSecrets || event.reconcileAction == ReconcileAll {
				if err = c.reconcileSecretsForCluster(event.mc, c.secretsToCopy, managedClient); err != nil {
					log.WithError(err).Error("failed to reconcile secrets for cluster")
					needRetry = true
				}
			}

			// Use single retry when either or both of them fails.
			if needRetry {
				retry(rc, event.mc.Name, *event, reconcileChan, stop)
			}
		case secret := <-secretChan:
			retry := retryUpdate[corev1.Secret]

			// Get all clusters.
			mcs := mcInformer.GetStore().List()

			for _, obj := range mcs {
				mc, ok := obj.(*v3.ManagedCluster)
				if !ok {
					logrus.Warnf("Received unexpected type %T", obj)
					continue
				}
				log := c.loggerForManagedCluster(mc)

				managedClient, err := c.factory.Impersonate(c.impersonationInfo).NewClientSetForApplication(mc.Name)
				if err != nil {
					log.WithError(err).Error("failed to get client for cluster")
					retry(rc, fmt.Sprintf("%s/%s", secret.Namespace, secret.Name), *secret, secretChan, stop)
					continue
				}

				if err = c.reconcileSecretsForCluster(mc, []corev1.Secret{*secret}, managedClient); err != nil {
					log.WithError(err).Error("failed to reconcile secrets for cluster")
					retry(rc, fmt.Sprintf("%s/%s", secret.Namespace, secret.Name), *secret, secretChan, stop)
				}
			}
		}
	}
}

func (c *controller) deleteManagedCluster(mcName string) {
	// Stop the informers when the managed clusters get deleted.
	if mcStopCh, ok := c.informerStopChans[mcName]; ok {
		close(mcStopCh)
		delete(c.informerStopChans, mcName)
		logrus.WithField("name", mcName).Info("removed informer for the deleted/disconnected managed cluster")
	}

	// Remove the entry from permissionMap.
	if _, ok := c.permissionMap[mcName]; ok {
		delete(c.permissionMap, mcName)
		logrus.WithField("name", mcName).Info("removed permissionMap entry for the deleted/disconnected managed cluster")
	}
}

func NewRetryCalculator(start time.Duration, maxRetries int) *retryCalculator {
	return &retryCalculator{
		startDuration:      start,
		maxRetries:         maxRetries,
		outstandingRetries: map[string]time.Duration{},
		numRetries:         map[string]int{},
	}
}

type retryCalculator struct {
	startDuration      time.Duration
	outstandingRetries map[string]time.Duration
	numRetries         map[string]int
	maxRetries         int
}

// duration returns the next duration to use when retrying the given key.
// after a max number of retries, it will return (false, 0) to indicate that we should give up.
func (r *retryCalculator) duration(key string) (bool, time.Duration) {
	fields := logrus.Fields{"numRetries": r.numRetries[key], "maxRetries": r.maxRetries}
	logrus.WithFields(fields).Debugf("retryCalulator getting duration")
	if r.numRetries[key] >= r.maxRetries {
		// Give up.
		delete(r.numRetries, key)
		delete(r.outstandingRetries, key)
		return false, 0 * time.Second
	}
	r.numRetries[key]++

	if d, ok := r.outstandingRetries[key]; ok {
		// Double the duration, up to a maximum of 1 minute.
		d = d * 2
		if d > 1*time.Minute {
			d = 1 * time.Minute
		}
		r.outstandingRetries[key] = d
		return true, d
	} else {
		// First time we've seen this key.
		d = r.startDuration
		r.outstandingRetries[key] = d
		return true, d
	}
}

func isValid(mc *v3.ManagedCluster) error {
	if mc.Name == "" {
		return errors.New("empty cluster name given")
	}

	return nil
}

func (c *controller) loggerForManagedCluster(mc *v3.ManagedCluster) *logrus.Entry {
	name := mc.Name
	if mc.Namespace != "" {
		name = fmt.Sprintf("%s/%s", mc.Namespace, mc.Name)
	}

	logger := logrus.WithField("cluster", name)

	if c.tenant != "" {
		logger = logger.WithField("tenant", c.tenant)
	}

	return logger
}

// reconcileTokens reconciles tokens. This is a hack and should be moved to its own location.
func (c *controller) reconcileTokensForCluster(mc *v3.ManagedCluster, managedClient kubernetes.Interface, mcNamespace string) error {
	log := c.loggerForManagedCluster(mc)

	if err := isValid(mc); err != nil {
		return err
	} else if !isConnected(mc) {
		log.Debug("ManagedCluster not connected, skipping")
		return nil
	}

	var tokenErrors []error
	for _, user := range c.userInfos {
		log = log.WithField("service", user.Name)

		// If mcNamespace is specified, copy tokens only for those namespaces, otherwise skip.
		if len(mcNamespace) > 0 && user.Namespace != mcNamespace {
			continue
		}

		// Skip the namespace check if Linseed does not have the required permissions to watch the managed cluster's namespace.
		if c.permissionMap[mc.Name] {
			// Check if the namespace exists before copying the token.
			exists, err := namespaceExists(managedClient, user.Namespace)
			if err != nil {
				log.WithError(err).Error("error checking namespace exists")
				tokenErrors = append(tokenErrors, err)
				continue
			}
			if !exists {
				log.Warn("Manged cluster does not have the Namespace:", user.Namespace)
				continue
			}
		}

		// First, check if token exists. If it does, we don't need to do anything.
		tokenName := c.tokenNameForService(user.Name)
		if update, err := c.needsUpdate(log, managedClient, mc.Name, tokenName, user); err != nil {
			log.WithError(err).Error("error checking token")
			tokenErrors = append(tokenErrors, err)
			continue
		} else if !update {
			log.Debug("Token does not need to be updated")
			continue
		}

		// Token needs to be created or updated.
		token, err := c.createToken(c.tenant, mc.Name, user)
		if err != nil {
			log.WithError(err).Error("error creating token")
			tokenErrors = append(tokenErrors, err)
			continue
		}

		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      tokenName,
				Namespace: user.Namespace,
			},
			Data: map[string][]byte{
				"token": token,
			},
		}

		if err = resource.WriteSecretToK8s(managedClient, resource.CopySecret(&secret)); err != nil {
			log.WithError(err).Error("error copying secrets")
			tokenErrors = append(tokenErrors, err)
			continue
		}
		log.WithField("name", secret.Name).Info("Created/updated token secret")
	}
	return errors.Join(tokenErrors...)
}

func (c *controller) reconcileSecretsForCluster(mc *v3.ManagedCluster, secretsToCopy []corev1.Secret, managedClient k8s.ClientSet) error {
	log := c.loggerForManagedCluster(mc)

	if err := isValid(mc); err != nil {
		return err
	} else if !isConnected(mc) {
		log.Debug("ManagedCluster not connected, skipping")
		return nil
	}

	var secretErrors []error
	for _, s := range secretsToCopy {
		secret, err := c.managementK8sClient.CoreV1().Secrets(s.Namespace).Get(context.Background(), s.Name, metav1.GetOptions{})
		if err != nil {
			log.WithError(err).Errorf("Error retrieving secret %v in namespace %v", s.Name, s.Namespace)
			secretErrors = append(secretErrors, err)
			continue
		}

		managedOperatorNS, err := utils.FetchOperatorNamespace(managedClient)
		if err != nil {
			log.WithError(err).Error("Unable to fetch managed cluster operator namespace")
			secretErrors = append(secretErrors, err)
			continue
		}

		secret.Namespace = managedOperatorNS
		if err = resource.WriteSecretToK8s(managedClient, resource.CopySecret(secret)); err != nil {
			log.WithError(err).Error("Error writing secret to managed cluster")
			secretErrors = append(secretErrors, err)
			continue
		}
		log.WithFields(logrus.Fields{
			"name":      secret.Name,
			"namespace": secret.Namespace,
		}).Debug("Copied secret to managed cluster")

		// The name of the voltron linseed cert has changed in newer releases (after Calico Enterprise v3.23). To not
		// break functionality on older managed clusters that still expect to find the secret with the old name we need
		// to copy both the newly named cert and the legacy named cert into the managed cluster. This logic can be removed
		// in v3.26 when we no longer support versions that use the legacy named cert. The standard cert copy happens above
		// while we handle the additional legacy copy here as a special case
		if secret.Name == resource.VoltronLinseedPublicCert {
			legacyCopy := resource.CopySecret(secret)
			legacyCopy.Name = resource.LegacyVoltronLinseedPublicCert
			if err = resource.WriteSecretToK8s(managedClient, legacyCopy); err != nil {
				log.WithError(err).Error("Error writing secret to managed cluster")
				secretErrors = append(secretErrors, err)
				continue
			}
			log.WithFields(logrus.Fields{
				"name":      legacyCopy.Name,
				"namespace": legacyCopy.Namespace,
			}).Debug("Copied secret to managed cluster")
		}

	}
	err := errors.Join(secretErrors...)

	if err == nil {
		log.Debug("Successfully copied all secrets")
	}

	return err
}

func (c *controller) tokenNameForService(service string) string {
	// Secret names should be identified by:
	// - The issuer of the token
	// - The service the token is being created for
	return fmt.Sprintf("%s-%s-token", service, c.issuerName)
}

func (c *controller) needsUpdate(log *logrus.Entry, cs kubernetes.Interface, mcName, tokenName string, user UserInfo) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cm, err := cs.CoreV1().Secrets(user.Namespace).Get(ctx, tokenName, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		// Error querying the token.
		return false, err
	} else if k8serrors.IsNotFound(err) {
		// No token exists.
		return true, nil
	} else {
		// Validate the token to make sure it was signed by us.
		tokenBytes := []byte(cm.Data["token"])
		_, err = jwt.ParseWithClaims(string(tokenBytes), &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
			return c.privateKey.Public(), nil
		})
		if err != nil {
			// If the token is not signed by us, we should replace it. This covers two cases:
			// - User has manually specified a new invalid token in the secret.
			// - We're using a new cert to sign tokens, invalidating any and all tokens that we
			//   had previously distributed to clients.
			log.WithError(err).Warn("Could not authenticate token")
			return true, nil
		}

		// Parse the token to get its expiry.
		tkn, err := jws.ParseJWT(tokenBytes)
		if err != nil {
			log.WithError(err).Warn("failed to parse token")
			return true, nil
		}
		expiry, exists := tkn.Claims().Expiration()
		if !exists {
			log.Info("token has no expiration data present")
			return true, nil
		}

		// Refresh the token if the time between the expiry and now
		// is less than 2/3 of the total expiry time.
		dur := 2 * c.expiry / 3
		if time.Until(expiry) < dur {
			log.Info("token needs to be refreshed")
			return true, nil
		}

		// Check if the token's subject field is correct for this ManagedCluster.
		subject, exists := tkn.Claims().Subject()
		if !exists {
			log.Debug("token has no subject data present")
			return true, nil
		}

		expectedSubject := GenerateSubjectLinseed(c.tenant, mcName, user.Namespace, user.Name, user.TenantNamespaceOverride)

		if subject != expectedSubject {
			log.Debugf("token subject (%v) does not match expected subject (%v)", subject, expectedSubject)
			return true, nil
		}
	}
	return false, nil
}

func (c *controller) createToken(tenant, cluster string, user UserInfo) ([]byte, error) {
	tokenLifetime := c.expiry
	if tokenLifetime == 0 {
		tokenLifetime = defaultTokenLifetime
	}
	expirationTime := time.Now().Add(tokenLifetime)

	// Subject is a combination of tenantID, clusterID, and service name.
	subj := GenerateSubjectLinseed(tenant, cluster, user.Namespace, user.Name, user.TenantNamespaceOverride)

	claims := &jwt.RegisteredClaims{
		Subject:   subj,
		Issuer:    c.issuer,
		Audience:  jwt.ClaimStrings{c.issuerName},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(expirationTime),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(c.privateKey)
	if err != nil {
		return nil, err
	}
	return []byte(tokenString), err
}

func ParseSubjectLinseed(subject string) (tenant, cluster, namespace, name string, err error) {
	splits := strings.Split(subject, ":")
	if len(splits) != 4 {
		return "", "", "", "", fmt.Errorf("bad subject")
	}
	return splits[0], splits[1], splits[2], splits[3], nil
}

func GenerateSubjectLinseed(tenant, cluster, namespace, name, namespaceOverride string) string {
	serviceAccountNamespace := namespace
	if namespaceOverride != "" {
		serviceAccountNamespace = namespaceOverride
	}
	return fmt.Sprintf("%s:%s:%s:%s", tenant, cluster, serviceAccountNamespace, name)
}

// ParseClaimsLinseed implements ClaimParser for token claims generated by Linseed.
func ParseClaimsLinseed(claims jwt.Claims) (*user.DefaultInfo, error) {
	reg, ok := claims.(*jwt.RegisteredClaims)
	if !ok {
		logrus.WithField("claims", claims).Warn("given claims were not a RegisteredClaims")
		return nil, fmt.Errorf("invalid claims given")
	}
	_, _, namespace, name, err := ParseSubjectLinseed(reg.Subject)
	if err != nil {
		return nil, err
	}
	return &user.DefaultInfo{Name: fmt.Sprintf("system:serviceaccount:%s:%s", namespace, name)}, nil
}

// newManagedClusterListWatcher returns an implementation of the ListWatch interface capable of being used to
// build an informer based on a controller-runtime client. Using the controller-runtime client allows us to build
// an Informer that works for both namespaced and cluster-scoped ManagedCluster resources regardless of whether
// it is a multi-tenant cluster or not.
func newManagedClusterListWatcher(ctx context.Context, c ctrlclient.WithWatch, namespace string) *cache.ListWatch {
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

func namespaceExists(c kubernetes.Interface, namespace string) (bool, error) {
	_, err := c.CoreV1().Namespaces().Get(context.Background(), namespace, metav1.GetOptions{})
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("error looking for the Namespace: %s, %w", namespace, err)
	}
	return true, nil
}

func (c *controller) createInformer(mc *v3.ManagedCluster, reconcileChan chan *tokenEvent) (cache.SharedIndexInformer, error) {

	managedClient, err := c.factory.Impersonate(c.impersonationInfo).NewClientSetForApplication(mc.Name)
	if err != nil {
		logrus.WithError(err).Error("failed to get client for cluster")
		return nil, err
	}

	// Create a namespace informer for the managed cluster.
	namespaceFactory := informers.NewSharedInformerFactory(managedClient, 0)
	namespaceInformer := namespaceFactory.Core().V1().Namespaces().Informer()
	namespaceHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if ns, ok := obj.(*corev1.Namespace); ok {
				if c.isRelevantNamespace(ns.Name) {
					// Populate the reconcileChan channel to copy the tokens when a namespace is created in the managed cluster.
					newtokenEvent := &tokenEvent{
						mc:              mc,
						namespace:       ns.Name,
						reconcileAction: ReconcileTokens,
					}
					go func(newtokenEvent *tokenEvent) {
						// Wait a moment before sending the event to allow RBAC resources to be created
						// before we attempt to access the namespace.
						time.Sleep(*c.initialReconciliationDelay)
						reconcileChan <- newtokenEvent
					}(newtokenEvent)
				}
			}
		},
		UpdateFunc: func(_, obj interface{}) {},
		DeleteFunc: func(obj interface{}) {},
	}

	_, err = namespaceInformer.AddEventHandler(namespaceHandler)
	if err != nil {
		logrus.WithError(err).Error("failed to add managed cluster namespace event handler")
		return nil, err
	}
	return namespaceInformer, nil
}

func (c *controller) isRelevantNamespace(namespace string) bool {
	for _, ns := range c.linseedTokenTargetNamespaces {
		if ns == namespace {
			return true
		}
	}
	return false
}

func (c *controller) supportNamespaceWatches(mc *v3.ManagedCluster) (bool, error) {
	managedClient, err := c.factory.Impersonate(c.impersonationInfo).NewClientSetForApplication(mc.Name)
	if err != nil {
		return false, err
	}

	_, err = managedClient.CoreV1().Namespaces().Get(context.Background(), resource.ComplianceNamespace, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		if k8serrors.IsForbidden(err) {
			// Managed clusters older than v3.20 will not have the required RBAC for Linseed to fetch namespaces.
			c.permissionMap[mc.Name] = false
			return false, nil
		}
		return false, fmt.Errorf("error fetch namespace from the managed cluster: %w", err)
	}

	// If we do not encounter a "Forbidden error", then the managed cluster is version 3.20 or later and has the required RBAC for Linseed to fetch namespaces.
	c.permissionMap[mc.Name] = true
	return true, nil
}
