// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.

package felixsyncer_test

import (
	"context"
	"os"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	kapiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	. "github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/felixsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/remotecluster"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("Remote cluster syncer tests - connection failures", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	var err error
	var c clientv3.Interface
	var be api.Client
	var syncer api.Syncer
	var syncTester *testutils.SyncerTester
	var filteredSyncerTester api.SyncerCallbacks
	var cs kubernetes.Interface

	BeforeEach(func() {
		// Create the v3 client
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		// Create the backend client to clean the datastore and obtain a syncer interface.
		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// build k8s clientset.
		cfg, err := clientcmd.BuildConfigFromFlags("", "/kubeconfig.yaml")
		Expect(err).NotTo(HaveOccurred())
		cs = kubernetes.NewForConfigOrDie(cfg)
	})

	AfterEach(func() {
		if syncer != nil {
			syncer.Stop()
			syncer = nil
		}
		if be != nil {
			be.Close()
			be = nil
		}
	})

	DescribeTable("Configuring a RemoteClusterConfiguration resource with",
		func(name string, spec apiv3.RemoteClusterConfigurationSpec,
			errPrefix string, connTimeout time.Duration) {
			By("Creating the RemoteClusterConfiguration")
			_, outError := c.RemoteClusterConfigurations().Create(ctx, &apiv3.RemoteClusterConfiguration{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
				Spec: spec,
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())

			By("Creating and starting a syncer")
			syncTester = testutils.NewSyncerTester()
			filteredSyncerTester = NewRemoteClusterConnFailedFilter(NewValidationFilter(syncTester))
			syncer = New(be, config.Spec, filteredSyncerTester, false, true)
			syncer.Start()

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectStatusUpdate(api.InSync, connTimeout)

			By("Checking we received the event messages for the remote cluster")
			// We should receive Connecting and ConnectionFailed
			expectedEvents := []api.Update{
				{
					KVPair: model.KVPair{
						Key: model.RemoteClusterStatusKey{Name: name},
						Value: &model.RemoteClusterStatus{
							Status: model.RemoteClusterConnecting,
						},
					},
					UpdateType: api.UpdateTypeKVNew,
				},
			}
			defaultCacheEntries := calculateDefaultFelixSyncerEntries(cs, config.Spec.DatastoreType)
			for _, r := range defaultCacheEntries {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair:     r,
					UpdateType: api.UpdateTypeKVNew,
				})
			}

			expectedEvents = append(expectedEvents, api.Update{
				KVPair: model.KVPair{
					Key: model.RemoteClusterStatusKey{Name: name},
					Value: &model.RemoteClusterStatus{
						Status: model.RemoteClusterConnectionFailed,
						Error:  errPrefix,
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			})

			err = syncTester.HasUpdates(expectedEvents, false)
			Expect(err).NotTo(HaveOccurred())
		},

		// An invalid etcd endpoint takes the configured dial timeout to fail (10s), so let's wait for at least 15s
		// for the test.
		Entry("invalid etcd endpoint", "bad-etcdv3-1",
			apiv3.RemoteClusterConfigurationSpec{
				DatastoreType: "etcdv3",
				EtcdConfig: apiv3.EtcdConfig{
					EtcdEndpoints: "http://foobarbaz:1000",
				},
			},
			".*context deadline exceeded.*", 15*time.Second,
		),

		Entry("invalid etcd cert files", "bad-etcdv3-2",
			apiv3.RemoteClusterConfigurationSpec{
				DatastoreType: "etcdv3",
				EtcdConfig: apiv3.EtcdConfig{
					EtcdEndpoints:  "https://127.0.0.1:2379",
					EtcdCertFile:   "foo",
					EtcdCACertFile: "bar",
					EtcdKeyFile:    "baz",
				},
			},
			".*could not initialize etcdv3 client: open foo: no such file or directory.*", 3*time.Second,
		),

		Entry("invalid k8s endpoint", "bad-k8s-1",
			apiv3.RemoteClusterConfigurationSpec{
				DatastoreType: "kubernetes",
				KubeConfig: apiv3.KubeConfig{
					K8sAPIEndpoint: "http://foobarbaz:1000",
				},
			},
			".*dial tcp: lookup foobarbaz on.*", 15*time.Second,
		),

		Entry("invalid k8s kubeconfig file - retry for 30s before failing connection", "bad-k8s2",
			apiv3.RemoteClusterConfigurationSpec{
				DatastoreType: "kubernetes",
				KubeConfig: apiv3.KubeConfig{
					Kubeconfig: "foobarbaz",
				},
			},
			".*stat foobarbaz: no such file or directory.*", 15*time.Second,
		),
	)

	Describe("Deleting a RemoteClusterConfiguration before connection fails", func() {
		It("should get a delete event without getting a connection failure event", func() {
			// Create a RemoteClusterConfiguration with a bad etcd endpoint - this takes a little while to timeout
			// which gives us time to delete the RemoteClusterConfiguration before we actually get the connection
			// failure notification.
			By("Creating the RemoteClusterConfiguration")
			rcc, outError := c.RemoteClusterConfigurations().Create(ctx, &apiv3.RemoteClusterConfiguration{
				ObjectMeta: metav1.ObjectMeta{Name: "etcd-timeout"},
				Spec: apiv3.RemoteClusterConfigurationSpec{
					DatastoreType: "etcdv3",
					EtcdConfig: apiv3.EtcdConfig{
						EtcdEndpoints: "http://foobarbaz:1000",
					},
				},
			}, options.SetOptions{})
			Expect(outError).NotTo(HaveOccurred())

			By("Creating and starting a syncer")
			syncTester = testutils.NewSyncerTester()
			filteredSyncerTester = NewRemoteClusterConnFailedFilter(NewValidationFilter(syncTester))
			syncer = New(be, config.Spec, filteredSyncerTester, false, true)
			syncer.Start()

			By("Checking status is updated to resync in progress")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)

			By("Checking we received the event messages for the remote cluster")
			// We should receive Connecting event first.
			expectedEvents := []api.Update{
				{
					KVPair: model.KVPair{
						Key: model.RemoteClusterStatusKey{Name: "etcd-timeout"},
						Value: &model.RemoteClusterStatus{
							Status: model.RemoteClusterConnecting,
						},
					},
					UpdateType: api.UpdateTypeKVNew,
				},
			}

			defaultCacheEntries := calculateDefaultFelixSyncerEntries(cs, config.Spec.DatastoreType)
			for _, r := range defaultCacheEntries {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair:     r,
					UpdateType: api.UpdateTypeKVNew,
				})
			}

			syncTester.ExpectUpdates(expectedEvents, false)

			By("Deleting the RemoteClusterConfiguration")
			_, err = c.RemoteClusterConfigurations().Delete(ctx, "etcd-timeout", options.DeleteOptions{ResourceVersion: rcc.ResourceVersion})
			Expect(err).NotTo(HaveOccurred())

			By("Expecting the syncer to move quickly to in-sync")
			syncTester.ExpectStatusUpdate(api.InSync)

			By("Checking we received the delete event messages for the remote cluster")
			expectedDeleteEvents := []api.Update{
				{
					KVPair: model.KVPair{
						Key: model.RemoteClusterStatusKey{Name: "etcd-timeout"},
					},
					UpdateType: api.UpdateTypeKVDeleted,
				},
			}
			syncTester.ExpectUpdates(expectedDeleteEvents, false)
		})
	})
})

var _ = testutils.E2eDatastoreDescribe("Remote cluster syncer tests - datastore configurations", testutils.DatastoreEtcdV3, func(etcdConfig apiconfig.CalicoAPIConfig) {
	testutils.E2eDatastoreDescribe("", testutils.DatastoreK8s, func(k8sConfig apiconfig.CalicoAPIConfig) {
		rccName := "remote-cluster"
		rccSecretName := "remote-cluster-config"

		var ctx context.Context
		var err error
		var localClient clientv3.Interface
		var localBackend api.Client
		var remoteBackend api.Client
		var syncer api.Syncer
		var syncTester *testutils.SyncerTester
		var filteredSyncerTester api.SyncerCallbacks
		var remoteClient clientv3.Interface
		var k8sClientset *kubernetes.Clientset
		var remoteConfig apiconfig.CalicoAPIConfig
		var localConfig apiconfig.CalicoAPIConfig
		var expectedEvents []api.Update
		var deleteEvents []api.Update
		var cs kubernetes.Interface
		var k8sInlineConfig apiconfig.CalicoAPIConfig
		var rcc *apiv3.RemoteClusterConfiguration
		var restartCallbackCalled bool
		var restartCallbackMsg string

		BeforeEach(func() {
			k8sClient, err := clientv3.New(k8sConfig)
			Expect(err).NotTo(HaveOccurred())
			_, _ = k8sClient.HostEndpoints().Delete(context.Background(), "hep1", options.DeleteOptions{})
			etcdClient, err := clientv3.New(etcdConfig)
			Expect(err).NotTo(HaveOccurred())
			_, _ = etcdClient.HostEndpoints().Delete(context.Background(), "hep1", options.DeleteOptions{})

			// build k8s clientset.
			cfg, err := clientcmd.BuildConfigFromFlags("", "/kubeconfig.yaml")
			Expect(err).NotTo(HaveOccurred())
			cs = kubernetes.NewForConfigOrDie(cfg)

			// Get the k8s inline config that we use for testing.
			k8sInlineConfig = testutils.GetK8sInlineConfig()
		})
		AfterEach(func() {
			By("doing aftereach")
			if syncer != nil {
				syncer.Stop()
				syncer = nil
			}
			if localBackend != nil {
				localBackend.Clean()
				localBackend.Close()
				localBackend = nil
			}
			if remoteBackend != nil {
				remoteBackend.Clean()
				remoteBackend.Close()
				remoteBackend = nil
			}
			if k8sClientset != nil {
				_ = k8sClientset.CoreV1().Secrets("namespace-1").Delete(ctx, rccSecretName, metav1.DeleteOptions{})
			}
			if remoteClient != nil {
				_, _ = remoteClient.HostEndpoints().Delete(ctx, "hep1", options.DeleteOptions{})
			}
			By("done with aftereach")
		})

		rccInitialEvents := []api.Update{
			{
				KVPair: model.KVPair{
					Key: model.RemoteClusterStatusKey{Name: "remote-cluster"},
					Value: &model.RemoteClusterStatus{
						Status: model.RemoteClusterConnecting,
					},
				},
				UpdateType: api.UpdateTypeKVNew,
			},
			{
				KVPair: model.KVPair{
					Key: model.RemoteClusterStatusKey{Name: "remote-cluster"},
					Value: &model.RemoteClusterStatus{
						Status: model.RemoteClusterResyncInProgress,
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			},
			{
				KVPair: model.KVPair{
					Key: model.RemoteClusterStatusKey{Name: "remote-cluster"},
					Value: &model.RemoteClusterStatus{
						Status: model.RemoteClusterInSync,
					},
				},
				UpdateType: api.UpdateTypeKVUpdated,
			},
		}

		setup := func(local, remote *apiconfig.CalicoAPIConfig, mode apiv3.OverlayRoutingMode) {
			localConfig = *local
			remoteConfig = *remote
			ctx = context.Background()
			log.SetLevel(log.DebugLevel)
			// Create the v3 clients for the local and remote clusters.
			localClient, err = clientv3.New(localConfig)
			Expect(err).NotTo(HaveOccurred())
			remoteClient, err = clientv3.New(remoteConfig)
			Expect(err).NotTo(HaveOccurred())

			// Create the local backend client to clean the datastore and obtain a syncer interface.
			localBackend, err = backend.NewClient(localConfig)
			Expect(err).NotTo(HaveOccurred())
			localBackend.Clean()

			// Create the remote backend client to clean the datastore.
			remoteBackend, err = backend.NewClient(remoteConfig)
			Expect(err).NotTo(HaveOccurred())
			remoteBackend.Clean()

			k8sBackend, err := backend.NewClient(k8sConfig)
			Expect(err).NotTo(HaveOccurred())
			k8sClientset = k8sBackend.(*k8s.KubeClient).ClientSet
			expectedEvents = []api.Update{}
			deleteEvents = []api.Update{}

			// Get the default cache entries for the local cluster.
			defaultCacheEntries := calculateDefaultFelixSyncerEntries(cs, local.Spec.DatastoreType)
			for _, r := range defaultCacheEntries {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair:     r,
					UpdateType: api.UpdateTypeKVNew,
				})
			}
			// Get the default entries for the remote cluster.
			defaultCacheEntries = calculateDefaultFelixSyncerEntries(cs, remote.Spec.DatastoreType, felixSyncerRemote{name: "remote-cluster", mode: mode})
			for _, r := range defaultCacheEntries {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair:     r,
					UpdateType: api.UpdateTypeKVNew,
				})

				deleteEvents = append(deleteEvents, api.Update{
					KVPair:     model.KVPair{Key: r.Key, Value: nil},
					UpdateType: api.UpdateTypeKVDeleted,
				})
			}
			// Add the RCC initial events.
			expectedEvents = append(expectedEvents, rccInitialEvents...)
		}

		type createFunc func()
		type modifyFunc func()
		type noOpFunc func()
		type invalidateFunc func()

		// createRCCDirect creates an RCC with the configuration in the RCC from the remoteConfig
		createRCCDirect := func(mode apiv3.OverlayRoutingMode) func() {
			return func() {
				By("Creating direct RemoteClusterConfiguration")
				rcc = &apiv3.RemoteClusterConfiguration{ObjectMeta: metav1.ObjectMeta{Name: rccName}}
				rcc.Spec.DatastoreType = string(remoteConfig.Spec.DatastoreType)
				rcc.Spec.EtcdEndpoints = remoteConfig.Spec.EtcdEndpoints
				rcc.Spec.EtcdUsername = remoteConfig.Spec.EtcdUsername
				rcc.Spec.EtcdPassword = remoteConfig.Spec.EtcdPassword
				rcc.Spec.EtcdKeyFile = remoteConfig.Spec.EtcdKeyFile
				rcc.Spec.EtcdCertFile = remoteConfig.Spec.EtcdCertFile
				rcc.Spec.EtcdCACertFile = remoteConfig.Spec.EtcdCACertFile
				rcc.Spec.Kubeconfig = remoteConfig.Spec.Kubeconfig
				rcc.Spec.K8sAPIEndpoint = remoteConfig.Spec.K8sAPIEndpoint
				rcc.Spec.K8sKeyFile = remoteConfig.Spec.K8sKeyFile
				rcc.Spec.K8sCertFile = remoteConfig.Spec.K8sCertFile
				rcc.Spec.K8sCAFile = remoteConfig.Spec.K8sCAFile
				rcc.Spec.K8sAPIToken = remoteConfig.Spec.K8sAPIToken
				rcc.Spec.K8sInsecureSkipTLSVerify = remoteConfig.Spec.K8sInsecureSkipTLSVerify
				rcc.Spec.KubeconfigInline = remoteConfig.Spec.KubeconfigInline
				rcc.Spec.SyncOptions.OverlayRoutingMode = mode
				_, outError := localClient.RemoteClusterConfigurations().Create(ctx, rcc, options.SetOptions{})
				Expect(outError).NotTo(HaveOccurred())
			}
		}

		// modifyRCCDirect updates the already created RCC with a change, not creating a valid config
		// but that should be fine for using it to test what happens when a valid RCC is updated
		modifyRCCDirect := func() {
			By("Modifying direct RemoteClusterConfiguration")
			r, err := localClient.RemoteClusterConfigurations().Get(ctx, rccName, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			if remoteConfig.Spec.DatastoreType == apiconfig.Kubernetes {
				r.Spec.Kubeconfig = "notreal"
			} else {
				r.Spec.EtcdUsername = "fakeusername"
			}
			_, err = localClient.RemoteClusterConfigurations().Update(ctx, r, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		// createRCCSecret creates a secret and an RCC that references the secret, both based on the remoteConfig
		createRCCSecret := func(mode apiv3.OverlayRoutingMode) func() {
			return func() {
				By("Creating secret for the RemoteClusterConfiguration")
				_, err = k8sClientset.CoreV1().Secrets("namespace-1").Create(ctx,
					&kapiv1.Secret{
						ObjectMeta: metav1.ObjectMeta{Name: rccSecretName, Namespace: "namespace-1"},
						StringData: map[string]string{
							"datastoreType": string(remoteConfig.Spec.DatastoreType),
							"kubeconfig":    remoteConfig.Spec.KubeconfigInline,
							"etcdEndpoints": remoteConfig.Spec.EtcdEndpoints,
							"etcdUsername":  remoteConfig.Spec.EtcdUsername,
							"etcdPassword":  remoteConfig.Spec.EtcdPassword,
							"etcdKey":       remoteConfig.Spec.EtcdKey,
							"etcdCert":      remoteConfig.Spec.EtcdCert,
							"etcdCACert":    remoteConfig.Spec.EtcdCACert,
						},
					},
					metav1.CreateOptions{})
				Expect(err).NotTo(HaveOccurred())

				By("Configuring the RemoteClusterConfiguration referencing secret")
				rcc = &apiv3.RemoteClusterConfiguration{ObjectMeta: metav1.ObjectMeta{Name: rccName}}
				rcc.Spec.ClusterAccessSecret = &kapiv1.ObjectReference{
					Kind:      reflect.TypeFor[kapiv1.Secret]().String(),
					Namespace: "namespace-1",
					Name:      rccSecretName,
				}
				rcc.Spec.SyncOptions.OverlayRoutingMode = mode
				_, outError := localClient.RemoteClusterConfigurations().Create(ctx, rcc, options.SetOptions{})
				Expect(outError).NotTo(HaveOccurred())
			}
		}

		// modifyRCCSecret modifies an already created Secret that is referenced by an RCC
		modifyRCCSecret := func() {
			By("Modifying RCC Secret RemoteClusterConfiguration")
			s, err := k8sClientset.CoreV1().Secrets("namespace-1").Get(ctx, rccSecretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			if remoteConfig.Spec.DatastoreType == apiconfig.Kubernetes {
				s.StringData = map[string]string{"kubeconfig": "notreal"}
			} else {
				s.StringData = map[string]string{"etcdPassword": "fakeusername"}
			}
			_, err = k8sClientset.CoreV1().Secrets("namespace-1").Update(ctx, s, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		// noOpUpdateRCCDirect reapplies the same RCC config
		noOpUpdateRCCDirect := func() {
			By("Applying no-op update to direct RemoteClusterConfiguration")
			r, err := localClient.RemoteClusterConfigurations().Get(ctx, rccName, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = localClient.RemoteClusterConfigurations().Update(ctx, r, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		// noOpRCCSecret reapplies the same RCC secret
		noOpRCCSecret := func() {
			By("Applying no-op update to RCC Secret RemoteClusterConfiguration")
			s, err := k8sClientset.CoreV1().Secrets("namespace-1").Get(ctx, rccSecretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			_, err = k8sClientset.CoreV1().Secrets("namespace-1").Update(ctx, s, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		invalidateRCCDirect := func() {
			By("Applying no-op update to direct RemoteClusterConfiguration")
			r, err := localClient.RemoteClusterConfigurations().Get(ctx, rccName, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			r.Spec.DatastoreType = "this-is-not-valid"
			_, err = localBackend.Update(ctx, &model.KVPair{
				Key: model.ResourceKey{
					Name: rccName,
					Kind: apiv3.KindRemoteClusterConfiguration,
				},
				Value:    r,
				Revision: r.ResourceVersion,
			})
			Expect(err).NotTo(HaveOccurred())
		}

		invalidateRCCSecret := func() {
			By("Invalidating RCC Secret RemoteClusterConfiguration")
			s, err := k8sClientset.CoreV1().Secrets("namespace-1").Get(ctx, rccSecretName, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			s.StringData = map[string]string{"datastoreType": "this-is-not-valid"}
			_, err = k8sClientset.CoreV1().Secrets("namespace-1").Update(ctx, s, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}

		toggleOverlayMode := func() {
			By("Toggling overlay mode on RemoteClusterConfiguration")
			r, err := localClient.RemoteClusterConfigurations().Get(ctx, rccName, options.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			currentValue := r.Spec.SyncOptions.OverlayRoutingMode
			if currentValue == "Enabled" {
				r.Spec.SyncOptions.OverlayRoutingMode = "Disabled"
			} else {
				r.Spec.SyncOptions.OverlayRoutingMode = "Enabled"
			}
			_, err = localBackend.Update(ctx, &model.KVPair{
				Key: model.ResourceKey{
					Name: rccName,
					Kind: apiv3.KindRemoteClusterConfiguration,
				},
				Value:    r,
				Revision: r.ResourceVersion,
			})
			Expect(err).NotTo(HaveOccurred())
		}

		// addHep creates a HEP on the remoteClient and adds the expected events to expectedEvents for later checking
		addHep := func() {
			// Keep track of the set of events we will expect from the Felix syncer. Start with the remote
			// cluster status updates as the connection succeeds.
			By("Creating a HEP")
			_, err = remoteClient.HostEndpoints().Create(ctx, &apiv3.HostEndpoint{
				ObjectMeta: metav1.ObjectMeta{Name: "hep1"},
				Spec: apiv3.HostEndpointSpec{
					Node:          "node-hep",
					InterfaceName: "eth1",
					Profiles:      []string{"foo", "bar"},
				},
			}, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
			expectedEvents = append(expectedEvents, api.Update{
				KVPair: model.KVPair{
					Key: model.HostEndpointKey{
						Hostname:   "remote-cluster/node-hep",
						EndpointID: "hep1",
					},
					Value: &model.HostEndpoint{
						Name:              "eth1",
						ExpectedIPv4Addrs: nil,
						ExpectedIPv6Addrs: nil,
						ProfileIDs:        []string{"remote-cluster/foo", "remote-cluster/bar"},
						Ports:             []model.EndpointPort{},
					},
				},
				UpdateType: api.UpdateTypeKVNew,
			})
			deleteEvents = append(deleteEvents, api.Update{
				KVPair: model.KVPair{
					Key: model.HostEndpointKey{
						Hostname:   "remote-cluster/node-hep",
						EndpointID: "hep1",
					},
					Value: nil,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			})

			// We only get the local event if the local config is the same datastore (which we can tell from the
			// datastore type).
			if localConfig.Spec.DatastoreType == remoteConfig.Spec.DatastoreType {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair: model.KVPair{
						Key: model.HostEndpointKey{
							Hostname:   "node-hep",
							EndpointID: "hep1",
						},
						Value: &model.HostEndpoint{
							Name:              "eth1",
							ExpectedIPv4Addrs: nil,
							ExpectedIPv6Addrs: nil,
							ProfileIDs:        []string{"foo", "bar"},
							Ports:             []model.EndpointPort{},
						},
					},
					UpdateType: api.UpdateTypeKVNew,
				})
			}
		}

		// addWep creates a WEP on the remoteClient and adds the expected events to expectedEvents for later checking
		addWep := func() {
			wep := libapiv3.NewWorkloadEndpoint()
			wep.Namespace = "ns1"
			wep.Spec.Node = "node1"
			wep.Spec.Orchestrator = "k8s"
			wep.Spec.Pod = "pod-1"
			wep.Spec.ContainerID = "container-1"
			wep.Spec.Endpoint = "eth0"
			wep.Spec.InterfaceName = "cali01234"
			wep.Spec.IPNetworks = []string{"10.100.10.1"}
			wep.Spec.Profiles = []string{"this-profile", "that-profile"}
			wep, err = remoteClient.WorkloadEndpoints().Create(ctx, wep, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Pass the resource through the update processor to get the expected syncer update (we'll need to
			// modify it to include the remote cluster details).
			up := updateprocessors.NewWorkloadEndpointUpdateProcessor()
			kvp := model.KVPair{
				Key: model.ResourceKey{
					Kind:      libapiv3.KindWorkloadEndpoint,
					Name:      "node1-k8s-pod--1-eth0",
					Namespace: "ns1",
				},
				Value: wep,
			}
			kvps, err := up.Process(&kvp)
			Expect(err).NotTo(HaveOccurred())
			Expect(kvps).To(HaveLen(1))

			// Modify the values as expected for the remote cluster
			wepKey := kvps[0].Key.(model.WorkloadEndpointKey)
			wepValue := kvps[0].Value.(*model.WorkloadEndpoint)
			wepKey.Hostname = "remote-cluster/node1"
			wepValue.ProfileIDs = []string{"remote-cluster/this-profile", "remote-cluster/that-profile"}

			// Add this WEP to the set of expected events that we'll get from the syncer.
			expectedEvents = append(expectedEvents, api.Update{
				KVPair: model.KVPair{
					Key:   wepKey,
					Value: wepValue,
				},
				UpdateType: api.UpdateTypeKVNew,
			})
			deleteEvents = append(deleteEvents, api.Update{
				KVPair: model.KVPair{
					Key:   wepKey,
					Value: nil,
				},
				UpdateType: api.UpdateTypeKVDeleted,
			})
		}

		// addProfile creates a Profile on the remoteClient and adds the expected events to expectedEvents for later checking
		addProfile := func() {
			pro := apiv3.NewProfile()
			pro.Name = "profile-1"
			pro.Spec.LabelsToApply = map[string]string{
				"label1": "value1",
				"label2": "value2",
			}
			pro.Spec.Ingress = []apiv3.Rule{
				{
					Action: "Allow",
				},
			}
			pro, err = remoteClient.Profiles().Create(ctx, pro, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Add the remote profiles to the events - doing this by hand is simpler (although arguably not as
			// maintainable).
			expectedEvents = append(expectedEvents,
				api.Update{
					KVPair: model.KVPair{
						Key: model.ProfileRulesKey{
							ProfileKey: model.ProfileKey{Name: "remote-cluster/profile-1"},
						},
						Value: &model.ProfileRules{},
					},
					UpdateType: api.UpdateTypeKVNew,
				}, api.Update{
					KVPair: model.KVPair{
						Key: model.ResourceKey{
							Kind: apiv3.KindProfile,
							Name: "remote-cluster/profile-1",
						},
						Value: &apiv3.Profile{
							TypeMeta: metav1.TypeMeta{
								Kind: apiv3.KindProfile,
							},
							ObjectMeta: metav1.ObjectMeta{
								Name: "profile-1",
							},
							Spec: apiv3.ProfileSpec{
								LabelsToApply: pro.Spec.LabelsToApply,
							},
						},
					},
					UpdateType: api.UpdateTypeKVNew,
				},
				api.Update{
					KVPair: model.KVPair{
						Key: model.ProfileLabelsKey{
							ProfileKey: model.ProfileKey{Name: "remote-cluster/profile-1"},
						},
						Value: pro.Spec.LabelsToApply,
					},
					UpdateType: api.UpdateTypeKVNew,
				},
			)
			deleteEvents = append(deleteEvents,
				api.Update{
					KVPair: model.KVPair{
						Key: model.ProfileRulesKey{
							ProfileKey: model.ProfileKey{Name: "remote-cluster/profile-1"},
						},
						Value: nil,
					},
					UpdateType: api.UpdateTypeKVDeleted,
				}, api.Update{
					KVPair: model.KVPair{
						Key: model.ResourceKey{
							Kind: apiv3.KindProfile,
							Name: "remote-cluster/profile-1",
						},
						Value: nil,
					},
					UpdateType: api.UpdateTypeKVDeleted,
				},
				api.Update{
					KVPair: model.KVPair{
						Key: model.ProfileLabelsKey{
							ProfileKey: model.ProfileKey{Name: "remote-cluster/profile-1"},
						},
						Value: nil,
					},
					UpdateType: api.UpdateTypeKVDeleted,
				},
			)
		}

		addPool := func(mode apiv3.OverlayRoutingMode) {
			cidrString := "192.168.10.0/24"
			_, cidrNet, err := net.ParseCIDR(cidrString)
			Expect(err).NotTo(HaveOccurred())

			automatic := apiv3.Automatic

			ipPool := apiv3.NewIPPool()
			ipPool.Name = "my-ippool"
			ipPool.Spec.CIDR = cidrString
			ipPool.Spec.VXLANMode = apiv3.VXLANModeNever
			ipPool.Spec.IPIPMode = apiv3.IPIPModeNever
			ipPool.Spec.BlockSize = 26
			ipPool.Spec.NodeSelector = "all()"
			ipPool.Spec.AllowedUses = []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel}
			ipPool.Spec.AssignmentMode = &automatic
			_, err = remoteClient.IPPools().Create(ctx, ipPool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// We only get the local event if the local config is the same datastore (which we can tell from the
			// datastore type).
			if localConfig.Spec.DatastoreType == remoteConfig.Spec.DatastoreType {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair: model.KVPair{
						Key: model.IPPoolKey{
							CIDR: *cidrNet,
						},
						Value: &model.IPPool{
							CIDR:             *cidrNet,
							IPAM:             true,
							IPIPInterface:    "",
							IPIPMode:         "",
							VXLANMode:        "",
							Masquerade:       false,
							Disabled:         false,
							DisableBGPExport: false,
							AWSSubnetID:      "",
							AssignmentMode:   apiv3.Automatic,
						},
					},
					UpdateType: api.UpdateTypeKVNew,
				})
			}

			if mode == apiv3.OverlayRoutingModeEnabled {
				v3Key := model.ResourceKey{
					Name: "my-ippool",
					Kind: apiv3.KindIPPool,
				}
				// Expect RemoteClusterResourceKey pairs.
				expectedEvents = append(expectedEvents, api.Update{
					KVPair: model.KVPair{
						Key: model.RemoteClusterResourceKey{
							ResourceKey: v3Key,
							Cluster:     "remote-cluster",
						},
						Value: ipPool,
					},
					UpdateType: api.UpdateTypeKVNew,
				})
				deleteEvents = append(deleteEvents, api.Update{
					KVPair: model.KVPair{
						Key: model.RemoteClusterResourceKey{
							ResourceKey: v3Key,
							Cluster:     "remote-cluster",
						},
						Value: nil,
					},
					UpdateType: api.UpdateTypeKVDeleted,
				})
			}
		}

		addBlock := func(mode apiv3.OverlayRoutingMode) {
			cidrString := "192.168.10.0/30"
			_, cidrNet, err := net.ParseCIDR(cidrString)
			Expect(err).NotTo(HaveOccurred())
			v1Key := model.BlockKey{
				CIDR: *cidrNet,
			}

			idx := 0
			handle := "test-handle"
			affinity := "host:test-node"
			v1Value := &model.AllocationBlock{
				CIDR:     *cidrNet,
				Affinity: &affinity,
				Attributes: []model.AllocationAttribute{
					{
						AttrPrimary: &handle,
						AttrSecondary: map[string]string{
							ipam.AttributeNode: "test-node",
						},
					},
				},
				Allocations: []*int{&idx, nil, nil, nil},
				Unallocated: []int{1, 2, 3},
			}
			_, err = remoteBackend.Create(ctx, &model.KVPair{
				Key:   v1Key,
				Value: v1Value,
			})
			Expect(err).NotTo(HaveOccurred())

			// We only get the local event if the local config is the same datastore (which we can tell from the
			// datastore type).
			if localConfig.Spec.DatastoreType == remoteConfig.Spec.DatastoreType {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair: model.KVPair{
						Key:   v1Key,
						Value: v1Value,
					},
					UpdateType: api.UpdateTypeKVNew,
				})
			}

			if mode == apiv3.OverlayRoutingModeEnabled {
				remoteAffinity := "host:remote-cluster/test-node"
				ipamBlock := libapiv3.NewIPAMBlock()
				ipamBlock.Name = "192-168-10-0-30"
				ipamBlock.Spec.CIDR = "192.168.10.0/30"
				ipamBlock.Spec.Affinity = &remoteAffinity
				ipamBlock.Spec.Attributes = []libapiv3.AllocationAttribute{
					{
						AttrPrimary: &handle,
						AttrSecondary: map[string]string{
							ipam.AttributeNode: "remote-cluster/test-node",
						},
					},
				}
				ipamBlock.Spec.Allocations = []*int{&idx, nil, nil, nil}
				ipamBlock.Spec.Unallocated = []int{1, 2, 3}
				v3Key := model.ResourceKey{
					Name: "192-168-10-0-30",
					Kind: libapiv3.KindIPAMBlock,
				}

				// Expect RemoteClusterResourceKey pairs.
				expectedEvents = append(expectedEvents, api.Update{
					KVPair: model.KVPair{
						Key: model.RemoteClusterResourceKey{
							ResourceKey: v3Key,
							Cluster:     "remote-cluster",
						},
						Value: ipamBlock,
					},
					UpdateType: api.UpdateTypeKVNew,
				})
				deleteEvents = append(deleteEvents, api.Update{
					KVPair: model.KVPair{
						Key: model.RemoteClusterResourceKey{
							ResourceKey: v3Key,
							Cluster:     "remote-cluster",
						},
						Value: nil,
					},
					UpdateType: api.UpdateTypeKVDeleted,
				})
			}
		}

		addNode := func(mode apiv3.OverlayRoutingMode) {
			node := libapiv3.NewNode()
			node.Name = "test-node"
			node.Spec.BGP = &libapiv3.NodeBGPSpec{
				IPv4Address: "1.2.3.4/24",
			}
			node.Spec.IPv4VXLANTunnelAddr = "192.168.56.78"
			node.Spec.Wireguard = &libapiv3.NodeWireguardSpec{
				InterfaceIPv4Address: "192.168.12.34",
			}
			node.Status.WireguardPublicKey = "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="
			_, err := remoteClient.Nodes().Create(ctx, node, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			if mode == apiv3.OverlayRoutingModeEnabled {
				nodeIP := net.MustParseIP("1.2.3.4")
				wgIP := net.MustParseIP("192.168.12.34")
				expected := []api.Update{
					{
						KVPair: model.KVPair{
							Key: model.HostIPKey{
								Hostname: "remote-cluster/test-node",
							},
							Value: &nodeIP,
						},
						UpdateType: api.UpdateTypeKVNew,
					},
					{
						KVPair: model.KVPair{
							Key: model.ResourceKey{
								Name: "remote-cluster/test-node",
								Kind: libapiv3.KindNode,
							},
							Value: node,
						},
						UpdateType: api.UpdateTypeKVNew,
					},
					{
						KVPair: model.KVPair{
							Key: model.WireguardKey{
								NodeName: "remote-cluster/test-node",
							},
							Value: &model.Wireguard{
								InterfaceIPv4Addr: &wgIP,
								PublicKey:         node.Status.WireguardPublicKey,
							},
						},
						UpdateType: api.UpdateTypeKVNew,
					},
					{
						KVPair: model.KVPair{
							Key: model.HostConfigKey{
								Hostname: "remote-cluster/test-node",
								Name:     "NodeIP",
							},
							Value: "1.2.3.4",
						},
						UpdateType: api.UpdateTypeKVNew,
					},
					{
						KVPair: model.KVPair{
							Key: model.HostConfigKey{
								Hostname: "remote-cluster/test-node",
								Name:     "IPv4VXLANTunnelAddr",
							},
							Value: "192.168.56.78",
						},
						UpdateType: api.UpdateTypeKVNew,
					},
				}

				for _, update := range expected {
					expectedEvents = append(expectedEvents, update)
					deleteEvents = append(deleteEvents, api.Update{
						KVPair: model.KVPair{
							Key:   update.Key,
							Value: nil,
						},
						UpdateType: api.UpdateTypeKVDeleted,
					})
				}
			}
		}

		type TestCfg struct {
			name            string
			localCfg        *apiconfig.CalicoAPIConfig
			remoteCfg       *apiconfig.CalicoAPIConfig
			create          createFunc
			modifyDatastore modifyFunc
			modifySync      modifyFunc
			noop            noOpFunc
			invalidate      invalidateFunc
		}

		Context("Events handling for all datastore types", func() {
			for _, rmLoop := range []apiv3.OverlayRoutingMode{apiv3.OverlayRoutingModeEnabled, apiv3.OverlayRoutingModeDisabled} {
				for _, tcLoop := range []TestCfg{
					{
						name:            "local K8s with remote etcd direct config",
						localCfg:        &k8sConfig,
						remoteCfg:       &etcdConfig,
						create:          createRCCDirect(rmLoop),
						modifyDatastore: modifyRCCDirect,
						modifySync:      toggleOverlayMode,
						noop:            noOpUpdateRCCDirect,
						invalidate:      invalidateRCCDirect,
					},
					{
						name:            "local K8s with remote etcd secret config",
						localCfg:        &k8sConfig,
						remoteCfg:       &etcdConfig,
						create:          createRCCSecret(rmLoop),
						modifyDatastore: modifyRCCSecret,
						modifySync:      toggleOverlayMode,
						noop:            noOpRCCSecret,
						invalidate:      invalidateRCCSecret,
					},
					{
						name:            "local K8s with remote k8s direct config",
						localCfg:        &k8sConfig,
						remoteCfg:       &k8sConfig,
						create:          createRCCDirect(rmLoop),
						modifyDatastore: modifyRCCDirect,
						modifySync:      toggleOverlayMode,
						noop:            noOpUpdateRCCDirect,
						invalidate:      invalidateRCCDirect,
					},
					//remoteCfg: k8sConfig,
					//create: createRCCSecret
					//This combination is not possible because there is no
					//way to provide k8s config in a secret that is not inline.
					//way to provide k8s config in a secret that is not inline.
					{
						name:            "local K8s with remote k8s inline direct config",
						localCfg:        &k8sConfig,
						remoteCfg:       &k8sInlineConfig,
						create:          createRCCDirect(rmLoop),
						modifyDatastore: modifyRCCDirect,
						modifySync:      toggleOverlayMode,
						noop:            noOpUpdateRCCDirect,
						invalidate:      invalidateRCCDirect,
					},
					{
						name:            "local K8s with remote k8s inline secret config",
						localCfg:        &k8sConfig,
						remoteCfg:       &k8sInlineConfig,
						create:          createRCCSecret(rmLoop),
						modifyDatastore: modifyRCCSecret,
						modifySync:      toggleOverlayMode,
						noop:            noOpRCCSecret,
						invalidate:      invalidateRCCSecret,
					},
					{
						name:            "local etcd with remote k8s inline secret config",
						localCfg:        &etcdConfig,
						remoteCfg:       &k8sInlineConfig,
						create:          createRCCSecret(rmLoop),
						modifyDatastore: modifyRCCSecret,
						modifySync:      toggleOverlayMode,
						noop:            noOpRCCSecret,
						invalidate:      invalidateRCCSecret,
					},
				} {
					// Local variable tc to ensure it's not updated for all tests.
					tc := tcLoop
					rm := rmLoop

					Describe("Events are received with "+tc.name, func() {
						Context("Resources created before starting syncer", func() {
							BeforeEach(func() {
								setup(tc.localCfg, tc.remoteCfg, rm)
								tc.create()

								// In KDD mode, WEPs are backed by Pods, and Profiles are backed by Namespaces, and Nodes are backed by k8s Nodes.
								// We'll exclude the creation of these resource types for remote KDD. Rationale:
								// - K8s remote syncer connection testing is not impacted: still tested through the included types
								// - Remote syncer conversion testing is not impacted:
								//   - All excluded types are tested explicitly through the etcd tests
								//   - Profile and Node types are tested implicitly in k8s tests through calculateDefaultFelixSyncerEntries
								if remoteConfig.Spec.DatastoreType != apiconfig.Kubernetes {
									addWep()
									addProfile()
									addNode(rm)
								}
								addPool(rm)
								addBlock(rm)
								addHep()

								By("Creating and starting a syncer")
								syncTester = testutils.NewSyncerTester()
								filteredSyncerTester = NewRemoteClusterConnFailedFilter(NewValidationFilter(syncTester))
								restartCallbackCalled = false
								restartCallbackMsg = ""
								restartMonitor := remotecluster.NewRemoteClusterRestartMonitor(filteredSyncerTester, func(reason string) {
									restartCallbackCalled = true
									restartCallbackMsg = reason
								})

								os.Setenv("KUBERNETES_MASTER", k8sConfig.Spec.K8sAPIEndpoint)
								syncer = New(localBackend, localConfig.Spec, restartMonitor, false, true)
								defer os.Unsetenv("KUBERNETES_MASTER")
								syncer.Start()

								By("Checking status is updated to sync'd at start of day")
								syncTester.ExpectStatusUpdate(api.WaitForDatastore)
								syncTester.ExpectStatusUpdate(api.ResyncInProgress)
								syncTester.ExpectStatusUpdate(api.InSync)
							})

							It("Should get restart message and see callback when datastore config is changed", func() {
								By("Checking we received the expected events")
								syncTester.ExpectUpdates(expectedEvents, false)

								By("Modifying the RCC/Secret config")
								tc.modifyDatastore()
								By("Checking we received a restart required event")
								expectedEvents = []api.Update{
									{
										KVPair: model.KVPair{
											Key: model.RemoteClusterStatusKey{Name: rccName},
											Value: &model.RemoteClusterStatus{
												Status: model.RemoteClusterConfigChangeRestartRequired,
											},
										},
										UpdateType: api.UpdateTypeKVUpdated,
									},
								}

								syncTester.ExpectUpdates(expectedEvents, false)

								By("Expecting that the RestartMonitor is appropriately calling back")
								Expect(restartCallbackCalled).To(BeTrue())
								Expect(restartCallbackMsg).NotTo(BeEmpty())
								By("done with It")
							})

							It("Should get restart message and see callback when sync config is changed", func() {
								By("Checking we received the expected events")
								syncTester.ExpectUpdates(expectedEvents, false)

								By("Modifying the sync config")
								tc.modifySync()
								By("Checking we received a restart required event")
								expectedEvents = []api.Update{
									{
										KVPair: model.KVPair{
											Key: model.RemoteClusterStatusKey{Name: rccName},
											Value: &model.RemoteClusterStatus{
												Status: model.RemoteClusterConfigChangeRestartRequired,
											},
										},
										UpdateType: api.UpdateTypeKVUpdated,
									},
								}

								syncTester.ExpectUpdates(expectedEvents, false)

								By("Expecting that the RestartMonitor is appropriately calling back")
								Expect(restartCallbackCalled).To(BeTrue())
								Expect(restartCallbackMsg).NotTo(BeEmpty())
								By("done with It")
							})

							It("Should receive events for resources created before starting syncer", func() {
								By("Checking we received the expected events")
								syncTester.ExpectUpdates(expectedEvents, false)
								By("done with It")
							})

							It("Should receive delete events when removing the remote cluster after it is synced", func() {
								By("Checking we received the expected events")
								syncTester.ExpectUpdates(expectedEvents, false)

								By("Deleting the remote cluster configuration")
								_, outError := localClient.RemoteClusterConfigurations().Delete(
									ctx, rccName, options.DeleteOptions{ResourceVersion: rcc.ResourceVersion},
								)
								Expect(outError).NotTo(HaveOccurred())

								By("Checking we received the expected events")
								expectedDeleteUpdates := []api.Update{{
									KVPair:     model.KVPair{Key: model.RemoteClusterStatusKey{Name: "remote-cluster"}},
									UpdateType: api.UpdateTypeKVDeleted,
								}}
								expectedDeleteUpdates = append(expectedDeleteUpdates, deleteEvents...)

								syncTester.ExpectUpdates(expectedDeleteUpdates, false)
							})

							It("Should send no update and see no callback when reapplying RCC", func() {
								By("Checking we received the expected events")
								syncTester.ExpectUpdates(expectedEvents, false)

								By("Applying a no-op update to the RCC/Secret config")
								tc.noop()
								By("Checking we received no new events")
								syncTester.ExpectUpdates([]api.Update{}, false)
								Expect(restartCallbackCalled).To(BeFalse())
							})

							It("Should send invalid status and see no callback when config is changed to an invalid one", func() {
								By("Checking we received the expected events")
								syncTester.ExpectUpdates(expectedEvents, false)

								By("Applying an invalid update to the RCC/Secret config")
								tc.invalidate()
								By("Checking we received invalid config events")
								expectedEvents = []api.Update{
									{
										KVPair: model.KVPair{
											Key: model.RemoteClusterStatusKey{Name: rccName},
											Value: &model.RemoteClusterStatus{
												Status: model.RemoteClusterConfigIncomplete,
												Error:  "Config is incomplete, stopping watch remote",
											},
										},
										UpdateType: api.UpdateTypeKVUpdated,
									},
								}
								// An additional incomplete event is sent by the secret retrieval logic.
								if rcc.Spec.ClusterAccessSecret != nil {
									expectedEvents = append(expectedEvents, api.Update{
										KVPair: model.KVPair{
											Key: model.RemoteClusterStatusKey{Name: rccName},
											Value: &model.RemoteClusterStatus{
												Status: model.RemoteClusterConfigIncomplete,
												Error:  ".*failed to validate Field: DatastoreType.*",
											},
										},
										UpdateType: api.UpdateTypeKVUpdated,
									})
								} else if rcc.Spec.ClusterAccessSecret == nil {
									expectedEvents = append(expectedEvents, api.Update{
										KVPair: model.KVPair{
											Key: model.RemoteClusterStatusKey{Name: rccName},
											Value: &model.RemoteClusterStatus{
												Status: model.RemoteClusterConfigIncomplete,
											},
										},
										UpdateType: api.UpdateTypeKVUpdated,
									})
								}
								expectedEvents = append(expectedEvents, deleteEvents...)
								syncTester.ExpectUpdates(expectedEvents, false)
								Expect(restartCallbackCalled).To(BeFalse())
							})
						})

						Context("Resources created after starting syncer", func() {
							BeforeEach(func() {
								setup(tc.localCfg, tc.remoteCfg, rm)
								tc.create()

								By("Creating and starting a syncer")
								syncTester = testutils.NewSyncerTester()
								filteredSyncerTester = NewRemoteClusterConnFailedFilter(NewValidationFilter(syncTester))

								os.Setenv("KUBERNETES_MASTER", k8sConfig.Spec.K8sAPIEndpoint)
								syncer = New(localBackend, localConfig.Spec, filteredSyncerTester, false, true)
								defer os.Unsetenv("KUBERNETES_MASTER")
								syncer.Start()

								By("Checking status is updated to sync'd at start of day")
								syncTester.ExpectStatusUpdate(api.WaitForDatastore)
								syncTester.ExpectStatusUpdate(api.ResyncInProgress)
								syncTester.ExpectStatusUpdate(api.InSync)
							})

							It("Should receive events for resources created after starting syncer", func() {
								By("Checking we received the expected events")
								syncTester.ExpectUpdates(expectedEvents, false)

								expectedEvents = []api.Update{}
								if remoteConfig.Spec.DatastoreType != apiconfig.Kubernetes {
									addWep()
									addProfile()
									addNode(rm)
								}
								addPool(rm)
								addBlock(rm)
								addHep()
								syncTester.ExpectUpdates(expectedEvents, false)
								By("done with It")
							})
						})
					})
				}
			}
		})
	})
})

func NewRemoteClusterConnFailedFilter(sink api.SyncerCallbacks) *RemoteClusterConnFailedFilter {
	return &RemoteClusterConnFailedFilter{
		sink:    sink,
		handled: make(map[string]bool),
	}
}

type RemoteClusterConnFailedFilter struct {
	sink    api.SyncerCallbacks
	handled map[string]bool
}

func (r *RemoteClusterConnFailedFilter) OnStatusUpdated(status api.SyncStatus) {
	// Pass through.
	r.sink.OnStatusUpdated(status)
}

func (r *RemoteClusterConnFailedFilter) OnUpdates(updates []api.Update) {
	defer GinkgoRecover()

	filteredUpdates := make([]api.Update, 0, len(updates))
	for _, update := range updates {
		if k, ok := update.Key.(model.RemoteClusterStatusKey); ok {
			if v, ok := update.Value.(*model.RemoteClusterStatus); ok && v.Status == model.RemoteClusterConnectionFailed {
				// Only include 1 remote cluster failed update per remote cluster.
				if r.handled[k.Name] {
					continue
				}
				r.handled[k.Name] = true
			}
		}
		filteredUpdates = append(filteredUpdates, update)
	}

	r.sink.OnUpdates(filteredUpdates)
}
