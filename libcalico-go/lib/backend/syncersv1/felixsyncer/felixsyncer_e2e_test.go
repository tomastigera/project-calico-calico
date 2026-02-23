// Copyright (c) 2017-2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package felixsyncer_test

import (
	"context"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	resources2 "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/felixsyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	v1v "github.com/projectcalico/calico/libcalico-go/lib/validator/v1"
	v3v "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
)

const (
	controlPlaneNodeName = "kind-single-control-plane"
)

type felixSyncerRemote struct {
	name string
	mode apiv3.OverlayRoutingMode
}

// calculateDefaultFelixSyncerEntries determines the expected set of Felix configuration for the currently configured
// cluster.
func calculateDefaultFelixSyncerEntries(cs kubernetes.Interface, dt apiconfig.DatastoreType, remote ...felixSyncerRemote) (expected []model.KVPair) {
	remoteClusterPrefix := ""
	defaultProfileRules := []model.Rule{{Action: "allow"}}
	if len(remote) > 0 {
		// Names are prefixed with the remote cluster name (if specified) and a "/" separator.
		remoteClusterPrefix = remote[0].name + "/"
		defaultProfileRules = nil
	}

	// Add 2 for the default-allow profile that is always there.
	// However, no profile labels are in the list because the
	// default-allow profile doesn't specify labels.
	expectedProfile := resources.DefaultAllowProfile()
	if remoteClusterPrefix == "" {
		expected = append(expected, *expectedProfile)
	} else {
		expected = append(expected, model.KVPair{
			Key: model.ResourceKey{
				Kind: apiv3.KindProfile,
				Name: remoteClusterPrefix + resources.DefaultAllowProfileName,
			},
			Value: &apiv3.Profile{
				TypeMeta: metav1.TypeMeta{
					Kind: apiv3.KindProfile,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: resources.DefaultAllowProfileName,
				},
			},
		})
	}
	expected = append(expected, model.KVPair{
		Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: remoteClusterPrefix + "projectcalico-default-allow"}},
		Value: &model.ProfileRules{
			InboundRules:  defaultProfileRules,
			OutboundRules: defaultProfileRules,
		},
	})

	if dt == apiconfig.Kubernetes {
		// Grab the k8s converter (we use this for converting some of the resources below).
		converter := conversion.NewConverter()

		// From our ANX days we also have a default profile (identical to the newer projectcalico-default-allow).
		expectedProfile = resources2.DefaultProfile()
		if remoteClusterPrefix == "" {
			expected = append(expected, *expectedProfile)
		} else {
			expected = append(expected, model.KVPair{
				Key: model.ResourceKey{
					Kind: apiv3.KindProfile,
					Name: remoteClusterPrefix + "default",
				},
				Value: &apiv3.Profile{
					TypeMeta: metav1.TypeMeta{
						Kind: apiv3.KindProfile,
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
					},
				},
			})
		}
		expected = append(expected, model.KVPair{
			Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: remoteClusterPrefix + "default"}},
			Value: &model.ProfileRules{
				InboundRules:  defaultProfileRules,
				OutboundRules: defaultProfileRules,
			},
		})

		// Add one for each node resource. If invoked for remote cluster, only add if overlay routing is enabled.
		if len(remoteClusterPrefix) == 0 || remote[0].mode == apiv3.OverlayRoutingModeEnabled {
			nodes, err := cs.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			for _, node := range nodes.Items {
				// Nodes get updated frequently, so don't include the revision info.
				node.ResourceVersion = ""
				nodeKV, err := resources2.K8sNodeToCalico(&node, false)
				Expect(err).NotTo(HaveOccurred())

				var ipKV *model.KVPair
				for _, ip := range nodeKV.Value.(*internalapi.Node).Spec.Addresses {
					if ip.Type == internalapi.InternalIP {
						ipKV = &model.KVPair{
							Key: model.HostIPKey{
								Hostname: node.Name,
							},
							Value: net.ParseIP(ip.Address),
						}
					}
				}

				if len(remoteClusterPrefix) > 0 {
					nodeKey := nodeKV.Key.(model.ResourceKey)
					nodeKey.Name = remoteClusterPrefix + node.Name
					nodeKV.Key = nodeKey

					if ipKV != nil {
						ipKey := ipKV.Key.(model.HostIPKey)
						ipKey.Hostname = remoteClusterPrefix + node.Name
						ipKV.Key = ipKey
					}
				}

				expected = append(expected, *nodeKV)
				if ipKV != nil {
					expected = append(expected, *ipKV)
				}
			}
		}

		// Add endpoint slices. We don't include these in the remote endpoints.
		if remoteClusterPrefix == "" {
			epss, err := cs.DiscoveryV1().EndpointSlices("").List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			for _, eps := range epss.Items {
				// Endpoints slices get updated frequently, so don't include the revision info.
				eps.ResourceVersion = ""
				epskv, err := converter.EndpointSliceToKVP(&eps)
				Expect(err).NotTo(HaveOccurred())
				expected = append(expected, *epskv)
			}
		}

		// Add services
		if remoteClusterPrefix == "" {
			svcs, err := cs.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			for _, svc := range svcs.Items {
				// Services get updated frequently, so don't include the revision info.
				svc.ResourceVersion = ""
				svckv, err := converter.ServiceToKVP(&svc)
				Expect(err).NotTo(HaveOccurred())
				expected = append(expected, *svckv)
			}
		}

		// Add resources for the namespaces we expect in the cluster.
		namespaces, err := cs.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		for _, ns := range namespaces.Items {
			name := "kns." + ns.Name

			// Expect profile rules for each namespace providing default allow behavior.
			expected = append(expected, model.KVPair{
				Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: remoteClusterPrefix + name}},
				Value: &model.ProfileRules{
					InboundRules:  defaultProfileRules,
					OutboundRules: defaultProfileRules,
				},
			})

			// Expect profile labels for each namespace as well. The labels should include the name
			// of the namespace. As of Kubernetes v1.21, k8s also includes a label for the namespace name
			// that will be inherited by the profile.
			expected = append(expected, model.KVPair{
				Key: model.ProfileLabelsKey{ProfileKey: model.ProfileKey{Name: remoteClusterPrefix + name}},
				Value: map[string]string{
					"pcns.projectcalico.org/name":      ns.Name,
					"pcns.kubernetes.io/metadata.name": ns.Name,
				},
			})

			uid, err := conversion.ConvertUID(ns.UID)
			Expect(err).NotTo(HaveOccurred())

			// And expect a v3 profile for each namespace.
			prof := apiv3.Profile{
				TypeMeta:   metav1.TypeMeta{Kind: "Profile", APIVersion: "projectcalico.org/v3"},
				ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid, CreationTimestamp: ns.CreationTimestamp},
				Spec: apiv3.ProfileSpec{
					LabelsToApply: map[string]string{
						"pcns.projectcalico.org/name":      ns.Name,
						"pcns.kubernetes.io/metadata.name": ns.Name,
					},
					Ingress: []apiv3.Rule{{Action: apiv3.Allow}},
					Egress:  []apiv3.Rule{{Action: apiv3.Allow}},
				},
			}
			if remoteClusterPrefix != "" {
				// Rules are suppressed in federated remote Profile resources.
				prof.Spec.Ingress = nil
				prof.Spec.Egress = nil
			}
			expected = append(expected, model.KVPair{
				Key:   model.ResourceKey{Kind: "Profile", Name: remoteClusterPrefix + name},
				Value: &prof,
			})

			serviceAccounts, err := cs.CoreV1().ServiceAccounts(ns.Name).List(context.Background(), metav1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			for _, sa := range serviceAccounts.Items {
				name := "ksa." + ns.Name + "." + sa.Name

				// Expect profile rules for the serviceaccounts in each namespace.
				expected = append(expected, model.KVPair{
					Key: model.ProfileRulesKey{ProfileKey: model.ProfileKey{Name: remoteClusterPrefix + name}},
					Value: &model.ProfileRules{
						InboundRules:  nil,
						OutboundRules: nil,
					},
				})

				// Expect profile labels for each default serviceaccount as well. The labels should include the name
				// of the service account.
				expected = append(expected, model.KVPair{
					Key: model.ProfileLabelsKey{ProfileKey: model.ProfileKey{Name: remoteClusterPrefix + name}},
					Value: map[string]string{
						"pcsa.projectcalico.org/name": sa.Name,
					},
				})

				uid, err := conversion.ConvertUID(sa.UID)
				Expect(err).NotTo(HaveOccurred())

				//  We also expect one v3 Profile to be present for each ServiceAccount.
				prof := apiv3.Profile{
					TypeMeta:   metav1.TypeMeta{Kind: "Profile", APIVersion: "projectcalico.org/v3"},
					ObjectMeta: metav1.ObjectMeta{Name: name, UID: uid, CreationTimestamp: sa.CreationTimestamp},
					Spec: apiv3.ProfileSpec{
						LabelsToApply: map[string]string{
							"pcsa.projectcalico.org/name": sa.Name,
						},
					},
				}
				expected = append(expected, model.KVPair{
					Key:   model.ResourceKey{Kind: "Profile", Name: remoteClusterPrefix + name},
					Value: &prof,
				})
			}
		}

	}

	return
}

var _ = testutils.E2eDatastoreDescribe("Felix syncer tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	var ctx context.Context
	var c clientv3.Interface
	var be api.Client
	var syncTester *testutils.SyncerTester
	var filteredSyncerTester api.SyncerCallbacks
	var err error
	var datamodelCleanups []func()
	var cs kubernetes.Interface

	addCleanup := func(cleanup func()) {
		datamodelCleanups = append(datamodelCleanups, cleanup)
	}

	BeforeEach(func() {
		ctx = context.Background()
		// Create a v3 client to drive data changes (luckily because this is the _test module,
		// we don't get circular imports.
		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		// Create the backend client to obtain a syncer interface.
		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// build k8s clientset.
		cfg, err := clientcmd.BuildConfigFromFlags("", "/kubeconfig.yaml")
		Expect(err).NotTo(HaveOccurred())
		cs = kubernetes.NewForConfigOrDie(cfg)

		// Create a SyncerTester to receive the BGP syncer callback events and to allow us
		// to assert state.
		syncTester = testutils.NewSyncerTester()
		filteredSyncerTester = NewValidationFilter(syncTester)

		datamodelCleanups = nil
	})

	AfterEach(func() {
		for _, cleanup := range datamodelCleanups {
			cleanup()
		}
	})

	Describe("Felix syncer functionality", func() {
		It("should receive the synced after return all current data", func() {
			syncer := felixsyncer.New(be, config.Spec, filteredSyncerTester, false, true)
			syncer.Start()
			expectedCacheSize := 0

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectStatusUpdate(api.InSync)

			By("Checking updates match those expected.")
			defaultCacheEntries := calculateDefaultFelixSyncerEntries(cs, config.Spec.DatastoreType)
			expectedCacheSize += len(defaultCacheEntries)
			for _, r := range defaultCacheEntries {
				// Expect the correct cache values.
				syncTester.ExpectData(r)
			}

			// Expect the correct updates - should have a new entry for each of these entries. Note that we don't do
			// any more update checks below because we filter out host related updates since they are chatty outside
			// of our control (and a lot of the tests below are focused on host data), instead the tests below will
			// just check the final cache entry.
			var expectedEvents []api.Update
			for _, r := range defaultCacheEntries {
				expectedEvents = append(expectedEvents, api.Update{
					KVPair:     r,
					UpdateType: api.UpdateTypeKVNew,
				})
			}
			syncTester.ExpectUpdates(expectedEvents, false)
			Expect(err).NotTo(HaveOccurred())

			// Verify our cache size is correct.
			syncTester.ExpectCacheSize(expectedCacheSize)

			var node *internalapi.Node
			wip := net.MustParseIP("192.168.12.34")
			if config.Spec.DatastoreType == apiconfig.Kubernetes {
				// For Kubernetes, update the existing node config to have some BGP configuration.
				By("Configuring a node with an IP address and tunnel MAC address")
				var (
					oldValuesSaved        bool
					oldBGPSpec            *internalapi.NodeBGPSpec
					oldVXLANTunnelMACAddr string
					oldWireguardSpec      *internalapi.NodeWireguardSpec
					oldWireguardPublicKey string
				)
				for range 5 {
					// This can fail due to an update conflict, so we allow a few retries.
					node, err = c.Nodes().Get(ctx, "127.0.0.1", options.GetOptions{})
					Expect(err).NotTo(HaveOccurred())
					if !oldValuesSaved {
						if node.Spec.BGP == nil {
							oldBGPSpec = nil
						} else {
							bgpSpecCopy := *node.Spec.BGP
							oldBGPSpec = &bgpSpecCopy
						}
						oldVXLANTunnelMACAddr = node.Spec.VXLANTunnelMACAddr
						if node.Spec.Wireguard == nil {
							oldWireguardSpec = nil
						} else {
							wireguardSpecCopy := *node.Spec.Wireguard
							oldWireguardSpec = &wireguardSpecCopy
						}
						oldWireguardPublicKey = node.Status.WireguardPublicKey
						oldValuesSaved = true
					}
					node.Spec.BGP = &internalapi.NodeBGPSpec{
						IPv4Address:        "1.2.3.4/24",
						IPv6Address:        "aa:bb::cc/120",
						IPv4IPIPTunnelAddr: "192.168.0.1",
					}
					node.Spec.VXLANTunnelMACAddr = "66:cf:23:df:22:07"
					node.Spec.Wireguard = &internalapi.NodeWireguardSpec{
						InterfaceIPv4Address: "192.168.12.34",
					}
					node.Status = internalapi.NodeStatus{
						WireguardPublicKey: "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=",
					}
					node, err = c.Nodes().Update(ctx, node, options.SetOptions{})
					if err == nil {
						break
					}
				}
				Expect(err).NotTo(HaveOccurred())
				addCleanup(func() {
					for range 5 {
						// This can fail due to an update conflict, so we allow a few retries.
						node, err = c.Nodes().Get(ctx, "127.0.0.1", options.GetOptions{})
						Expect(err).NotTo(HaveOccurred())
						node.Spec.BGP = oldBGPSpec
						node.Spec.VXLANTunnelMACAddr = oldVXLANTunnelMACAddr
						node.Spec.Wireguard = oldWireguardSpec
						node.Status.WireguardPublicKey = oldWireguardPublicKey
						node, err = c.Nodes().Update(ctx, node, options.SetOptions{})
						if err == nil {
							break
						}
					}
					Expect(err).NotTo(HaveOccurred())
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.HostConfigKey{Hostname: "127.0.0.1", Name: "IpInIpTunnelAddr"},
					Value: "192.168.0.1",
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.HostConfigKey{Hostname: "127.0.0.1", Name: "VXLANTunnelMACAddr"},
					Value: "66:cf:23:df:22:07",
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.WireguardKey{NodeName: "127.0.0.1"},
					Value: &model.Wireguard{InterfaceIPv4Addr: &wip, PublicKey: "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="},
				})
				expectedCacheSize += 3
			} else {
				// For non-Kubernetes, add a new node with valid BGP configuration.
				By("Creating a node with an IP address and tunnel MAC address")
				node, err = c.Nodes().Create(
					ctx,
					&internalapi.Node{
						ObjectMeta: metav1.ObjectMeta{Name: "127.0.0.1"},
						Spec: internalapi.NodeSpec{
							BGP: &internalapi.NodeBGPSpec{
								IPv4Address:        "1.2.3.4/24",
								IPv6Address:        "aa:bb::cc/120",
								IPv4IPIPTunnelAddr: "192.168.0.1",
							},
							VXLANTunnelMACAddr: "66:cf:23:df:22:07",
							Wireguard: &internalapi.NodeWireguardSpec{
								InterfaceIPv4Address: "192.168.12.34",
							},
						},
						Status: internalapi.NodeStatus{
							WireguardPublicKey: "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=",
						},
					},
					options.SetOptions{},
				)
				Expect(err).NotTo(HaveOccurred())

				// Add 1 for the Node resource passed over the felix syncer.
				expectedCacheSize += 1

				// Creating the node initialises the ClusterInformation as a side effect.
				syncTester.ExpectData(model.KVPair{
					Key:   model.ReadyFlagKey{},
					Value: true,
				})
				syncTester.ExpectValueMatches(
					model.GlobalConfigKey{Name: "ClusterGUID"},
					MatchRegexp("[a-f0-9]{32}"),
				)
				// Creating the node also creates default, kube-admin, and kube-baseline tiers.
				order := apiv3.DefaultTierOrder
				syncTester.ExpectData(model.KVPair{
					Key:   model.TierKey{Name: "default"},
					Value: &model.Tier{Order: &order, DefaultAction: apiv3.Deny},
				})
				adminTierOrder := apiv3.KubeAdminTierOrder
				syncTester.ExpectData(model.KVPair{
					Key:   model.TierKey{Name: names.KubeAdminTierName},
					Value: &model.Tier{Order: &adminTierOrder, DefaultAction: apiv3.Pass},
				})
				baselineTierOrder := apiv3.KubeBaselineTierOrder
				syncTester.ExpectData(model.KVPair{
					Key:   model.TierKey{Name: names.KubeBaselineTierName},
					Value: &model.Tier{Order: &baselineTierOrder, DefaultAction: apiv3.Pass},
				})
				anpOrder := apiv3.AdminNetworkPolicyTierOrder
				syncTester.ExpectData(model.KVPair{
					Key:   model.TierKey{Name: names.AdminNetworkPolicyTierName},
					Value: &model.Tier{Order: &anpOrder, DefaultAction: apiv3.Pass},
				})
				banpOrder := apiv3.BaselineAdminNetworkPolicyTierOrder
				syncTester.ExpectData(model.KVPair{
					Key:   model.TierKey{Name: names.BaselineAdminNetworkPolicyTierName},
					Value: &model.Tier{Order: &banpOrder, DefaultAction: apiv3.Pass},
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.HostConfigKey{Hostname: "127.0.0.1", Name: "IpInIpTunnelAddr"},
					Value: "192.168.0.1",
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.HostConfigKey{Hostname: "127.0.0.1", Name: "VXLANTunnelMACAddr"},
					Value: "66:cf:23:df:22:07",
				})
				syncTester.ExpectData(model.KVPair{
					Key:   model.WireguardKey{NodeName: "127.0.0.1"},
					Value: &model.Wireguard{InterfaceIPv4Addr: &wip, PublicKey: "jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY="},
				})
				// add one for the node resource
				expectedCacheSize += 10
			}

			// The HostIP will be added for the IPv4 address
			expectedCacheSize += 2
			ip := net.MustParseIP("1.2.3.4")
			syncTester.ExpectData(model.KVPair{
				Key:   model.HostIPKey{Hostname: "127.0.0.1"},
				Value: &ip,
			})
			syncTester.ExpectData(model.KVPair{
				Key:   model.HostConfigKey{Hostname: "127.0.0.1", Name: "NodeIP"},
				Value: "1.2.3.4",
			})
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating an IPPool")
			poolCIDR := "192.124.0.0/21"
			poolCIDRNet := net.MustParseCIDR(poolCIDR)
			pool, err := c.IPPools().Create(
				ctx,
				&apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: "mypool"},
					Spec: apiv3.IPPoolSpec{
						CIDR:        poolCIDR,
						IPIPMode:    apiv3.IPIPModeCrossSubnet,
						NATOutgoing: true,
						BlockSize:   30,
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// The pool will add as single entry ( +1 )
			expectedCacheSize += 1

			syncTester.ExpectData(model.KVPair{
				Key: model.IPPoolKey{CIDR: net.MustParseCIDR("192.124.0.0/21")},
				Value: &model.IPPool{
					CIDR:           poolCIDRNet,
					IPIPInterface:  "tunl0",
					IPIPMode:       encap.CrossSubnet,
					Masquerade:     true,
					IPAM:           true,
					Disabled:       false,
					AssignmentMode: apiv3.Automatic,
				},
				Revision: pool.ResourceVersion,
			})
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating a GlobalNetworkSet")
			gns := apiv3.NewGlobalNetworkSet()
			gns.Name = "anetworkset"
			gns.Labels = map[string]string{
				"a": "b",
			}
			gns.Spec.Nets = []string{
				"11.0.0.0/16",
			}
			gns.Spec.AllowedEgressDomains = []string{
				"direct.gov.uk",
				"cam.ac.uk",
			}
			gns, err = c.GlobalNetworkSets().Create(
				ctx,
				gns,
				options.SetOptions{},
			)
			Expect(err).To(BeNil())
			expectedCacheSize++

			_, expGNet, err := net.ParseCIDROrIP("11.0.0.0/16")
			Expect(err).NotTo(HaveOccurred())
			syncTester.ExpectData(model.KVPair{
				Key: model.NetworkSetKey{Name: "anetworkset"},
				Value: &model.NetworkSet{
					Labels: uniquelabels.Make(map[string]string{
						"a":             "b",
						apiv3.LabelKind: apiv3.KindNetworkSet,
						apiv3.LabelName: "anetworkset",
					}),
					Nets: []net.IPNet{
						*expGNet,
					},
					AllowedEgressDomains: []string{
						"direct.gov.uk",
						"cam.ac.uk",
					},
				},
				Revision: gns.ResourceVersion,
			})
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating a NetworkSet")
			ns := apiv3.NewNetworkSet()
			ns.Name = "anetworkset"
			ns.Namespace = "namespace-1"
			ns.Labels = map[string]string{
				"a": "b",
			}
			ns.Spec.Nets = []string{
				"11.0.0.0/16",
			}
			ns.Spec.AllowedEgressDomains = []string{
				"direct.gov.uk",
				"cam.ac.uk",
			}
			ns, err = c.NetworkSets().Create(
				ctx,
				ns,
				options.SetOptions{},
			)
			expectedCacheSize++

			_, expNet, err := net.ParseCIDROrIP("11.0.0.0/16")
			Expect(err).NotTo(HaveOccurred())
			syncTester.ExpectData(model.KVPair{
				Key: model.NetworkSetKey{Name: "namespace-1/anetworkset"},
				Value: &model.NetworkSet{
					Labels: uniquelabels.Make(map[string]string{
						"a":                           "b",
						apiv3.LabelName:               "anetworkset",
						apiv3.LabelKind:               "NetworkSet",
						"projectcalico.org/namespace": "namespace-1",
					}),
					Nets: []net.IPNet{
						*expNet,
					},
					AllowedEgressDomains: []string{
						"direct.gov.uk",
						"cam.ac.uk",
					},
					ProfileIDs: []string{
						"kns.namespace-1",
					},
				},
				Revision: ns.ResourceVersion,
			})
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating a LicenseKey")
			lk := apiv3.NewLicenseKey()
			lk.Name = "default"
			lk.Spec.Token = "token"
			lk.Spec.Certificate = "certificate"
			lk, err = c.LicenseKey().Create(
				ctx,
				lk,
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			expectedCacheSize++

			syncTester.ExpectData(model.KVPair{
				Key: model.LicenseKeyKey{Name: "default"},
				Value: &model.LicenseKey{
					Token:       "token",
					Certificate: "certificate",
				},
				Revision: lk.ResourceVersion,
			})
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating a HostEndpoint")
			hep, err := c.HostEndpoints().Create(
				ctx,
				&apiv3.HostEndpoint{
					ObjectMeta: metav1.ObjectMeta{
						Name: "hosta.eth0-a",
						Labels: map[string]string{
							"label1": "value1",
						},
					},
					Spec: apiv3.HostEndpointSpec{
						Node:          "127.0.0.1",
						InterfaceName: "eth0",
						ExpectedIPs:   []string{"1.2.3.4", "aa:bb::cc:dd"},
						Profiles:      []string{"profile1", "profile2"},
						Ports: []apiv3.EndpointPort{
							{
								Name:     "port1",
								Protocol: numorstring.ProtocolFromString("TCP"),
								Port:     1234,
							},
							{
								Name:     "port2",
								Protocol: numorstring.ProtocolFromString("UDP"),
								Port:     1010,
							},
						},
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())

			// The host endpoint will add as single entry ( +1 )
			expectedCacheSize += 1
			syncTester.ExpectData(model.KVPair{
				Key: model.HostEndpointKey{Hostname: "127.0.0.1", EndpointID: "hosta.eth0-a"},
				Value: &model.HostEndpoint{
					Name:              "eth0",
					ExpectedIPv4Addrs: []net.IP{net.MustParseIP("1.2.3.4")},
					ExpectedIPv6Addrs: []net.IP{net.MustParseIP("aa:bb::cc:dd")},
					Labels: uniquelabels.Make(map[string]string{
						"label1": "value1",
					}),
					ProfileIDs: []string{"profile1", "profile2"},
					Ports: []model.EndpointPort{
						{
							Name:     "port1",
							Protocol: numorstring.ProtocolFromStringV1("TCP"),
							Port:     1234,
						},
						{
							Name:     "port2",
							Protocol: numorstring.ProtocolFromStringV1("UDP"),
							Port:     1010,
						},
					},
				},
				Revision: hep.ResourceVersion,
			})
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Allocating an IP")
			err = c.IPAM().AssignIP(ctx, ipam.AssignIPArgs{
				Hostname: "127.0.0.1",
				IP:       net.MustParseIP("192.124.0.1"),
			})
			Expect(err).NotTo(HaveOccurred())
			expectedCacheSize += 1

			_, cidr, _ := net.ParseCIDR("192.124.0.0/30")
			affinity := "host:127.0.0.1"
			zero := 0
			syncTester.ExpectData(model.KVPair{
				Key: model.BlockKey{CIDR: *cidr},
				Value: &model.AllocationBlock{
					CIDR:        *cidr,
					Affinity:    &affinity,
					Allocations: []*int{nil, &zero, nil, nil},
					Unallocated: []int{0, 2, 3},
					Attributes: []model.AllocationAttribute{
						{},
					},
				},
			})

			By("Creating a Tier")
			tierName := "mytier"
			order := float64(100.00)
			actionPass := apiv3.Pass
			tier, err := c.Tiers().Create(
				ctx,
				&apiv3.Tier{
					ObjectMeta: metav1.ObjectMeta{Name: tierName},
					Spec: apiv3.TierSpec{
						Order:         &order,
						DefaultAction: &actionPass,
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			expectedCacheSize += 1
			syncTester.ExpectData(model.KVPair{
				Key: model.TierKey{Name: tierName},
				Value: &model.Tier{
					Order:         &order,
					DefaultAction: apiv3.Pass,
				},
				Revision: tier.ResourceVersion,
			})
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating a PacketCapture")
			captureName := "my-capture"
			_, err = c.PacketCaptures().Create(
				ctx,
				&apiv3.PacketCapture{
					ObjectMeta: metav1.ObjectMeta{
						Name:      captureName,
						Namespace: "namespace-1",
					},
					Spec: apiv3.PacketCaptureSpec{
						Selector: "all()",
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			expectedCacheSize += 1
			syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/packetcaptures/namespace-1/my-capture")
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating an ExternalNetwork")
			externalNetworkName := "my-network"
			index := uint32(10)
			_, err = c.ExternalNetworks().Create(
				ctx,
				&apiv3.ExternalNetwork{
					ObjectMeta: metav1.ObjectMeta{
						Name: externalNetworkName,
					},
					Spec: apiv3.ExternalNetworkSpec{
						RouteTableIndex: &index,
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			expectedCacheSize += 1
			syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/externalnetworks/my-network")
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating an EgressGatewayPolicy")
			egressGatewayPolicyName := "my-egressgatewaypolicy"
			egressGatewayPolicyRule := apiv3.EgressGatewayRule{
				Destination: &apiv3.EgressGatewayPolicyDestinationSpec{
					CIDR: "0.0.0.0/0",
				},
				Gateway: &apiv3.EgressSpec{
					Selector:          "egress-code == 'red'",
					NamespaceSelector: "projectcalico.org/name == 'default'",
					MaxNextHops:       4,
				},
			}
			_, err = c.EgressGatewayPolicy().Create(
				ctx,
				&apiv3.EgressGatewayPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name: egressGatewayPolicyName,
					},
					Spec: apiv3.EgressGatewayPolicySpec{
						Rules: []apiv3.EgressGatewayRule{egressGatewayPolicyRule},
					},
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			expectedCacheSize += 1
			syncTester.ExpectPath("/calico/resources/v3/projectcalico.org/egressgatewaypolicies/my-egressgatewaypolicy")
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Starting a new syncer and verifying that all current entries are returned before sync status")
			// We need to create a new syncTester and syncer.
			current := syncTester.GetCacheEntries()

			syncTester = testutils.NewSyncerTester()
			filteredSyncerTester = NewValidationFilter(syncTester)
			syncer = felixsyncer.New(be, config.Spec, filteredSyncerTester, false, true)
			syncer.Start()

			// Verify the data is the same as the data from the previous cache.  We got the cache in the previous
			// step.
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectCacheSize(len(current))
			for _, e := range current {
				if config.Spec.DatastoreType == apiconfig.Kubernetes {
					// Don't check revisions for K8s since the node data gets updated constantly.
					e.Revision = ""
				}
				syncTester.ExpectData(e)
			}
			syncTester.ExpectStatusUpdate(api.InSync)
		})
	})
})

var _ = testutils.E2eDatastoreDescribe("Felix syncer tests (KDD only)", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	var be api.Client
	var syncTester *testutils.SyncerTester
	var filteredSyncerTester api.SyncerCallbacks
	var err error

	BeforeEach(func() {
		// Create the backend client to obtain a syncer interface.
		config.Spec.K8sUsePodCIDR = true
		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// Create a SyncerTester to receive the BGP syncer callback events and to allow us
		// to assert state.
		syncTester = testutils.NewSyncerTester()
		filteredSyncerTester = NewValidationFilter(syncTester)
	})

	It("should handle IPAM blocks properly for host-local IPAM", func() {
		config.Spec.K8sUsePodCIDR = true
		syncer := felixsyncer.New(be, config.Spec, filteredSyncerTester, false, true)
		syncer.Start()

		// Verify we start a resync.
		syncTester.ExpectStatusUpdate(api.WaitForDatastore)
		syncTester.ExpectStatusUpdate(api.ResyncInProgress)

		// Expect a felix config for the IPIP tunnel address, generated from the podCIDR.
		syncTester.ExpectData(model.KVPair{
			Key:   model.HostConfigKey{Hostname: "127.0.0.1", Name: "IpInIpTunnelAddr"},
			Value: "192.168.0.1",
		})

		// Expect to be in-sync.
		syncTester.ExpectStatusUpdate(api.InSync)
	})
})

var _ = testutils.E2eDatastoreDescribe("Felix syncer tests (passive mode)", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	var be api.Client
	var syncTester *testutils.SyncerTester
	var filteredSyncerTester api.SyncerCallbacks
	var err error
	var c clientv3.Interface

	BeforeEach(func() {
		// Create the backend client to obtain a syncer interface.
		be, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		c, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		// Create a SyncerTester to receive the BGP syncer callback events and to allow us
		// to assert state.
		syncTester = testutils.NewSyncerTester()
		filteredSyncerTester = NewValidationFilter(syncTester)
	})

	It("should only receive config updates when in passive mode", func() {
		syncer := felixsyncer.New(be, config.Spec, filteredSyncerTester, false, false)
		syncer.Start()

		// Verify we start a resync.
		syncTester.ExpectStatusUpdate(api.WaitForDatastore)
		syncTester.ExpectStatusUpdate(api.ResyncInProgress)

		// Expect to be in-sync.
		syncTester.ExpectStatusUpdate(api.InSync)

		// We don't expect any resources, since we're only watching config.
		syncTester.ExpectCacheSize(0)

		// Change the variant.
		ci := &apiv3.ClusterInformation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: apiv3.ClusterInformationSpec{
				Variant: "Calico",
			},
		}
		_, err = c.ClusterInformation().Create(context.Background(), ci, options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Expect an update for the variant.
		syncTester.ExpectCacheSize(1)
		syncTester.ExpectValueMatches(
			model.GlobalConfigKey{Name: "Variant"},
			MatchRegexp("Calico"),
		)
	})
})

// --- This is a copy  of the validation filter defined in typha, but modified to expect no errors.

func NewValidationFilter(sink api.SyncerCallbacks) *ValidationFilter {
	return &ValidationFilter{
		sink: sink,
	}
}

type ValidationFilter struct {
	sink api.SyncerCallbacks
}

func (v *ValidationFilter) OnStatusUpdated(status api.SyncStatus) {
	// Pass through.
	v.sink.OnStatusUpdated(status)
}

func (v *ValidationFilter) OnUpdates(updates []api.Update) {
	defer GinkgoRecover()

	filteredUpdates := make([]api.Update, len(updates))
	for i, update := range updates {
		logCxt := logrus.WithFields(logrus.Fields{
			"key":   update.Key,
			"value": update.Value,
		})
		logCxt.Debug("Validating KV pair.")
		validatorFunc := v1v.Validate
		if _, isV3 := update.Key.(model.ResourceKey); isV3 {
			logCxt.Debug("Use v3 validator")
			validatorFunc = v3v.Validate
		} else if _, isRemoteV3 := update.Key.(model.RemoteClusterResourceKey); isRemoteV3 {
			logCxt.Debug("Use v3 validator")
			validatorFunc = v3v.Validate
		} else {
			logCxt.Debug("Use v1 validator")
		}
		if update.Value != nil {
			val := reflect.ValueOf(update.Value)
			if val.Kind() == reflect.Pointer {
				elem := val.Elem()
				if elem.Kind() == reflect.Struct {
					err := validatorFunc(elem.Interface())
					Expect(err).NotTo(HaveOccurred())
				}
			}

			switch k := update.Key.(type) {
			case model.NodeKey:
				// TODO: This should be in its own filter.
				// Special case: we can't serialize Node keys but Felix only cares
				// about the host metadata anyway.  Extract the Host IP.
				update.Key = model.HostIPKey(k)
				if update.Value != nil {
					_, ok := update.Value.(*model.Node)
					Expect(ok).To(BeTrue())
				}
			}

			switch v := update.Value.(type) {
			case *model.WorkloadEndpoint:
				Expect(v.Name).NotTo(Equal(""))
			}
		}
		filteredUpdates[i] = update
	}
	v.sink.OnUpdates(filteredUpdates)
}
