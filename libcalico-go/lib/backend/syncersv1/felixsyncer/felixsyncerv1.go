// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package felixsyncer

import (
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/remotecluster"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

const (
	calicoClientID = "calico"
	k8sClientID    = "ks"
)

// New creates a new Felix v1 Syncer.
func New(calicoClient api.Client, cfg apiconfig.CalicoAPIConfigSpec, callbacks api.SyncerCallbacks, includeServices bool, isLeader bool) api.Syncer {
	// Always include the Calico client.
	clients := map[string]api.Client{
		calicoClientID: calicoClient,
	}
	k8sClientSet := k8s.BestEffortGetKubernetesClientSet(calicoClient, &cfg)

	// Felix always needs ClusterInformation and FelixConfiguration resources.
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindClusterInformation},
			UpdateProcessor: updateprocessors.NewClusterInfoUpdateProcessor(),
			ClientID:        calicoClientID, // This is backed by the calico client
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindLicenseKey},
			UpdateProcessor: updateprocessors.NewLicenseKeyUpdateProcessor(),
			ClientID:        calicoClientID, // This is backed by the calico client
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindFelixConfiguration},
			UpdateProcessor: updateprocessors.NewFelixConfigUpdateProcessor(),
			ClientID:        calicoClientID, // This is backed by the calico client
		},
	}

	if isLeader {
		// These resources are only required if this is the active Felix instance on the node.
		additionalTypes := []watchersyncer.ResourceType{
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkPolicy},
				UpdateProcessor: updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindStagedGlobalNetworkPolicy},
				UpdateProcessor: updateprocessors.NewStagedGlobalNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindGlobalNetworkSet},
				UpdateProcessor: updateprocessors.NewGlobalNetworkSetUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindIPPool},
				UpdateProcessor: updateprocessors.NewIPPoolUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: libapiv3.KindNode},
				UpdateProcessor: updateprocessors.NewFelixNodeUpdateProcessor(cfg.K8sUsePodCIDR),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindProfile},
				UpdateProcessor: updateprocessors.NewProfileUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: libapiv3.KindWorkloadEndpoint},
				UpdateProcessor: updateprocessors.NewWorkloadEndpointUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindNetworkPolicy},
				UpdateProcessor: updateprocessors.NewNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindStagedNetworkPolicy},
				UpdateProcessor: updateprocessors.NewStagedNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindStagedKubernetesNetworkPolicy},
				UpdateProcessor: updateprocessors.NewStagedKubernetesNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindNetworkSet},
				UpdateProcessor: updateprocessors.NewNetworkSetUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindTier},
				UpdateProcessor: updateprocessors.NewTierUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindHostEndpoint},
				UpdateProcessor: updateprocessors.NewHostEndpointUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindRemoteClusterConfiguration},
				UpdateProcessor: nil,            // No need to process the updates so pass nil
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindPacketCapture},
				UpdateProcessor: nil,            // No need to process the updates so pass nil
				ClientID:        calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface: model.ResourceListOptions{Kind: apiv3.KindBGPConfiguration},
				ClientID:      calicoClientID, // This is backed by the calico client
			},
			{
				ListInterface: model.ResourceListOptions{Kind: apiv3.KindExternalNetwork},
				ClientID:      calicoClientID,
			},
			{
				ListInterface: model.ResourceListOptions{Kind: apiv3.KindEgressGatewayPolicy},
				ClientID:      calicoClientID,
			},
			{
				ListInterface: model.ResourceListOptions{Kind: apiv3.KindBGPPeer},
				ClientID:      calicoClientID,
			},
		}

		// If running in kdd mode, also watch Kubernetes network policies directly.
		// We don't need this in etcd mode, since kube-controllers copies k8s resources into etcd.
		if cfg.DatastoreType == apiconfig.Kubernetes {
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface:   model.ResourceListOptions{Kind: model.KindKubernetesNetworkPolicy},
				UpdateProcessor: updateprocessors.NewNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			})
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface:   model.ResourceListOptions{Kind: model.KindKubernetesAdminNetworkPolicy},
				UpdateProcessor: updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			})
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface:   model.ResourceListOptions{Kind: model.KindKubernetesBaselineAdminNetworkPolicy},
				UpdateProcessor: updateprocessors.NewGlobalNetworkPolicyUpdateProcessor(),
				ClientID:        calicoClientID, // This is backed by the calico client
			})
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface: model.ResourceListOptions{Kind: model.KindKubernetesEndpointSlice},
				ClientID:      calicoClientID, // This is backed by the calico client
			})
			additionalTypes = append(additionalTypes, watchersyncer.ResourceType{
				ListInterface: model.ResourceListOptions{Kind: model.KindKubernetesService},
				ClientID:      calicoClientID, // This is backed by the calico client
			})
		}

		resourceTypes = append(resourceTypes, additionalTypes...)

		// If using Calico IPAM, include IPAM resources that felix cares about.
		if !cfg.K8sUsePodCIDR {
			additionalTypes := []watchersyncer.ResourceType{{
				ListInterface:   model.BlockListOptions{},
				UpdateProcessor: nil,
				ClientID:        calicoClientID, // This is backed by the calico client
			}}
			resourceTypes = append(resourceTypes, additionalTypes...)
		}

		if includeServices && k8sClientSet != nil {
			// We have a k8s clientset so we can also include services and endpoints in our sync'd data.  We'll use a
			// special k8s wrapped client for this (which is a calico API wrapped k8s API).
			clients[k8sClientID] = k8s.NewK8sResourceWrapperClient(k8sClientSet)
			additionalTypes = []watchersyncer.ResourceType{{
				ListInterface:   model.ResourceListOptions{Kind: model.KindKubernetesService},
				UpdateProcessor: nil,         // No need to process the updates so pass nil
				ClientID:        k8sClientID, // This is backed by the kubernetes wrapped client
			}}
			/* Future: Include k8s endpoints for service categorization from LB IP direct to endpoint.
			{
				ListInterface:   model.ResourceListOptions{Kind: apiv3.KindK8sEndpoints},
				UpdateProcessor: nil,         // No need to process the updates so pass nil
				ClientID:        k8sClientID, // This is backed by the kubernetes wrapped client
			}
			*/
			resourceTypes = append(resourceTypes, additionalTypes...)
		}
	}

	// The "main" watchersyncer will spawn additional watchersyncers for any remote clusters that are found.
	// The callbacks are wrapped to allow the messages to be intercepted so that the additional watchersyncers can be spawned.
	return watchersyncer.NewMultiClient(
		clients,
		resourceTypes,
		remotecluster.NewWrappedCallbacks(callbacks, k8sClientSet, felixRemoteClusterProcessor{}),
	)
}

// felixRemoteClusterProcessor provides the Felix syncer specific remote cluster processing.
// Remote resource updates that Felix can treat equivalently to local resource updates have their key types preserved, and key names prefixed.
// Remote resource updates that Felix can NOT treat equivalently have their keys wrapped in a RemoteClusterResourceKey.
type felixRemoteClusterProcessor struct{}

func (_ felixRemoteClusterProcessor) CreateResourceTypes(overlayRoutingMode apiv3.OverlayRoutingMode, usePodCIDR bool) []watchersyncer.ResourceType {
	resourceTypes := []watchersyncer.ResourceType{
		{
			ListInterface:   model.ResourceListOptions{Kind: libapiv3.KindWorkloadEndpoint},
			UpdateProcessor: updateprocessors.NewWorkloadEndpointUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindHostEndpoint},
			UpdateProcessor: updateprocessors.NewHostEndpointUpdateProcessor(),
		},
		{
			ListInterface:   model.ResourceListOptions{Kind: apiv3.KindProfile},
			UpdateProcessor: updateprocessors.NewProfileUpdateProcessor(),
		},
	}

	if overlayRoutingMode == apiv3.OverlayRoutingModeEnabled {
		resourceTypes = append(resourceTypes, []watchersyncer.ResourceType{
			{
				ListInterface:   model.ResourceListOptions{Kind: libapiv3.KindNode},
				UpdateProcessor: updateprocessors.NewFelixNodeUpdateProcessor(usePodCIDR),
			},
			// Remote IP pool updates should not utilize the same update as local, as this would remove the updates guarantee of disjoint CIDRs.
			{
				ListInterface: model.ResourceListOptions{Kind: apiv3.KindIPPool},
				// Relay the full v3 Resource, we'll replace its key with a RemoteClusterResourceKey (this key requires a Resource value).
				UpdateProcessor: nil,
			},
			// Remote block updates should not utilize the same update as local, as this would remove the updates guarantee of disjoint CIDRs.
			{
				// The Resource interface is not used for operations on the V1/backend API involving Blocks, so we will not receive a v3 Resource value.
				ListInterface: model.BlockListOptions{},
				// Relay the v1 resource. We'll convert it to a v3 Resource representation so that we can key it with a RemoteClusterResourceKey.
				UpdateProcessor: nil,
			},
		}...)
	}

	return resourceTypes
}

func (_ felixRemoteClusterProcessor) ConvertUpdates(clusterName string, updates []api.Update) (propagatedUpdates []api.Update) {
	for i, update := range updates {
		if update.UpdateType == api.UpdateTypeKVUpdated || update.UpdateType == api.UpdateTypeKVNew {
			switch t := update.Key.(type) {
			default:
				log.Warnf("unexpected type %T\n", t)
			case model.HostEndpointKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
				for profileIndex, profile := range updates[i].Value.(*model.HostEndpoint).ProfileIDs {
					updates[i].Value.(*model.HostEndpoint).ProfileIDs[profileIndex] = clusterName + "/" + profile
				}
			case model.WorkloadEndpointKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
				for profileIndex, profile := range updates[i].Value.(*model.WorkloadEndpoint).ProfileIDs {
					updates[i].Value.(*model.WorkloadEndpoint).ProfileIDs[profileIndex] = clusterName + "/" + profile
				}
			case model.ProfileRulesKey:
				t.Name = clusterName + "/" + t.Name
				updates[i].Value.(*model.ProfileRules).InboundRules = nil
				updates[i].Value.(*model.ProfileRules).OutboundRules = nil
				updates[i].Key = t
			case model.ProfileLabelsKey:
				t.Name = clusterName + "/" + t.Name
				updates[i].Key = t
			case model.HostIPKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
			case model.HostConfigKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
			case model.WireguardKey:
				t.NodeName = clusterName + "/" + t.NodeName
				updates[i].Key = t
			case model.ResourceKey:
				switch t.Kind {
				case apiv3.KindProfile:
					// v3 Profile resource is federated because it carries
					// labels that may be inherited by endpoints.  This replaces
					// federation of the legacy v1 ProfileLabels object.
					t.Name = clusterName + "/" + t.Name
					updates[i].Value.(*apiv3.Profile).Spec.Ingress = nil
					updates[i].Value.(*apiv3.Profile).Spec.Egress = nil
					updates[i].Key = t
				case libapiv3.KindNode:
					t.Name = clusterName + "/" + t.Name
					updates[i].Key = t
				case apiv3.KindIPPool:
					rk := updates[i].Key.(model.ResourceKey)
					rcrk := model.RemoteClusterResourceKey{
						Cluster:     clusterName,
						ResourceKey: rk,
					}
					updates[i].Key = rcrk
				default:
					log.Panicf("Don't expect to federate other v3 resources (%v)", t)
				}
			case model.BlockKey:
				// Convert the v1 object to the internal v3 Resource object.
				v3KVPair := resources.IPAMBlockV1toV3(&updates[i].KVPair)
				v3Block := v3KVPair.Value.(*libapiv3.IPAMBlock)
				v3Block.APIVersion = apiv3.GroupVersionCurrent

				// Prefix any node references with the cluster name.
				if v3Block.Spec.Affinity != nil {
					affinity := "host:" + clusterName + "/" + strings.TrimPrefix(*v3Block.Spec.Affinity, "host:")
					v3Block.Spec.Affinity = &affinity
				}
				for _, attribute := range v3Block.Spec.Attributes {
					if node, ok := attribute.AttrSecondary[ipam.AttributeNode]; ok {
						attribute.AttrSecondary[ipam.AttributeNode] = clusterName + "/" + node
					}
				}

				remoteKey := model.RemoteClusterResourceKey{
					Cluster:     clusterName,
					ResourceKey: v3KVPair.Key.(model.ResourceKey),
				}
				updates[i].Key = remoteKey
				updates[i].Value = v3Block
			}
		} else if update.UpdateType == api.UpdateTypeKVDeleted {
			switch t := update.Key.(type) {
			default:
				log.Warnf("unexpected type %T\n", t)
			case model.HostEndpointKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
			case model.WorkloadEndpointKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
			case model.ProfileRulesKey:
				t.Name = clusterName + "/" + t.Name
				updates[i].Key = t
			case model.ProfileLabelsKey:
				t.Name = clusterName + "/" + t.Name
				updates[i].Key = t
			case model.HostIPKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
			case model.HostConfigKey:
				t.Hostname = clusterName + "/" + t.Hostname
				updates[i].Key = t
			case model.WireguardKey:
				t.NodeName = clusterName + "/" + t.NodeName
				updates[i].Key = t
			case model.ResourceKey:
				switch t.Kind {
				case apiv3.KindProfile:
					// v3 Profile resource is federated because it carries
					// labels that may be inherited by endpoints.  This replaces
					// federation of the legacy v1 ProfileLabels object.
					t.Name = clusterName + "/" + t.Name
					updates[i].Key = t
				case libapiv3.KindNode:
					t.Name = clusterName + "/" + t.Name
					updates[i].Key = t
				case apiv3.KindIPPool:
					rk := updates[i].Key.(model.ResourceKey)
					rcrk := model.RemoteClusterResourceKey{
						Cluster:     clusterName,
						ResourceKey: rk,
					}
					updates[i].Key = rcrk
				default:
					log.Panicf("Don't expect to federate other v3 resources (%v)", t)
				}
			case model.BlockKey:
				name := names.CIDRToName(t.CIDR)
				key := model.ResourceKey{
					Name: name,
					Kind: libapiv3.KindIPAMBlock,
				}
				remoteKey := model.RemoteClusterResourceKey{
					Cluster:     clusterName,
					ResourceKey: key,
				}
				updates[i].Key = remoteKey
			}
		}
		propagatedUpdates = append(propagatedUpdates, updates[i])
	}

	return
}

func (_ felixRemoteClusterProcessor) GetCalicoAPIConfig(config *apiv3.RemoteClusterConfiguration) *apiconfig.CalicoAPIConfig {
	datastoreConfig := apiconfig.NewCalicoAPIConfig()
	datastoreConfig.Spec.DatastoreType = apiconfig.DatastoreType(config.Spec.DatastoreType)
	switch datastoreConfig.Spec.DatastoreType {
	case apiconfig.EtcdV3:
		datastoreConfig.Spec.EtcdEndpoints = config.Spec.EtcdEndpoints
		datastoreConfig.Spec.EtcdUsername = config.Spec.EtcdUsername
		datastoreConfig.Spec.EtcdPassword = config.Spec.EtcdPassword
		datastoreConfig.Spec.EtcdKeyFile = config.Spec.EtcdKeyFile
		datastoreConfig.Spec.EtcdCertFile = config.Spec.EtcdCertFile
		datastoreConfig.Spec.EtcdCACertFile = config.Spec.EtcdCACertFile
		datastoreConfig.Spec.EtcdKey = config.Spec.EtcdKey
		datastoreConfig.Spec.EtcdCert = config.Spec.EtcdCert
		datastoreConfig.Spec.EtcdCACert = config.Spec.EtcdCACert
		return datastoreConfig
	case apiconfig.Kubernetes:
		datastoreConfig.Spec.Kubeconfig = config.Spec.Kubeconfig
		datastoreConfig.Spec.K8sAPIEndpoint = config.Spec.K8sAPIEndpoint
		datastoreConfig.Spec.K8sKeyFile = config.Spec.K8sKeyFile
		datastoreConfig.Spec.K8sCertFile = config.Spec.K8sCertFile
		datastoreConfig.Spec.K8sCAFile = config.Spec.K8sCAFile
		datastoreConfig.Spec.K8sAPIToken = config.Spec.K8sAPIToken
		datastoreConfig.Spec.K8sInsecureSkipTLSVerify = config.Spec.K8sInsecureSkipTLSVerify
		datastoreConfig.Spec.KubeconfigInline = config.Spec.KubeconfigInline
		return datastoreConfig
	}
	return nil
}
