// Copyright (c) 2016-2023 Tigera, Inc. All rights reserved.
//
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

package model

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	kapiv1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/labels"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/namespace"
)

// Name/type information about a single resource.
type resourceInfo struct {
	typeOf    reflect.Type
	plural    string
	kindLower string
	kind      string
}

var (
	matchGlobalResource     = regexp.MustCompile("^/calico/resources/v3/projectcalico[.]org/([^/]+)/([^/]+)$")
	matchNamespacedResource = regexp.MustCompile("^/calico/resources/v3/projectcalico[.]org/([^/]+)/([^/]+)/([^/]+)$")
	resourceInfoByKindLower = make(map[string]resourceInfo)
	resourceInfoByPlural    = make(map[string]resourceInfo)
)

func registerResourceInfo(kind string, plural string, typeOf reflect.Type) {
	kindLower := strings.ToLower(kind)
	plural = strings.ToLower(plural)
	ri := resourceInfo{
		typeOf:    typeOf,
		kindLower: kindLower,
		kind:      kind,
		plural:    plural,
	}
	resourceInfoByKindLower[kindLower] = ri
	resourceInfoByPlural[plural] = ri
}

func AllResourcePlurals() []string {
	plurals := make([]string, 0, len(resourceInfoByPlural))
	for plural := range resourceInfoByPlural {
		plurals = append(plurals, plural)
	}
	return plurals
}

func init() {
	registerResourceInfo(
		apiv3.KindBGPPeer,
		"bgppeers",
		reflect.TypeOf(apiv3.BGPPeer{}),
	)
	registerResourceInfo(
		apiv3.KindBGPConfiguration,
		"bgpconfigurations",
		reflect.TypeOf(apiv3.BGPConfiguration{}),
	)
	registerResourceInfo(
		apiv3.KindClusterInformation,
		"clusterinformations",
		reflect.TypeOf(apiv3.ClusterInformation{}),
	)
	registerResourceInfo(
		apiv3.KindLicenseKey,
		"licensekeys",
		reflect.TypeOf(apiv3.LicenseKey{}),
	)
	registerResourceInfo(
		apiv3.KindFelixConfiguration,
		"felixconfigurations",
		reflect.TypeOf(apiv3.FelixConfiguration{}),
	)
	registerResourceInfo(
		apiv3.KindGlobalNetworkPolicy,
		"globalnetworkpolicies",
		reflect.TypeOf(apiv3.GlobalNetworkPolicy{}),
	)
	registerResourceInfo(
		apiv3.KindStagedGlobalNetworkPolicy,
		"stagedglobalnetworkpolicies",
		reflect.TypeOf(apiv3.StagedGlobalNetworkPolicy{}),
	)
	registerResourceInfo(
		apiv3.KindHostEndpoint,
		"hostendpoints",
		reflect.TypeOf(apiv3.HostEndpoint{}),
	)
	registerResourceInfo(
		apiv3.KindGlobalNetworkSet,
		"globalnetworksets",
		reflect.TypeOf(apiv3.GlobalNetworkSet{}),
	)
	registerResourceInfo(
		KindKubernetesAdminNetworkPolicy,
		"kubernetesadminnetworkpolicies",
		reflect.TypeOf(apiv3.GlobalNetworkPolicy{}),
	)
	registerResourceInfo(
		KindKubernetesBaselineAdminNetworkPolicy,
		"kubernetesbaselineadminnetworkpolicies",
		reflect.TypeOf(apiv3.GlobalNetworkPolicy{}),
	)
	registerResourceInfo(
		apiv3.KindIPPool,
		"ippools",
		reflect.TypeOf(apiv3.IPPool{}),
	)
	registerResourceInfo(
		apiv3.KindIPReservation,
		"ipreservations",
		reflect.TypeOf(apiv3.IPReservation{}),
	)
	registerResourceInfo(
		apiv3.KindNetworkPolicy,
		"networkpolicies",
		reflect.TypeOf(apiv3.NetworkPolicy{}),
	)
	registerResourceInfo(

		apiv3.KindStagedNetworkPolicy,
		"stagednetworkpolicies",
		reflect.TypeOf(apiv3.StagedNetworkPolicy{}),
	)
	registerResourceInfo(
		apiv3.KindStagedKubernetesNetworkPolicy,
		"stagedkubernetesnetworkpolicies",
		reflect.TypeOf(apiv3.StagedKubernetesNetworkPolicy{}),
	)
	registerResourceInfo(
		KindKubernetesNetworkPolicy,
		"kubernetesnetworkpolicies",
		reflect.TypeOf(apiv3.NetworkPolicy{}),
	)
	registerResourceInfo(
		KindKubernetesEndpointSlice,
		"kubernetesendpointslices",
		reflect.TypeOf(discovery.EndpointSlice{}),
	)
	registerResourceInfo(
		apiv3.KindNetworkSet,
		"networksets",
		reflect.TypeOf(apiv3.NetworkSet{}),
	)
	registerResourceInfo(
		apiv3.KindTier,
		"tiers",
		reflect.TypeOf(apiv3.Tier{}),
	)
	registerResourceInfo(
		apiv3.KindUISettingsGroup,
		"uisettingsgroups",
		reflect.TypeOf(apiv3.UISettingsGroup{}),
	)
	registerResourceInfo(
		apiv3.KindUISettings,
		"uisettings",
		reflect.TypeOf(apiv3.UISettings{}),
	)
	registerResourceInfo(
		libapiv3.KindNode,
		"nodes",
		reflect.TypeOf(libapiv3.Node{}),
	)
	registerResourceInfo(
		apiv3.KindCalicoNodeStatus,
		"caliconodestatuses",
		reflect.TypeOf(apiv3.CalicoNodeStatus{}),
	)
	registerResourceInfo(
		apiv3.KindProfile,
		"profiles",
		reflect.TypeOf(apiv3.Profile{}),
	)
	registerResourceInfo(
		libapiv3.KindWorkloadEndpoint,
		"workloadendpoints",
		reflect.TypeOf(libapiv3.WorkloadEndpoint{}),
	)
	registerResourceInfo(
		libapiv3.KindIPAMConfig,
		"ipamconfigs",
		reflect.TypeOf(libapiv3.IPAMConfig{}),
	)
	registerResourceInfo(
		apiv3.KindKubeControllersConfiguration,
		"kubecontrollersconfigurations",
		reflect.TypeOf(apiv3.KubeControllersConfiguration{}),
	)
	registerResourceInfo(
		apiv3.KindRemoteClusterConfiguration,
		"remoteclusterconfigurations",
		reflect.TypeOf(apiv3.RemoteClusterConfiguration{}),
	)
	registerResourceInfo(
		apiv3.KindGlobalAlert,
		"globalalerts",
		reflect.TypeOf(apiv3.GlobalAlert{}),
	)
	registerResourceInfo(
		apiv3.KindGlobalAlertTemplate,
		"globalalerttemplates",
		reflect.TypeOf(apiv3.GlobalAlertTemplate{}),
	)
	registerResourceInfo(
		apiv3.KindGlobalThreatFeed,
		"globalthreatfeeds",
		reflect.TypeOf(apiv3.GlobalThreatFeed{}),
	)
	registerResourceInfo(
		apiv3.KindGlobalReportType,
		"globalreporttypes",
		reflect.TypeOf(apiv3.GlobalReportType{}),
	)
	registerResourceInfo(
		apiv3.KindGlobalReport,
		"globalreports",
		reflect.TypeOf(apiv3.GlobalReport{}),
	)
	registerResourceInfo(
		apiv3.KindManagedCluster,
		"managedclusters",
		reflect.TypeOf(apiv3.ManagedCluster{}),
	)
	registerResourceInfo(
		apiv3.KindPacketCapture,
		"packetcaptures",
		reflect.TypeOf(apiv3.PacketCapture{}),
	)
	registerResourceInfo(
		apiv3.KindDeepPacketInspection,
		"deeppacketinspections",
		reflect.TypeOf(apiv3.DeepPacketInspection{}),
	)
	// Resources that are translations of Kubernetes resources and effectively read-only representations.
	registerResourceInfo(
		apiv3.KindK8sEndpoints,
		"k8s-endpoints",
		reflect.TypeOf(kapiv1.Endpoints{}),
	)
	registerResourceInfo(
		KindKubernetesService,
		"kubernetesservice",
		reflect.TypeOf(kapiv1.Service{}),
	)
	registerResourceInfo(
		libapiv3.KindBlockAffinity,
		"blockaffinities",
		reflect.TypeOf(libapiv3.BlockAffinity{}),
	)
	registerResourceInfo(
		apiv3.KindBGPFilter,
		"BGPFilters",
		reflect.TypeOf(apiv3.BGPFilter{}),
	)
	registerResourceInfo(
		apiv3.KindExternalNetwork,
		"ExternalNetworks",
		reflect.TypeOf(apiv3.ExternalNetwork{}),
	)
	registerResourceInfo(
		apiv3.KindEgressGatewayPolicy,
		"EgressGatewayPolicies",
		reflect.TypeOf(apiv3.EgressGatewayPolicy{}),
	)
	registerResourceInfo(
		apiv3.KindSecurityEventWebhook,
		"SecurityEventWebhooks",
		reflect.TypeOf(apiv3.SecurityEventWebhook{}),
	)
	registerResourceInfo(
		apiv3.KindBFDConfiguration,
		"bfdconfigurations",
		reflect.TypeOf(apiv3.BFDConfiguration{}),
	)

	// Resources that may be transported in a ResourceKey but are not part of the public API, for use-cases like Federation.
	registerResourceInfo(
		libapiv3.KindIPAMBlock,
		"ipamblocks",
		reflect.TypeOf(libapiv3.IPAMBlock{}),
	)
}

type ResourceKey struct {
	// The name of the resource.
	Name string
	// The namespace of the resource.  Not required if the resource is not namespaced.
	Namespace string
	// The resource kind.
	Kind string
}

func (key ResourceKey) defaultPath() (string, error) {
	return key.defaultDeletePath()
}

func (key ResourceKey) defaultDeletePath() (string, error) {
	ri, ok := resourceInfoByKindLower[strings.ToLower(key.Kind)]
	if !ok {
		return "", fmt.Errorf("couldn't convert key: %+v", key)
	}
	if namespace.IsNamespaced(key.Kind) {
		return fmt.Sprintf("/calico/resources/v3/projectcalico.org/%s/%s/%s", ri.plural, key.Namespace, escapeName(key.Name)), nil
	}
	return fmt.Sprintf("/calico/resources/v3/projectcalico.org/%s/%s", ri.plural, escapeName(key.Name)), nil
}

func (key ResourceKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key ResourceKey) valueType() (reflect.Type, error) {
	ri, ok := resourceInfoByKindLower[strings.ToLower(key.Kind)]
	if !ok {
		return nil, fmt.Errorf("unexpected resource kind: %s", key.Kind)
	}
	return ri.typeOf, nil
}

func (key ResourceKey) String() string {
	if namespace.IsNamespaced(key.Kind) {
		return fmt.Sprintf("%s(%s/%s)", key.Kind, key.Namespace, key.Name)
	}
	return fmt.Sprintf("%s(%s)", key.Kind, key.Name)
}

// GetNamespace returns the namespace field of the ResourceKey.
func (key ResourceKey) GetNamespace() string {
	return key.Namespace
}

type ResourceListOptions struct {
	// The name of the resource.
	Name string
	// The namespace of the resource.  Not required if the resource is not namespaced.
	Namespace string
	// The resource kind.
	Kind string
	// Whether the name is prefix rather than the full name.  This is only
	// supported efficiently by the etcd API.  When using the Kubernetes API,
	// a full list operation is performed and then filtered client-side.
	Prefix bool
	// LabelSelector allows filtering on the labels of the resource. This is
	// supported efficiently by the Kubernetes backend, but the etcd backend
	// implements it client-side.
	LabelSelector labels.Selector
}

func (options ResourceListOptions) GetLabelSelector() labels.Selector {
	return options.LabelSelector
}

var _ LabelSelectingListInterface = ResourceListOptions{}

// If the Kind, Namespace and Name are specified, but the Name is a prefix then the
// last segment of this path is a prefix.
func (options ResourceListOptions) IsLastSegmentIsPrefix() bool {
	return len(options.Kind) != 0 &&
		(len(options.Namespace) != 0 || !namespace.IsNamespaced(options.Kind)) &&
		len(options.Name) != 0 &&
		options.Prefix
}

func (options ResourceListOptions) KeyFromDefaultPath(path string) Key {
	ri, ok := resourceInfoByKindLower[strings.ToLower(options.Kind)]
	if !ok {
		log.Panic("Unexpected resource kind: " + options.Kind)
	}

	if namespace.IsNamespaced(options.Kind) {
		log.Debugf("Get Namespaced Resource key from %s", path)
		r := matchNamespacedResource.FindAllStringSubmatch(path, -1)
		if len(r) != 1 {
			log.Debugf("Didn't match regex")
			return nil
		}
		kindPlural := r[0][1]
		namespace := r[0][2]
		name := unescapeName(r[0][3])
		if len(options.Kind) == 0 {
			panic("Kind must be specified in List option but is not")
		}
		if kindPlural != ri.plural {
			log.Debugf("Didn't match kind %s != %s", kindPlural, ri.plural)
			return nil
		}
		if len(options.Namespace) != 0 && namespace != options.Namespace {
			log.Debugf("Didn't match namespace %s != %s", options.Namespace, namespace)
			return nil
		}
		if len(options.Name) != 0 {
			if options.Prefix && !strings.HasPrefix(name, options.Name) {
				log.Debugf("Didn't match name prefix %s != prefix(%s)", options.Name, name)
				return nil
			} else if !options.Prefix && name != options.Name {
				log.Debugf("Didn't match name %s != %s", options.Name, name)
				return nil
			}
		}
		return ResourceKey{Kind: options.Kind, Namespace: namespace, Name: name}
	}

	log.Debugf("Get Global Resource key from %s", path)
	r := matchGlobalResource.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("Didn't match regex")
		return nil
	}
	kindPlural := r[0][1]
	name := unescapeName(r[0][2])
	if kindPlural != ri.plural {
		log.Debugf("Didn't match kind %s != %s", kindPlural, ri.plural)
		return nil
	}
	if len(options.Name) != 0 {
		if options.Prefix && !strings.HasPrefix(name, options.Name) {
			log.Debugf("Didn't match name prefix %s != prefix(%s)", options.Name, name)
			return nil
		} else if !options.Prefix && name != options.Name {
			log.Debugf("Didn't match name %s != %s", options.Name, name)
			return nil
		}
	}
	return ResourceKey{Kind: options.Kind, Name: name}
}

func (options ResourceListOptions) defaultPathRoot() string {
	ri, ok := resourceInfoByKindLower[strings.ToLower(options.Kind)]
	if !ok {
		log.Panic("Unexpected resource kind: " + options.Kind)
	}

	k := "/calico/resources/v3/projectcalico.org/" + ri.plural
	if namespace.IsNamespaced(options.Kind) {
		if options.Namespace == "" {
			return k
		}
		k = k + "/" + options.Namespace
	}
	if options.Name == "" {
		return k
	}
	return k + "/" + escapeName(options.Name)
}

func (options ResourceListOptions) String() string {
	description := "*"
	if options.Name != "" {
		description = options.Name
	}
	if options.Namespace != "" {
		description = options.Namespace + "/" + description
	}
	if options.Prefix {
		description = description + "*"
	}
	if options.LabelSelector != nil {
		description = description + " matching " + options.LabelSelector.String()
	}
	return fmt.Sprintf("%s(%s)", options.Kind, description)
}
