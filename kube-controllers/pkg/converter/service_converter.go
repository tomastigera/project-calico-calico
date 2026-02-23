// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
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

package converter

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8svalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	// Any service with those annotations will be excluded from networkset management
	ExcludeServiceAnnotation          = "networksets.projectcalico.org/exclude"
	ExcludeFederetedServiceAnnotation = "federation.tigera.io/serviceSelector"
)

const (
	// Following annotations will be added to NetworkSet created by service controller
	NsServiceNameAnnotation = "endpoints.projectcalico.org/serviceName"
	NsPortsAnnotation       = "endpoints.projectcalico.org/ports"
	NsProtocolsAnnotation   = "endpoints.projectcalico.org/protocols"

	// Following label will be added to NetworkSet created by service controller
	NsServiceNameLabel = "endpoints.projectcalico.org/serviceName"

	// NetworkSet created/managed by this controller will have following name prefix
	NetworkSetNamePrefix = "kse."

	// HashedNameLength is the length of hashed service name
	HashedNameLength = 10
)

// ErrorServiceMustBeIgnored indicates that conversion did not happen because
// service must be excluded from the NetworkSet management
type ErrorServiceMustBeIgnored struct {
	err string
}

func (e *ErrorServiceMustBeIgnored) Error() string {
	return e.err
}

type serviceConverter struct{}

// NewServiceConverter Constructor for serviceConverter
func NewServiceConverter() Converter {
	return &serviceConverter{}
}

// IsServiceToBeExcluded returns true if service should be excluded from networkset management.
func (s *serviceConverter) isServiceToBeExcluded(service *corev1.Service) bool {
	key := s.GetKey(service)
	clog := log.WithField("key", key)

	if len(service.Spec.Selector) != 0 {
		clog.Debug("Service has not empty selector. Ignoring it")
		return true
	}

	if len(service.Spec.ExternalName) != 0 {
		clog.Info("Service is ExternalName type. Ignoring it")
		return true
	}

	if _, ok := service.Annotations[ExcludeServiceAnnotation]; ok {
		clog.Info("Service annotation indicate to exclude service. Ignoring it")
		return true
	}

	if _, ok := service.Annotations[ExcludeFederetedServiceAnnotation]; ok {
		clog.Info("Service annotation indicate to exclude service. Ignoring it")
		return true
	}

	return false
}

// Convert takes a Kubernetes Service and returns a Calico api.NetworkSet representation.
func (s *serviceConverter) Convert(k8sObj any) (any, error) {
	service, ok := k8sObj.(*corev1.Service)

	if !ok {
		tombstone, ok := k8sObj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %+v", k8sObj)
		}
		service, ok = tombstone.Obj.(*corev1.Service)
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not a Service %+v", k8sObj)
		}
	}

	if s.isServiceToBeExcluded(service) {
		return nil, &ErrorServiceMustBeIgnored{"Service must not be excluded from networkset management"}
	}

	kvp, err := s.k8sServiceToNetworkSet(service)
	if err != nil {
		return nil, err
	}

	ns := kvp.Value.(*api.NetworkSet)

	// Isolate the metadata fields that we care about. ResourceVersion, CreationTimeStamp, etc are
	// not relevant so we ignore them. This prevents uncessary updates.
	ns.ObjectMeta = metav1.ObjectMeta{Name: ns.Name, Namespace: ns.Namespace, Annotations: ns.Annotations, Labels: ns.Labels}

	return *ns, err
}

// GetKey gets a K8s Services an returns the 'namespace/name' for the Calico NetworkSet as its key.
func (s *serviceConverter) GetKey(obj any) string {
	k8sResource := obj.(*corev1.Service)
	if len(k8sResource.Name)+len(NetworkSetNamePrefix) > k8svalidation.DNS1123SubdomainMaxLength {
		return fmt.Sprintf("%s/%s%s", k8sResource.Namespace, NetworkSetNamePrefix, hashName(k8sResource.Name))
	}
	return fmt.Sprintf("%s/%s%s", k8sResource.Namespace, NetworkSetNamePrefix, k8sResource.Name)
}

func (s *serviceConverter) DeleteArgsFromKey(key string) (string, string) {
	splits := strings.SplitN(key, "/", 2)
	return splits[0], splits[1]
}

// K8sServiceToNetworkSet converts a k8s Service to a NetworkSet.
// The NetworkSet will have:
// name = NetworkSetNamePrefix+<service name> (or hash(service name) if prefix+name would be longer than max allowed)
// namespace = <service namespace>
// labels = <service labeles> + extra label NetworkSetNamePrefix:<service name>
// at least one annotations added. Other two added if service ports/protocols are not nil
func (s *serviceConverter) k8sServiceToNetworkSet(service *corev1.Service) (*model.KVPair, error) {
	// Pull out important fields.
	key := s.GetKey(service)
	nsNamespace, nsName := s.DeleteArgsFromKey(key)

	// Create the NetworkSet.
	ns := api.NewNetworkSet()
	ns.ObjectMeta = metav1.ObjectMeta{
		Name:        nsName,
		Namespace:   nsNamespace,
		Annotations: make(map[string]string),
	}

	ns.Annotations[NsServiceNameAnnotation] = service.Name

	if len(service.Spec.Ports) != 0 {
		ns.Annotations[NsPortsAnnotation] = ""
		ns.Annotations[NsProtocolsAnnotation] = ""

		// Collect ports && protocol
		ports := make([]string, len(service.Spec.Ports))
		protocols := make([]string, len(service.Spec.Ports))
		for i := range service.Spec.Ports {
			ports[i] = service.Spec.Ports[i].TargetPort.String()
			protocols[i] = string(service.Spec.Ports[i].Protocol)
		}

		ports = sliceUniqMap(ports)
		sort.Slice(ports, func(i, j int) bool {
			numA, _ := strconv.Atoi(ports[i])
			numB, _ := strconv.Atoi(ports[j])
			return numA < numB
		})

		protocols = sliceUniqMap(protocols)
		sort.Slice(protocols, func(i, j int) bool {
			numA, _ := strconv.Atoi(protocols[i])
			numB, _ := strconv.Atoi(protocols[j])
			return numA < numB
		})

		ns.Annotations[NsPortsAnnotation] += strings.Join(ports, ",")
		ns.Annotations[NsProtocolsAnnotation] += strings.Join(protocols, ",")
	}

	ns.Labels = make(map[string]string)
	for l := range service.Labels {
		ns.Labels[l] = service.Labels[l]
	}

	ns.Labels[NsServiceNameLabel] = service.Name

	// Build and return the KVPair.
	return &model.KVPair{
		Key: model.ResourceKey{
			Name:      nsName,
			Namespace: service.Namespace,
			Kind:      api.KindNetworkSet,
		},
		Value: ns,
	}, nil
}

type endpointConverter struct{}

// NewEndpointConverter Constructor for endpointConverter
func NewEndpointConverter() Converter {
	return &endpointConverter{}
}

// Convert takes a Kubernetes Endpoint and returns a Calico api.NetworkSet representation if corresponding NetworkSet already exists.
func (s *endpointConverter) Convert(k8sObj any) (any, error) {
	ep, ok := k8sObj.(*corev1.Endpoints) //nolint:staticcheck

	if !ok {
		tombstone, ok := k8sObj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return nil, fmt.Errorf("couldn't get object from tombstone %+v", k8sObj)
		}
		ep, ok = tombstone.Obj.(*corev1.Endpoints) //nolint:staticcheck
		if !ok {
			return nil, fmt.Errorf("tombstone contained object that is not an Endpoint %+v", k8sObj)
		}
	}

	kvp, err := s.k8sEndpointToNetworkSet(ep)
	if err != nil {
		return nil, err
	}
	cns := kvp.Value.(*api.NetworkSet)

	// Isolate the metadata fields that we care about. This prevents uncessary updates.
	cns.ObjectMeta = metav1.ObjectMeta{Name: cns.Name, Namespace: cns.Namespace}

	return *cns, err
}

// GetKey gets a K8s Endpoint an returns the 'namespace/name' for the Calico NetworkSet as its key.
func (s *endpointConverter) GetKey(obj any) string {
	k8sResource := obj.(*corev1.Endpoints) //nolint:staticcheck
	if len(k8sResource.Name)+len(NetworkSetNamePrefix) > k8svalidation.DNS1123SubdomainMaxLength {
		return fmt.Sprintf("%s/%s%s", k8sResource.Namespace, NetworkSetNamePrefix, hashName(k8sResource.Name))
	}
	return fmt.Sprintf("%s/%s%s", k8sResource.Namespace, NetworkSetNamePrefix, k8sResource.Name)
}

func (s *endpointConverter) DeleteArgsFromKey(key string) (string, string) {
	splits := strings.SplitN(key, "/", 2)
	return splits[0], splits[1]
}

// K8sEndpointToNetworkSet converts a k8s Endpoints to a NetworkSet.
// K8sServiceToNetworkSet converts a k8s Service to a NetworkSet.
// The NetworkSet will have:
// name = NetworkSetNamePrefix+<service name> (or hash(service name) if prefix+name would be longer than max allowed)
// namespace = <service namespace>
// spec.Nets = endpoints addresses
func (s *endpointConverter) k8sEndpointToNetworkSet(ep *corev1.Endpoints) (*model.KVPair, error) { //nolint:staticcheck
	// Pull out important fields.
	key := s.GetKey(ep)
	nsNamespace, nsName := s.DeleteArgsFromKey(key)

	// TODO: mgianluc: what if
	// 1) Endpoints configuration does not match Service one, for instance Endpoint ports is different than Service targetPorts

	// Create the NetworkSet: only fields used are name, namespace and subsets.
	// If any other field is used when converting from Endpoints to NetworkSet, change also onEndpointsUpdate
	ns := api.NewNetworkSet()
	ns.ObjectMeta = metav1.ObjectMeta{
		Name:      nsName,
		Namespace: nsNamespace,
	}

	// Note that a NetworkSet does not include port and protocol information for each endpoint IP
	// and they could be different for each endpoint in the service.
	// We are collecting only IP addresses, ignoring ports
	ipAddressMaps := make(map[string]bool)
	for _, subset := range ep.Subsets {
		for _, address := range subset.Addresses {
			ipAddressMaps[address.IP] = true
		}
		for _, address := range subset.NotReadyAddresses {
			ipAddressMaps[address.IP] = true
		}
	}

	i := 0
	ns.Spec.Nets = make([]string, len(ipAddressMaps))
	for k := range ipAddressMaps {
		ns.Spec.Nets[i] = k
		i++
	}
	sort.Strings(ns.Spec.Nets)

	// Build and return the KVPair.
	return &model.KVPair{
		Key: model.ResourceKey{
			Name:      nsName,
			Namespace: ep.Namespace,
			Kind:      api.KindNetworkSet,
		},
		Value: ns,
	}, nil
}

func sliceUniqMap(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	j := 0
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		s[j] = v
		j++
	}
	return s[:j]
}

func hashName(name string) string {
	hasher := sha1.New()
	if _, err := hasher.Write([]byte(name)); err != nil {
		return name
	}
	h := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return h[0:HashedNameLength]
}
