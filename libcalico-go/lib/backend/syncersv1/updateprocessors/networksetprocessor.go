// Copyright (c) 2019, 2023 Tigera, Inc. All rights reserved.

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

package updateprocessors

import (
	"errors"
	"maps"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	netsetlabels "github.com/projectcalico/calico/libcalico-go/lib/labels"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync NetworkSet data in v1 format for consumption by Felix.
func NewNetworkSetUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(
		apiv3.KindNetworkSet,
		convertNetworkSetV2ToV1Key,
		convertNetworkSetV2ToV1Value,
	)
}

func convertNetworkSetV2ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	if v3key.Kind != apiv3.KindNetworkSet {
		return nil, errors.New("key is not a valid NetworkSet resource")
	}
	if v3key.Name == "" || v3key.Namespace == "" {
		return model.NetworkSetKey{}, errors.New("missing Name or Namespace field to create a v1 NetworkSet Key")
	}
	return model.NetworkSetKey{
		Name: v3key.Namespace + "/" + v3key.Name,
	}, nil
}

func convertNetworkSetV2ToV1Value(val any) (any, error) {
	v3res, ok := val.(*apiv3.NetworkSet)
	if !ok {
		return nil, errors.New("value is not a valid NetworkSet resource value")
	}

	var addrs []cnet.IPNet
	for _, cidrString := range v3res.Spec.Nets {
		_, ipNet, err := cnet.ParseCIDROrIP(string(cidrString))
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"CIDR":       cidrString,
				"networkSet": v3res.GetName(),
			}).Warn("Invalid CIDR")
		}
		addrs = append(addrs, *ipNet)
	}

	// Add in the Calico namespace label for storage purposes. Add in the Kind and Name label for
	// policy recommendation purposes
	labelsWithCalicoNamespace := make(map[string]string, len(v3res.GetLabels()))
	maps.Copy(labelsWithCalicoNamespace, v3res.GetLabels())
	labelsWithCalicoNamespace[apiv3.LabelNamespace] = v3res.Namespace

	if !netsetlabels.ValidateNetworkSetLabels(v3res.Name, labelsWithCalicoNamespace) {
		// Add Kind and Name labels to network set for policy rule mappings.
		netsetlabels.AddKindandNameLabels(v3res.Name, labelsWithCalicoNamespace)
	}

	// Also include the namespace profile in the profile IDs so that we get namespace label inheritance.
	// This is a wonky compared to Pods where the profile is included in the pod->WEP conversion and is therefore
	// conceptually limited to k8s, but then namespaces are themselves a k8s only concept.
	v1value := &model.NetworkSet{
		Nets:   addrs,
		Labels: uniquelabels.Make(labelsWithCalicoNamespace),
		ProfileIDs: []string{
			conversion.NamespaceProfileNamePrefix + v3res.Namespace,
		},
		AllowedEgressDomains: v3res.Spec.AllowedEgressDomains,
	}

	return v1value, nil
}

// Convert v3 KVPair to the equivalent v1 KVPair.
func ConvertNetworkSetV3ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	// Validate against incorrect key/value kinds.  This indicates a code bug rather
	// than a user error.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok {
		return nil, errors.New("key is not a valid ResourceKey")
	}
	v1key, err := convertNetworkSetV2ToV1Key(v3key)
	if err != nil {
		return nil, err
	}

	v1value, err := convertNetworkSetV2ToV1Value(kvp.Value)
	if err != nil {
		return nil, err
	}

	return &model.KVPair{
		Key:      v1key,
		Value:    v1value,
		Revision: kvp.Revision,
	}, nil
}
