// Copyright (c) 2018-2019, 2023 Tigera, Inc. All rights reserved.

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
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	netsetlabels "github.com/projectcalico/calico/libcalico-go/lib/labels"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// Create a new SyncerUpdateProcessor to sync GlobalNetworkSet data in v1 format for
// consumption by Felix.
func NewGlobalNetworkSetUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewConflictResolvingCacheUpdateProcessor(apiv3.KindGlobalNetworkSet, ConvertGlobalNetworkSetV3ToV1)
}

// Convert v3 KVPair to the equivalent v1 KVPair.
func ConvertGlobalNetworkSetV3ToV1(kvp *model.KVPair) (*model.KVPair, error) {
	// Validate against incorrect key/value kinds.  This indicates a code bug rather
	// than a user error.
	v3key, ok := kvp.Key.(model.ResourceKey)
	if !ok || v3key.Kind != apiv3.KindGlobalNetworkSet {
		return nil, errors.New("key is not a valid GlobalNetworkSet resource key")
	}
	v3res, ok := kvp.Value.(*apiv3.GlobalNetworkSet)
	if !ok {
		return nil, errors.New("value is not a valid GlobalNetworkSet resource key")
	}

	v1key := model.NetworkSetKey{
		Name: v3res.GetName(),
	}

	var addrs []cnet.IPNet
	for _, cidrString := range v3res.Spec.Nets {
		_, ipNet, err := cnet.ParseCIDROrIP(cidrString)
		if err != nil {
			// Validation should prevent this.
			log.WithError(err).WithFields(log.Fields{
				"CIDR":       cidrString,
				"networkSet": v3res.GetName(),
			}).Warn("Invalid CIDR")
			continue
		}
		addrs = append(addrs, *ipNet)
	}

	// Add in the Kind and Name label for policy recommendation purposes
	labelsWithCalicoNamespace := make(map[string]string, len(v3res.GetLabels()))
	maps.Copy(labelsWithCalicoNamespace, v3res.GetLabels())
	if !netsetlabels.ValidateNetworkSetLabels(v3res.Name, labelsWithCalicoNamespace) {
		// Add Kind and Name labels to network set for policy rule mappings.
		netsetlabels.AddKindandNameLabels(v3res.Name, labelsWithCalicoNamespace)
	}

	v1value := &model.NetworkSet{
		Labels:               uniquelabels.Make(labelsWithCalicoNamespace),
		Nets:                 addrs,
		AllowedEgressDomains: v3res.Spec.AllowedEgressDomains,
	}

	return &model.KVPair{
		Key:      v1key,
		Value:    v1value,
		Revision: kvp.Revision,
	}, nil
}
