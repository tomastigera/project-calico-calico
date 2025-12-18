// Copyright (c) 2017 Tigera, Inc. All rights reserved.

package updateprocessors

import (
	"errors"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
)

// Create a new SyncerUpdateProcessor to sync Tiers data in v1 format for
// consumption by Felix.
func NewTierUpdateProcessor() watchersyncer.SyncerUpdateProcessor {
	return NewSimpleUpdateProcessor(
		apiv3.KindTier,
		ConvertTierV3ToV1Key,
		ConvertTierV3ToV1Value,
	)
}

func ConvertTierV3ToV1Key(v3key model.ResourceKey) (model.Key, error) {
	if v3key.Name == "" {
		return model.PolicyKey{}, errors.New("Missing Name or Namespace field to create a v1 Tier Key")
	}
	return model.TierKey{
		Name: v3key.Name,
	}, nil
}

func ConvertTierV3ToV1Value(val interface{}) (interface{}, error) {
	v3res, ok := val.(*apiv3.Tier)
	if !ok {
		return nil, errors.New("Value is not a valid Tier resource value")
	}
	// Any value except Pass is interpreted as Deny.
	action := apiv3.Deny
	if v3res.Spec.DefaultAction != nil && *v3res.Spec.DefaultAction == apiv3.Pass {
		action = apiv3.Pass
	}
	return &model.Tier{
		Order:         v3res.Spec.Order,
		DefaultAction: action,
	}, nil
}
