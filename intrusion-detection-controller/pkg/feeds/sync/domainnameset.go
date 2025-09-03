// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package sync

import (
	"context"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/controller"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
)

type dnSetData struct {
	dnSet storage.DomainNameSet
}

func NewDomainNameSetController(sets storage.DomainNameSet) controller.Controller {
	return controller.NewController(dnSetData{sets}, cacher.LinseedSyncFailed)
}

func (d dnSetData) Put(ctx context.Context, name string, value interface{}) error {
	return d.dnSet.PutDomainNameSet(ctx, name, value.(storage.DomainNameSetSpec))
}

func (d dnSetData) List(ctx context.Context) ([]storage.Meta, error) {
	return d.dnSet.ListDomainNameSets(ctx)
}

func (d dnSetData) Delete(ctx context.Context, m storage.Meta) error {
	return d.dnSet.DeleteDomainNameSet(ctx, m)
}
