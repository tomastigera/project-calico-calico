// Copyright (c) 2019 Tigera Inc. All rights reserved.

package controller

import (
	"context"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
)

type mockSetsData struct {
	ipSet storage.IPSet
}

func (d *mockSetsData) Put(ctx context.Context, name string, value interface{}) error {
	return d.ipSet.PutIPSet(ctx, name, value.(storage.IPSetSpec))
}

func (d *mockSetsData) List(ctx context.Context) ([]storage.Meta, error) {
	return d.ipSet.ListIPSets(ctx)
}

func (d *mockSetsData) Delete(ctx context.Context, m storage.Meta) error {
	return d.ipSet.DeleteIPSet(ctx, m)
}
