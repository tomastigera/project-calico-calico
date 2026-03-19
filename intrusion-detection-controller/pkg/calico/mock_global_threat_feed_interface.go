// Copyright 2019-2020 Tigera Inc. All rights reserved.

package calico

import (
	"context"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	applyconfigv3 "github.com/tigera/api/pkg/client/applyconfiguration_generated/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

type MockGlobalThreatFeedInterface struct {
	GlobalThreatFeedList *v3.GlobalThreatFeedList
	GlobalThreatFeed     *v3.GlobalThreatFeed
	Error                error
	WatchError           error
	W                    *MockWatch
}

func (m *MockGlobalThreatFeedInterface) UpdateStatus(ctx context.Context, gtf *v3.GlobalThreatFeed, options v1.UpdateOptions) (*v3.GlobalThreatFeed, error) {
	m.GlobalThreatFeed = gtf
	return gtf, m.Error
}

func (m *MockGlobalThreatFeedInterface) Create(ctx context.Context, gtf *v3.GlobalThreatFeed, options v1.CreateOptions) (*v3.GlobalThreatFeed, error) {
	return gtf, m.Error
}

func (m *MockGlobalThreatFeedInterface) Update(ctx context.Context, gtf *v3.GlobalThreatFeed, options v1.UpdateOptions) (*v3.GlobalThreatFeed, error) {
	return gtf, m.Error
}

func (m *MockGlobalThreatFeedInterface) Delete(ctx context.Context, name string, options v1.DeleteOptions) error {
	return m.Error
}

func (m *MockGlobalThreatFeedInterface) DeleteCollection(ctx context.Context, options v1.DeleteOptions, listOptions v1.ListOptions) error {
	return m.Error
}

func (m *MockGlobalThreatFeedInterface) Get(ctx context.Context, name string, options v1.GetOptions) (*v3.GlobalThreatFeed, error) {
	return m.GlobalThreatFeed, m.Error
}

func (m *MockGlobalThreatFeedInterface) List(ctx context.Context, opts v1.ListOptions) (*v3.GlobalThreatFeedList, error) {
	return m.GlobalThreatFeedList, m.Error
}

func (m *MockGlobalThreatFeedInterface) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	if m.WatchError == nil {
		if m.W == nil {
			m.W = &MockWatch{C: make(chan watch.Event)}
		}
		return m.W, nil
	} else {
		return nil, m.WatchError
	}
}

func (m *MockGlobalThreatFeedInterface) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, options v1.PatchOptions, subresources ...string) (result *v3.GlobalThreatFeed, err error) {
	return nil, m.Error
}

func (m *MockGlobalThreatFeedInterface) Apply(ctx context.Context, globalThreatFeed *applyconfigv3.GlobalThreatFeedApplyConfiguration, opts v1.ApplyOptions) (*v3.GlobalThreatFeed, error) {
	return nil, m.Error
}

func (m *MockGlobalThreatFeedInterface) ApplyStatus(ctx context.Context, globalThreatFeed *applyconfigv3.GlobalThreatFeedApplyConfiguration, opts v1.ApplyOptions) (*v3.GlobalThreatFeed, error) {
	return nil, m.Error
}
