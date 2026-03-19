// Copyright 2019-2020 Tigera Inc. All rights reserved.

package calico

import (
	"context"
	"sync"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	applyconfigv3 "github.com/tigera/api/pkg/client/applyconfiguration_generated/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/spyutil"
)

type MockGlobalNetworkSetInterface struct {
	GlobalNetworkSet *v3.GlobalNetworkSet
	Error            error
	CreateError      []error
	DeleteError      error
	GetError         error
	UpdateError      error
	WatchError       error
	W                *MockWatch

	m     sync.Mutex
	calls []spyutil.Call
}

func (m *MockGlobalNetworkSetInterface) Create(ctx context.Context, gns *v3.GlobalNetworkSet, options v1.CreateOptions) (*v3.GlobalNetworkSet, error) {
	m.m.Lock()
	defer m.m.Unlock()
	m.calls = append(m.calls, spyutil.Call{Method: "Create", GNS: gns.DeepCopy()})
	var err error
	if len(m.CreateError) > 0 {
		err = m.CreateError[0]
		m.CreateError = m.CreateError[1:]
	}
	if err != nil {
		return nil, err
	}
	m.GlobalNetworkSet = gns
	return gns, m.Error
}

func (m *MockGlobalNetworkSetInterface) Update(ctx context.Context, gns *v3.GlobalNetworkSet, options v1.UpdateOptions) (*v3.GlobalNetworkSet, error) {
	m.m.Lock()
	defer m.m.Unlock()
	m.calls = append(m.calls, spyutil.Call{Method: "Update", GNS: gns.DeepCopy()})
	if m.UpdateError != nil {
		return nil, m.UpdateError
	}
	m.GlobalNetworkSet = gns
	return gns, m.Error
}

func (m *MockGlobalNetworkSetInterface) Delete(ctx context.Context, name string, options v1.DeleteOptions) error {
	m.m.Lock()
	defer m.m.Unlock()
	m.calls = append(m.calls, spyutil.Call{Method: "Delete", Name: name})
	return m.DeleteError
}

func (m *MockGlobalNetworkSetInterface) DeleteCollection(ctx context.Context, options v1.DeleteOptions, listOptions v1.ListOptions) error {
	return m.Error
}

func (m *MockGlobalNetworkSetInterface) Get(ctx context.Context, name string, options v1.GetOptions) (*v3.GlobalNetworkSet, error) {
	if m.GetError != nil {
		return nil, m.GetError
	}
	return m.GlobalNetworkSet, m.Error
}

func (m *MockGlobalNetworkSetInterface) List(ctx context.Context, opts v1.ListOptions) (*v3.GlobalNetworkSetList, error) {
	out := &v3.GlobalNetworkSetList{}
	if m.GlobalNetworkSet != nil {
		out.Items = append(out.Items, *m.GlobalNetworkSet)
	}
	return out, m.Error
}

func (m *MockGlobalNetworkSetInterface) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	if m.WatchError == nil {
		if m.W == nil {
			m.W = &MockWatch{make(chan watch.Event)}
		}
		return m.W, nil
	} else {
		return nil, m.WatchError
	}
}

func (m *MockGlobalNetworkSetInterface) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, options v1.PatchOptions, subresources ...string) (result *v3.GlobalNetworkSet, err error) {
	return nil, m.Error
}

func (m *MockGlobalNetworkSetInterface) Apply(ctx context.Context, globalNetworkSet *applyconfigv3.GlobalNetworkSetApplyConfiguration, opts v1.ApplyOptions) (*v3.GlobalNetworkSet, error) {
	return nil, m.Error
}

func (m *MockGlobalNetworkSetInterface) Calls() []spyutil.Call {
	var out []spyutil.Call
	m.m.Lock()
	defer m.m.Unlock()
	return append(out, m.calls...)
}
