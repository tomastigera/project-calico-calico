// Copyright 2019 Tigera Inc. All rights reserved.

package storage

import (
	"context"
	"sync"
	"time"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/spyutil"
)

type MockSets struct {
	Name              string
	SeqNo             any
	PrimaryTerm       any
	Metas             []Meta
	Value             any
	Time              time.Time
	Error             error
	DeleteCalled      bool
	DeleteName        string
	DeleteSeqNo       *int64
	DeletePrimaryTerm *int64
	DeleteError       error
	PutError          error

	m     sync.Mutex
	calls []spyutil.Call
}

func (m *MockSets) ListIPSets(ctx context.Context) ([]Meta, error) {
	return m.Metas, m.Error
}

func (m *MockSets) ListDomainNameSets(ctx context.Context) ([]Meta, error) {
	return m.Metas, m.Error
}

func (m *MockSets) DeleteIPSet(ctx context.Context, meta Meta) error {
	m.m.Lock()
	defer m.m.Unlock()
	m.calls = append(m.calls, spyutil.Call{Method: "DeleteIPSet", Name: meta.Name, SeqNo: meta.SeqNo, PrimaryTerm: meta.PrimaryTerm})
	m.DeleteCalled = true
	m.DeleteName = meta.Name
	if meta.SeqNo == nil {
		m.DeleteSeqNo = nil
	} else {
		i := struct{ i int64 }{*meta.SeqNo}
		m.DeleteSeqNo = &i.i
	}
	if meta.PrimaryTerm == nil {
		m.DeletePrimaryTerm = nil
	} else {
		i := struct{ i int64 }{*meta.PrimaryTerm}
		m.DeletePrimaryTerm = &i.i
	}
	return m.DeleteError
}

func (m *MockSets) DeleteDomainNameSet(ctx context.Context, meta Meta) error {
	m.m.Lock()
	defer m.m.Unlock()
	m.calls = append(m.calls, spyutil.Call{Method: "DeleteDomainNameSet", Name: meta.Name, SeqNo: meta.SeqNo, PrimaryTerm: meta.PrimaryTerm})
	m.DeleteCalled = true
	m.DeleteName = meta.Name
	if meta.SeqNo == nil {
		m.DeleteSeqNo = nil
	} else {
		i := struct{ i int64 }{*meta.SeqNo}
		m.DeleteSeqNo = &i.i
	}
	if meta.PrimaryTerm == nil {
		m.DeletePrimaryTerm = nil
	} else {
		i := struct{ i int64 }{*meta.PrimaryTerm}
		m.DeletePrimaryTerm = &i.i
	}
	return m.DeleteError
}

func (m *MockSets) GetIPSetModified(ctx context.Context, name string) (time.Time, error) {
	return m.Time, m.Error
}

func (m *MockSets) GetDomainNameSetModified(ctx context.Context, name string) (time.Time, error) {
	return m.Time, m.Error
}

func (m *MockSets) GetIPSet(ctx context.Context, name string) (IPSetSpec, error) {
	if m.Value == nil {
		return nil, m.Error
	}
	return m.Value.(IPSetSpec), m.Error
}

func (m *MockSets) PutIPSet(ctx context.Context, name string, set IPSetSpec) error {
	m.m.Lock()
	defer m.m.Unlock()
	m.calls = append(m.calls, spyutil.Call{Method: "PutIPSet", Name: name, Value: set})
	m.Name = name
	m.Value = set

	if m.PutError == nil {
		m.Time = time.Now()
	}

	return m.PutError
}

func (m *MockSets) PutDomainNameSet(ctx context.Context, name string, set DomainNameSetSpec) error {
	m.m.Lock()
	defer m.m.Unlock()
	m.calls = append(m.calls, spyutil.Call{Method: "PutDomainNameSet", Name: name, Value: set})
	m.Name = name
	m.Value = set

	if m.PutError == nil {
		m.Time = time.Now()
	}

	return m.PutError
}

func (m *MockSets) Calls() []spyutil.Call {
	var out []spyutil.Call
	m.m.Lock()
	defer m.m.Unlock()
	return append(out, m.calls...)
}
