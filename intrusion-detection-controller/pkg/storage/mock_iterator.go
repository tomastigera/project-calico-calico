// Copyright 2019 Tigera Inc. All rights reserved.

package storage

import (
	"context"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	geodb "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/geodb"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

type MockSetQuerier struct {
	QueryError   error
	IteratorFlow *MockIterator[v1.FlowLog]
	IteratorDNS  *MockIterator[v1.DNSLog]
	GetError     error
	Set          DomainNameSetSpec
}

func (m *MockSetQuerier) GetDomainNameSet(ctx context.Context, name string) (DomainNameSetSpec, error) {
	return m.Set, m.GetError
}

func (m *MockSetQuerier) QueryIPSet(ctx context.Context, geoDB geodb.GeoDatabase, feed *apiv3.GlobalThreatFeed) (Iterator[v1.FlowLog], string, error) {
	return m.IteratorFlow, "", m.QueryError
}

func (m *MockSetQuerier) QueryDomainNameSet(ctx context.Context, set DomainNameSetSpec, feed *apiv3.GlobalThreatFeed) (Iterator[v1.DNSLog], string, error) {
	return m.IteratorDNS, "", m.QueryError
}

type MockIterator[T any] struct {
	Error      error
	ErrorIndex int
	Keys       []QueryKey
	Values     []T
	next       int
}

func (m *MockIterator[T]) Next() bool {
	cur := m.next
	m.next++
	return cur < len(m.Values) && cur != m.ErrorIndex
}

func (m *MockIterator[T]) Value() (key QueryKey, hit T) {
	cur := m.next - 1
	return m.Keys[cur], m.Values[cur]
}

func (m *MockIterator[T]) Err() error {
	cur := m.next - 1
	if cur == m.ErrorIndex {
		return m.Error
	}
	return nil
}
