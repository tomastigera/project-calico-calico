// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//

package sync

import (
	"context"
	"maps"
	"sync"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
)

type MockIPSetController struct {
	m           sync.Mutex
	sets        map[string]storage.IPSetSpec
	failFuncs   map[string]func(error)
	feedCachers map[string]cacher.GlobalThreatFeedCacher
	noGC        map[string]struct{}
}

func NewMockIPSetController() *MockIPSetController {
	return &MockIPSetController{
		sets:        make(map[string]storage.IPSetSpec),
		failFuncs:   make(map[string]func(error)),
		feedCachers: make(map[string]cacher.GlobalThreatFeedCacher),
		noGC:        make(map[string]struct{}),
	}
}

func (c *MockIPSetController) Add(ctx context.Context, name string, set any, f func(error), feedCacher cacher.GlobalThreatFeedCacher) {
	c.m.Lock()
	defer c.m.Unlock()
	c.sets[name] = set.(storage.IPSetSpec)
	c.failFuncs[name] = f
	c.feedCachers[name] = feedCacher
}

func (c *MockIPSetController) Delete(ctx context.Context, name string) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.sets, name)
	delete(c.failFuncs, name)
	delete(c.feedCachers, name)
	delete(c.noGC, name)
}

func (c *MockIPSetController) NoGC(ctx context.Context, name string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.noGC[name] = struct{}{}
}

func (c *MockIPSetController) StartReconciliation(ctx context.Context) {
}

func (c *MockIPSetController) Run(ctx context.Context) {
}

func (c *MockIPSetController) NotGCable() map[string]struct{} {
	out := make(map[string]struct{})
	c.m.Lock()
	defer c.m.Unlock()
	maps.Copy(out, c.noGC)
	return out
}

func (c *MockIPSetController) Sets() map[string]storage.IPSetSpec {
	out := make(map[string]storage.IPSetSpec)
	c.m.Lock()
	defer c.m.Unlock()
	maps.Copy(out, c.sets)
	return out
}

type MockDomainNameSetsController struct {
	m           sync.Mutex
	sets        map[string]storage.DomainNameSetSpec
	failFuncs   map[string]func(error)
	feedCachers map[string]cacher.GlobalThreatFeedCacher
	noGC        map[string]struct{}
}

func NewMockDomainNameSetsController() *MockDomainNameSetsController {
	return &MockDomainNameSetsController{
		sets:        make(map[string]storage.DomainNameSetSpec),
		failFuncs:   make(map[string]func(error)),
		feedCachers: make(map[string]cacher.GlobalThreatFeedCacher),
		noGC:        make(map[string]struct{}),
	}
}

func (c *MockDomainNameSetsController) Add(ctx context.Context, name string, set any, f func(error), feedCacher cacher.GlobalThreatFeedCacher) {
	c.m.Lock()
	defer c.m.Unlock()
	c.sets[name] = set.(storage.DomainNameSetSpec)
	c.failFuncs[name] = f
	c.feedCachers[name] = feedCacher
}

func (c *MockDomainNameSetsController) Delete(ctx context.Context, name string) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.sets, name)
	delete(c.failFuncs, name)
	delete(c.feedCachers, name)
	delete(c.noGC, name)
}

func (c *MockDomainNameSetsController) NoGC(ctx context.Context, name string) {
	c.m.Lock()
	defer c.m.Unlock()
	c.noGC[name] = struct{}{}
}

func (c *MockDomainNameSetsController) StartReconciliation(ctx context.Context) {
}

func (c *MockDomainNameSetsController) Run(ctx context.Context) {
}

func (c *MockDomainNameSetsController) NotGCable() map[string]struct{} {
	out := make(map[string]struct{})
	c.m.Lock()
	defer c.m.Unlock()
	maps.Copy(out, c.noGC)
	return out
}

func (c *MockDomainNameSetsController) Sets() map[string]storage.DomainNameSetSpec {
	out := make(map[string]storage.DomainNameSetSpec)
	c.m.Lock()
	defer c.m.Unlock()
	maps.Copy(out, c.sets)
	return out
}
