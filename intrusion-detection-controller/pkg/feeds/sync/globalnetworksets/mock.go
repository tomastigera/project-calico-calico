// Copyright 2019 Tigera Inc. All rights reserved.

package globalnetworksets

import (
	"context"
	"maps"
	"sync"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
)

type MockGlobalNetworkSetController struct {
	m           sync.Mutex
	local       map[string]*v3.GlobalNetworkSet
	noGC        map[string]struct{}
	failFuncs   map[string]func(error)
	feedCachers map[string]cacher.GlobalThreatFeedCacher
}

func NewMockGlobalNetworkSetController() *MockGlobalNetworkSetController {
	return &MockGlobalNetworkSetController{
		local:       make(map[string]*v3.GlobalNetworkSet),
		noGC:        make(map[string]struct{}),
		failFuncs:   make(map[string]func(error)),
		feedCachers: make(map[string]cacher.GlobalThreatFeedCacher),
	}
}

func (c *MockGlobalNetworkSetController) Add(s *v3.GlobalNetworkSet, f func(error), feedCacher cacher.GlobalThreatFeedCacher) {
	c.m.Lock()
	defer c.m.Unlock()
	c.local[s.Name] = s
	c.failFuncs[s.Name] = f
	c.feedCachers[s.Name] = feedCacher
}

func (c *MockGlobalNetworkSetController) Delete(s *v3.GlobalNetworkSet) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.local, s.Name)
	delete(c.noGC, s.Name)
	delete(c.failFuncs, s.Name)
	delete(c.feedCachers, s.Name)
}

func (c *MockGlobalNetworkSetController) NoGC(s *v3.GlobalNetworkSet) {
	c.m.Lock()
	defer c.m.Unlock()
	c.noGC[s.Name] = struct{}{}
}

func (c *MockGlobalNetworkSetController) Run(ctx context.Context) {
}

func (c *MockGlobalNetworkSetController) Local() map[string]*v3.GlobalNetworkSet {
	out := make(map[string]*v3.GlobalNetworkSet)
	c.m.Lock()
	defer c.m.Unlock()
	maps.Copy(out, c.local)
	return out
}

func (c *MockGlobalNetworkSetController) NotGCable() map[string]struct{} {
	out := make(map[string]struct{})
	c.m.Lock()
	defer c.m.Unlock()
	maps.Copy(out, c.noGC)
	return out
}

func (c *MockGlobalNetworkSetController) FailFuncs() map[string]func(error) {
	out := make(map[string]func(error))
	c.m.Lock()
	defer c.m.Unlock()
	maps.Copy(out, c.failFuncs)
	return out
}
