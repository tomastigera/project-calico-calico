// Copyright 2019 Tigera Inc. All rights reserved.

package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/cacher"
	feedutils "github.com/projectcalico/calico/intrusion-detection-controller/pkg/feeds/utils"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
)

type Controller interface {
	// Add or update a new Set including the spec. f is function the controller should call
	// if we fail to update, and feedCacher is the GlobalThreatFeedCacher we should report or clear errors on.
	Add(ctx context.Context, name string, value interface{}, f func(error), feedCacher cacher.GlobalThreatFeedCacher)

	// Delete, and NoGC alter the desired state the controller will attempt to
	// maintain, by syncing with the database.

	// Delete removes a Set from the desired state.
	Delete(ctx context.Context, name string)

	// NoGC marks a Set as not eligible for garbage collection
	// until deleted. This is useful when we don't know the contents of a
	// Set, but know it should not be deleted.
	NoGC(ctx context.Context, name string)

	// StartReconciliation indicates that all Sets we don't want garbage
	// collected have either Add() or NoGC() called on them, and we can start
	// reconciling our desired state with the actual state.
	StartReconciliation(ctx context.Context)

	// Run starts processing Sets
	Run(context.Context)
}

type Data interface {
	Put(ctx context.Context, name string, value interface{}) error
	List(ctx context.Context) ([]storage.Meta, error)
	Delete(ctx context.Context, m storage.Meta) error
}

func NewController(data Data, errorType string) Controller {
	return &controller{
		dirty:     make(map[string]update),
		noGC:      make(map[string]struct{}),
		updates:   make(chan update, DefaultUpdateQueueLen),
		data:      data,
		errorType: errorType,
	}
}

type controller struct {
	once      sync.Once
	dirty     map[string]update
	noGC      map[string]struct{}
	updates   chan update
	data      Data
	errorType string
}

type op int

const (
	opAdd op = iota
	opDelete
	opNoGC
	opStart
)

type update struct {
	name       string
	op         op
	value      interface{}
	fail       func(error)
	feedCacher cacher.GlobalThreatFeedCacher
}

const (
	DefaultUpdateQueueLen  = 1000
	DefaultReconcilePeriod = 15 * time.Second
)

var NewTicker = func() *time.Ticker {
	tkr := time.NewTicker(DefaultReconcilePeriod)
	return tkr
}

func (c *controller) Add(ctx context.Context, name string, value interface{}, f func(error), feedCacher cacher.GlobalThreatFeedCacher) {
	select {
	case <-ctx.Done():
		return
	case c.updates <- update{name: name, op: opAdd, value: value, fail: f, feedCacher: feedCacher}:
		return
	}
}

func (c *controller) Delete(ctx context.Context, name string) {
	select {
	case <-ctx.Done():
		return
	case c.updates <- update{name: name, op: opDelete}:
		return
	}
}

func (c *controller) NoGC(ctx context.Context, name string) {
	select {
	case <-ctx.Done():
		return
	case c.updates <- update{name: name, op: opNoGC}:
		return
	}
}

func (c *controller) StartReconciliation(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case c.updates <- update{op: opStart}:
		return
	}
}

func (c *controller) Run(ctx context.Context) {
	c.once.Do(func() {
		go c.run(ctx)
	})
}

func (c *controller) run(ctx context.Context) {
	log.Infof("Starting threat feeds controller for %T", c.data)

	// Initially, we're just processing state updates, and not triggering any
	// reconcilliation.
UpdateLoop:
	for {
		select {
		case <-ctx.Done():
			return
		case u := <-c.updates:
			if u.op == opStart {
				break UpdateLoop
			}
			c.processUpdate(u)
		}
	}

	log.Debug("threat feeds controller reconciliation started")

	// After getting the startGC, we can also include state sync processing
	tkr := NewTicker()
	defer tkr.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case u := <-c.updates:
			if u.op == opStart {
				continue
			}
			c.processUpdate(u)
		case <-tkr.C:
			c.reconcile(ctx)
		}
	}
}

func (c *controller) processUpdate(u update) {
	switch u.op {
	case opAdd:
		c.dirty[u.name] = u
	case opDelete:
		delete(c.dirty, u.name)
		delete(c.noGC, u.name)
	case opNoGC:
		c.noGC[u.name] = struct{}{}
	default:
		panic(fmt.Sprintf("unhandled op type %d", u.op))
	}
}

func (c *controller) reconcile(ctx context.Context) {
	metas, err := c.data.List(ctx)
	if err != nil {
		log.WithError(err).Errorf("failed to reconcile threat feed object (%d)", len(c.dirty))
		for _, u := range c.dirty {
			feedutils.AddErrorToFeedStatus(u.feedCacher, c.errorType, err)
		}
		return
	}

	for _, m := range metas {
		if u, ok := c.dirty[m.Name]; ok {
			// value already exists, but is dirty
			c.updateObject(ctx, u)
		} else if _, ok := c.noGC[m.Name]; !ok {
			// Garbage collect
			c.purgeObject(ctx, m)
		} else {
			log.WithField("name", m.Name).Debug("Retained threat feed object")
		}
	}

	for _, u := range c.dirty {
		c.updateObject(ctx, u)
	}
}

func (c *controller) updateObject(ctx context.Context, u update) {
	err := c.data.Put(ctx, u.name, u.value)
	if err != nil {
		log.WithError(err).WithField("name", u.name).Error("failed to update threat feed object")
		u.fail(err)
		feedutils.AddErrorToFeedStatus(u.feedCacher, c.errorType, err)
		return
	}
	// success!
	feedutils.ClearErrorFromFeedStatus(u.feedCacher, c.errorType)
	c.noGC[u.name] = struct{}{}
	delete(c.dirty, u.name)
}

func (c *controller) purgeObject(ctx context.Context, m storage.Meta) {
	fields := log.Fields{
		"name": m.Name,
	}
	if m.SeqNo != nil {
		fields["seqNo"] = m.SeqNo
	} else {
		fields["seqNo"] = "nil"
	}
	if m.PrimaryTerm != nil {
		fields["primaryTerm"] = m.PrimaryTerm
	} else {
		fields["primaryTerm"] = "nil"
	}

	err := c.data.Delete(ctx, m)
	if err != nil {
		log.WithError(err).WithFields(fields).Error("Failed to purge ThreatFeeds Sets")
		return
	}
	log.WithFields(fields).Info("GC'd threat feed Sets")
}
