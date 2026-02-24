// Copyright 2019 Tigera Inc. All rights reserved.

package util

import "k8s.io/client-go/tools/cache"

type Ping struct{}

// pingKey is a sentinel to represent a ping on the FIFO.  Note that we use characters
// not allowed in Kubernetes names so that we won't conflict with GlobalThreatFeed
// names.
const pingKey = "~ping~"

// NewPingableFifo returns a DeltaFIFO that accepts GlobalThreatFeed objects and
// a special "ping" object that is used for health checking.
func NewPingableFifo() (*cache.DeltaFIFO, cache.Store) {
	// This will hold the client state, as we know it.  The special "ping" object
	// will never appear in the store, so it is safe to use a "standard" key function.
	// This is because the FIFO uses the store to process deletion of objects,
	// but we will never delete "ping" objects, just update.
	clientState := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	// This will hold incoming changes. Note how we pass clientState in as a
	// KeyLister, that way resync operations will result in the correct set
	// of update/delete deltas.  The FIFO's key function does need to account
	// for ping objects, since we will put them on the queue as updates.
	fifo := cache.NewDeltaFIFOWithOptions(cache.DeltaFIFOOptions{
		KeyFunction:  PingableKeyFunc,
		KnownObjects: clientState,
	})
	return fifo, clientState
}

func PingableKeyFunc(obj any) (string, error) {
	_, ok := obj.(Ping)
	if ok {
		return pingKey, nil
	}
	return cache.MetaNamespaceKeyFunc(obj)
}
