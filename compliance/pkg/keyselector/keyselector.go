// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package keyselector

import (
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// This file implements a key selector. This acts as a bridge between the resources that are configured with one or more
// keys (e.g. endpoints with Key addresses) and other resources that act as clients for these keys (e.g. service Keys).
//
// TODO (note): This is very similar to the LabelSelector and we could have used that to handle the simple match start/stop
// processing. However, this implementation does not require selector processing and so a little more efficient, and
// and eventually we may want additional data from the stored info (e.g. who owns an Key, and which Keys are not accounted
// for in the clients - both of these translate to useful report information)
//
// TODO(rlb): This is effecively the same processing as the policy rule selector manager, except we'd need to implement
// additional hooks to notify of "first" match and "last" match on start or stopped respectively. We should update the
// rule selector manager to use this.

// Callbacks. This is the notify the owner that there is a client using one of their keys.
type MatchStarted func(owner, client apiv3.ResourceID, key string, firstKey bool)
type MatchStopped func(owner, client apiv3.ResourceID, key string, lastKey bool)

// KeySelector interface. Used for handling callbacks and managing resource label and selectors.
type KeySelector interface {
	RegisterCallbacks(kinds []metav1.TypeMeta, started MatchStarted, stopped MatchStopped)
	SetOwnerKeys(owner apiv3.ResourceID, keys set.Set[string])
	SetClientKeys(client apiv3.ResourceID, keys set.Set[string])
	DeleteOwner(owner apiv3.ResourceID)
	DeleteClient(client apiv3.ResourceID)
}

// New creates a new KeyManager.
func New() KeySelector {
	keym := &keySelector{
		keysByOwner:       make(map[apiv3.ResourceID]set.Set[string]),
		keysByClient:      make(map[apiv3.ResourceID]set.Set[string]),
		clientsByKey:      make(map[string]set.Typed[apiv3.ResourceID]),
		ownersByKey:       make(map[string]set.Typed[apiv3.ResourceID]),
		keysByOwnerClient: make(map[ownerClient]set.Set[string]),
	}
	return keym
}

// keySelector implements the KeyManager interface.
type keySelector struct {
	// The cross referencing.
	keysByOwner       map[apiv3.ResourceID]set.Set[string]
	keysByClient      map[apiv3.ResourceID]set.Set[string]
	ownersByKey       map[string]set.Typed[apiv3.ResourceID]
	clientsByKey      map[string]set.Typed[apiv3.ResourceID]
	keysByOwnerClient map[ownerClient]set.Set[string]

	// Callbacks
	cbs []callbacksWithKind
}

type callbacksWithKind struct {
	started MatchStarted
	stopped MatchStopped
	kind    metav1.TypeMeta
}

type ownerClient struct {
	owner  apiv3.ResourceID
	client apiv3.ResourceID
}

// RegisterCallbacks registers client callbacks with this manager.
func (ls *keySelector) RegisterCallbacks(kinds []metav1.TypeMeta, started MatchStarted, stopped MatchStopped) {
	for _, kind := range kinds {
		ls.cbs = append(ls.cbs, callbacksWithKind{
			started: started,
			stopped: stopped,
			kind:    kind,
		})
	}
}

// SetOwnerKeys sets owners keys.
func (m *keySelector) SetOwnerKeys(owner apiv3.ResourceID, keys set.Set[string]) {
	// Start by finding the delta sets of Keys.
	currentSet := m.keysByOwner[owner]
	if currentSet == nil {
		currentSet = set.New[string]()
	}
	if keys == nil {
		delete(m.keysByOwner, owner)
		keys = set.New[string]()
	} else {
		m.keysByOwner[owner] = keys
	}

	set.IterDifferences(currentSet, keys,
		// Key address is removed from the owners list.
		func(key string) error {
			// Update the ownersByKey set.
			owners := m.ownersByKey[key]
			owners.Discard(owner)
			if owners.Len() == 0 {
				delete(m.ownersByKey, key)
			}

			// Notify links to clients.
			clients := m.clientsByKey[key]
			if clients == nil {
				return nil
			}
			clients.Iter(func(client apiv3.ResourceID) error {
				m.onKeyMatchStopped(owner, client, key)
				return nil
			})
			return nil
		},
		// New Key address is added to the owners list.
		func(key string) error {
			// Update the ownersByKey set.
			owners := m.ownersByKey[key]
			if owners == nil {
				owners = set.New[apiv3.ResourceID]()
				m.ownersByKey[key] = owners
			}
			owners.Add(owner)

			// Notify links to clients.
			clients := m.clientsByKey[key]
			if clients == nil {
				return nil
			}
			clients.Iter(func(client apiv3.ResourceID) error {
				m.onKeyMatchStarted(owner, client, key)
				return nil
			})
			return nil
		},
	)
}

// SetClientKeys sets clients keys.
func (m *keySelector) SetClientKeys(client apiv3.ResourceID, keys set.Set[string]) {
	// Start by finding the delta sets of Keys.
	currentSet := m.keysByClient[client]
	if currentSet == nil {
		currentSet = set.New[string]()
	}
	if keys == nil {
		delete(m.keysByClient, client)
		keys = set.New[string]()
	} else {
		m.keysByClient[client] = keys
	}

	set.IterDifferences(currentSet, keys,
		// Key address is removed from the clients list.
		func(key string) error {
			// Update the clientsByKey set.
			clients := m.clientsByKey[key]
			clients.Discard(client)
			if clients.Len() == 0 {
				delete(m.clientsByKey, key)
			}

			// Notify links to owners.
			owners := m.ownersByKey[key]
			if owners == nil {
				return nil
			}
			owners.Iter(func(owner apiv3.ResourceID) error {
				m.onKeyMatchStopped(owner, client, key)
				return nil
			})
			return nil
		},
		// New Key address is added to the clients list.
		func(key string) error {
			// Update the clientsByKey set.
			clients := m.clientsByKey[key]
			if clients == nil {
				clients = set.New[apiv3.ResourceID]()
				m.clientsByKey[key] = clients
			}
			clients.Add(client)

			// Notify links to owners.
			owners := m.ownersByKey[key]
			if owners == nil {
				return nil
			}
			owners.Iter(func(owner apiv3.ResourceID) error {
				m.onKeyMatchStarted(owner, client, key)
				return nil
			})
			return nil
		},
	)
}

func (m *keySelector) DeleteOwner(owner apiv3.ResourceID) {
	m.SetOwnerKeys(owner, nil)
}

func (m *keySelector) DeleteClient(client apiv3.ResourceID) {
	m.SetClientKeys(client, nil)
}

// onMatchStarted is called from the InheritIndex helper when a selector-endpoint match has
// started.
func (c *keySelector) onKeyMatchStarted(owner, client apiv3.ResourceID, key string) {
	var firstKey bool
	oc := ownerClient{owner: owner, client: client}
	keys := c.keysByOwnerClient[oc]
	if keys == nil {
		keys = set.New[string]()
		c.keysByOwnerClient[oc] = keys
		firstKey = true
	}
	keys.Add(key)

	for i := range c.cbs {
		if c.cbs[i].kind == owner.TypeMeta || c.cbs[i].kind == client.TypeMeta {
			c.cbs[i].started(owner, client, key, firstKey)
		}
	}
}

// onMatchStopped is called from the InheritIndex helper when a selector-endpoint match has
// stopped.
func (c *keySelector) onKeyMatchStopped(owner, client apiv3.ResourceID, key string) {
	var lastKey bool
	oc := ownerClient{owner: owner, client: client}
	keys := c.keysByOwnerClient[oc]
	keys.Discard(key)
	if keys.Len() == 0 {
		delete(c.keysByOwnerClient, oc)
		lastKey = true
	}

	for i := range c.cbs {
		if c.cbs[i].kind == owner.TypeMeta || c.cbs[i].kind == client.TypeMeta {
			c.cbs[i].stopped(owner, client, key, lastKey)
		}
	}
}
