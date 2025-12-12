// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package cache

import (
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

// SelectorAndLabelCache caches Selector and Labels and keeps a mapping between them.
type SelectorAndLabelCache interface {
	UpdateSelector(dpiKey interface{}, sel *selector.Selector)
	UpdateLabels(wepKey interface{}, labels uniquelabels.Map)
	DeleteSelector(wepKey interface{})
	DeleteLabel(dpiKey interface{})
}

type MatchCallback func(dpiKey, wepKey interface{})

type selectorAndLabelCache struct {
	// wepKeyToLabel has WEP key and its labels
	wepKeyToLabel map[interface{}]uniquelabels.Map
	// dpiKeyToSelector has DPI key and its selector
	dpiKeyToSelector map[interface{}]*selector.Selector

	// Current matches
	wepKeysByDPIKey map[interface{}]set.Set[interface{}]
	dpiKeysByWEPKey map[interface{}]set.Set[interface{}]

	// Callback functions
	OnMatchStarted MatchCallback
	OnMatchStopped MatchCallback

	dirtyWEPKeys set.Set[interface{}]
}

func NewSelectorAndLabelCache(onMatchStarted, onMatchStopped MatchCallback) SelectorAndLabelCache {
	return &selectorAndLabelCache{
		wepKeyToLabel:    make(map[interface{}]uniquelabels.Map),
		dpiKeyToSelector: make(map[interface{}]*selector.Selector),
		dpiKeysByWEPKey:  map[interface{}]set.Set[interface{}]{},
		wepKeysByDPIKey:  map[interface{}]set.Set[interface{}]{},

		// Callback functions
		OnMatchStarted: onMatchStarted,
		OnMatchStopped: onMatchStopped,

		dirtyWEPKeys: set.New[interface{}](),
	}
}

// UpdateLabels takes WEP key and WEP labels as input, if WEP has new/updated labels
// for each matching selector either calls OnMatchStarted or OnMatchStopped callback function.
func (cache *selectorAndLabelCache) UpdateLabels(wepKey interface{}, labels uniquelabels.Map) {
	log.Debugf("Updating labels for %v", wepKey)
	oldItm, ok := cache.wepKeyToLabel[wepKey]
	if ok {
		if oldItm.Equals(labels) {
			log.Debug("Nothing to update - no change to label")
			return
		}
	}
	cache.wepKeyToLabel[wepKey] = labels
	cache.dirtyWEPKeys.Add(wepKey)
	cache.flushUpdates()
}

// DeleteLabel deletes the cached label with given id.
func (cache *selectorAndLabelCache) DeleteLabel(wepKey interface{}) {
	log.Debugf("Deleting labels for %v", wepKey)
	delete(cache.wepKeyToLabel, wepKey)
	cache.dirtyWEPKeys.Add(wepKey)
	cache.flushUpdates()
}

// UpdateSelector takes DPI key and selector as input, if DPI selector is updated
// for each affected selector and labels either calls OnMatchStarted or OnMatchStopped callback function.
func (cache *selectorAndLabelCache) UpdateSelector(dpiKey interface{}, sel *selector.Selector) {
	log.Debugf("Updating selector for %v", dpiKey)
	if sel == nil {
		log.WithField("DPI", dpiKey).Error("Selector should not be nil")
		return
	}

	oldSel := cache.dpiKeyToSelector[dpiKey]
	if oldSel != nil && oldSel.UniqueID() == sel.UniqueID() {
		log.WithField("DPI", dpiKey).Debug("Skipping unchanged selector")
		return
	}

	cache.scanAllLabels(dpiKey, sel)
	cache.dpiKeyToSelector[dpiKey] = sel
}

// DeleteSelector for each cached label associated with the give WEP key (aka id)
// update the cache and also call the OnMatchStopped callback function.
func (cache *selectorAndLabelCache) DeleteSelector(dpiKey interface{}) {
	log.Debugf("Deleting selector for %v", dpiKey)
	matchSet := cache.wepKeysByDPIKey[dpiKey]
	if matchSet != nil {
		for wepKey := range matchSet.All() {
			// This modifies the set we're iterating over, but that's safe in Go.
			cache.deleteMatch(dpiKey, wepKey)
		}
	}
	delete(cache.dpiKeyToSelector, dpiKey)
}

// flushUpdates handles the dirtyWEPKeys, for each item in this array
// if wepKey doesn't exist in wepKeyToLabel, get the selectors that were previously mapped to wepKey and delete them,
// else re-evaluate labels.
func (cache *selectorAndLabelCache) flushUpdates() {
	for wepKey := range cache.dirtyWEPKeys.All() {
		if _, ok := cache.wepKeyToLabel[wepKey]; !ok {
			// Item deleted.
			matchSet := cache.dpiKeysByWEPKey[wepKey]
			if matchSet != nil {
				for dpiKey := range matchSet.All() {
					// This modifies the set we're iterating over, but that's safe in Go.
					cache.deleteMatch(dpiKey, wepKey)
				}
			}
		} else {
			// Item updated/created, re-evaluate labels.
			cache.scanAllSelectors(wepKey)
		}
		cache.dirtyWEPKeys.Discard(wepKey)
	}
}

// scanAllLabels for each cached label
//
//		if label matches the selector
//			- and if the label is already part selector (aka it is already in wepKeysByDPIKey[dpiKey]) do nothing
//	 	- else add update both the wepKeysByDPIKey and dpiKeysByWEPKey and calls OnMatchStarted or OnMatchStopped callback function.
//		if label that doesn't match the selector
//	 	-  if the label was previously part of selector (aka in wepKeysByDPIKey[dpiKey]),
//	        update both the wepKeysByDPIKey and dpiKeysByWEPKey
//	 	- else do nothing
func (cache *selectorAndLabelCache) scanAllLabels(dpiKey interface{}, sel *selector.Selector) {
	log.Debugf("Scanning all (%v) labels against selector of %v", len(cache.wepKeyToLabel), dpiKey)
	for wepKey, labels := range cache.wepKeyToLabel {
		cache.updateMatches(dpiKey, sel, wepKey, labels)
	}
}

func (cache *selectorAndLabelCache) scanAllSelectors(wepKey interface{}) {
	log.Debugf("Scanning all (%v) selectors against labels in %v", len(cache.dpiKeyToSelector), wepKey)
	labels := cache.wepKeyToLabel[wepKey]
	for dpiKey, sel := range cache.dpiKeyToSelector {
		cache.updateMatches(dpiKey, sel, wepKey, labels)
	}
}

func (cache *selectorAndLabelCache) updateMatches(dpiKey interface{}, sel *selector.Selector, wepKey interface{}, labels parser.Labels) {
	nowMatches := sel.EvaluateLabels(labels)
	if nowMatches {
		cache.storeMatch(dpiKey, wepKey)
	} else {
		cache.deleteMatch(dpiKey, wepKey)
	}
}

func (cache *selectorAndLabelCache) storeMatch(dpiKey, wepKey interface{}) {
	wepKeys := cache.wepKeysByDPIKey[dpiKey]
	if wepKeys == nil {
		wepKeys = set.New[interface{}]()
		cache.wepKeysByDPIKey[dpiKey] = wepKeys
	}
	previouslyMatched := wepKeys.Contains(wepKey)
	if !previouslyMatched {
		log.Debugf("Selector of %v now matches labels in %v", dpiKey, wepKey)
		wepKeys.Add(wepKey)
		cache.wepKeysByDPIKey[dpiKey] = wepKeys

		dpiKeys, ok := cache.dpiKeysByWEPKey[wepKey]
		if !ok {
			dpiKeys = set.New[interface{}]()
			cache.dpiKeysByWEPKey[wepKey] = dpiKeys
		}
		dpiKeys.Add(dpiKey)
		cache.dpiKeysByWEPKey[wepKey] = dpiKeys

		cache.OnMatchStarted(dpiKey, wepKey)
	}
}

func (cache *selectorAndLabelCache) deleteMatch(dpiKey, wepKey interface{}) {
	wepKeys := cache.wepKeysByDPIKey[dpiKey]
	if wepKeys == nil {
		return
	}
	previouslyMatched := wepKeys.Contains(wepKey)
	if previouslyMatched {
		log.Debugf("Selector of %v no longer matches labels in %v", dpiKey, wepKey)

		wepKeys.Discard(wepKey)
		if wepKeys.Len() == 0 {
			delete(cache.wepKeysByDPIKey, dpiKey)
		}

		cache.dpiKeysByWEPKey[wepKey].Discard(dpiKey)
		if cache.dpiKeysByWEPKey[wepKey].Len() == 0 {
			delete(cache.dpiKeysByWEPKey, wepKey)
		}

		cache.OnMatchStopped(dpiKey, wepKey)
	}
}
