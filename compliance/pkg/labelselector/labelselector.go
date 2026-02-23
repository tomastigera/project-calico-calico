// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package labelselector

import (
	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/labelindex"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// This is just a wrapper around the Felix InheritIndex helper, but uses ResourceID selector and label identifiers and
// provides automatic fanout based on registered listeners.
//
// This helper manages the links between selectors and labels. Callers register selectors and labels associated with a
// specific resource and this helper calls with match start and stop events between the linked and unlinked selector and
// labels.

// LabelSelector interface. Used for handling callbacks and managing resource label and selectors.
type LabelSelector interface {
	RegisterCallbacks(kinds []metav1.TypeMeta, started MatchStarted, stopped MatchStopped)

	UpdateLabels(res apiv3.ResourceID, labels uniquelabels.Map, parentIDs []string)
	DeleteLabels(res apiv3.ResourceID)
	UpdateParentLabels(id string, labels map[string]string)
	DeleteParentLabels(id string)
	UpdateSelector(res apiv3.ResourceID, selector string)
	DeleteSelector(res apiv3.ResourceID)
}

type MatchStarted func(selector, labels apiv3.ResourceID)
type MatchStopped func(selector, labels apiv3.ResourceID)

func New() LabelSelector {
	ls := &labelSelector{}
	ls.index = labelindex.NewInheritIndex(ls.onMatchStarted, ls.onMatchStopped)
	return ls
}

type labelSelector struct {
	// InheritIndex helper.  This is used to track correlations between endpoints and
	// registered selectors.
	index *labelindex.InheritIndex

	// Callbacks.
	cbs []callbacksWithKind
}

type callbacksWithKind struct {
	started MatchStarted
	stopped MatchStopped
	kind    metav1.TypeMeta
}

func (ls *labelSelector) RegisterCallbacks(kinds []metav1.TypeMeta, started MatchStarted, stopped MatchStopped) {
	for _, kind := range kinds {
		ls.cbs = append(ls.cbs, callbacksWithKind{
			started: started,
			stopped: stopped,
			kind:    kind,
		})
	}
}

func (ls *labelSelector) UpdateLabels(res apiv3.ResourceID, labels uniquelabels.Map, parentIDs []string) {
	ls.index.UpdateLabels(res, labels, parentIDs)
}

func (ls *labelSelector) DeleteLabels(res apiv3.ResourceID) {
	ls.index.DeleteLabels(res)
}

func (ls *labelSelector) UpdateParentLabels(parentID string, labels map[string]string) {
	ls.index.UpdateParentLabels(parentID, labels)
}

func (ls *labelSelector) DeleteParentLabels(parentID string) {
	ls.index.DeleteParentLabels(parentID)
}

func (ls *labelSelector) UpdateSelector(res apiv3.ResourceID, sel string) {
	parsedSel, err := selector.Parse(sel)
	if err != nil {
		// The selector is bad, remove the associated resource from the helper.
		log.WithError(err).Errorf("Bad selector found in config, removing from cache: %s", sel)
		ls.index.DeleteSelector(res)
		return
	}
	ls.index.UpdateSelector(res, parsedSel)
}

func (ls *labelSelector) DeleteSelector(res apiv3.ResourceID) {
	ls.index.DeleteSelector(res)
}

// onMatchStarted is called from the InheritIndex helper when a selector-endpoint match has
// started.
func (c *labelSelector) onMatchStarted(selId, labelsId any) {
	selRes := selId.(apiv3.ResourceID)
	labelsRes := labelsId.(apiv3.ResourceID)

	for i := range c.cbs {
		if c.cbs[i].kind == selRes.TypeMeta || c.cbs[i].kind == labelsRes.TypeMeta {
			c.cbs[i].started(selRes, labelsRes)
		}
	}
}

// onMatchStopped is called from the InheritIndex helper when a selector-endpoint match has
// stopped.
func (c *labelSelector) onMatchStopped(selId, labelsId any) {
	selRes := selId.(apiv3.ResourceID)
	labelsRes := labelsId.(apiv3.ResourceID)

	for i := range c.cbs {
		if c.cbs[i].kind == selRes.TypeMeta || c.cbs[i].kind == labelsRes.TypeMeta {
			c.cbs[i].stopped(selRes, labelsRes)
		}
	}
}
