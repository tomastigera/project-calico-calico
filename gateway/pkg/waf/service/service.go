package service

import (
	"io/fs"
	"sync"

	"github.com/corazawaf/coraza/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/app-policy/waf"
	"github.com/projectcalico/calico/felix/proto"
)

type WAFServiceManager struct {
	currentWAF coraza.WAF
	rootFS     fs.FS
	events     *waf.WafEventsPipeline
	generation int64

	mu sync.Mutex
}

func NewWAFServiceManager(rootFS fs.FS, logger func(*proto.WAFEvent)) *WAFServiceManager {
	return &WAFServiceManager{
		currentWAF: nil,
		rootFS:     rootFS,
		events:     waf.NewEventsPipeline(logger),
	}
}

func (m *WAFServiceManager) Read(w func(coraza.WAF, *waf.WafEventsPipeline)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"generation": m.generation,
			"ptr":        m.currentWAF,
		}).Debug("Reading current WAF instance")
	}
	w(m.currentWAF, m.events)
}

func (m *WAFServiceManager) OnUpdate(directives []string) {
	shouldPanic := m.currentWAF == nil // If there is no current WAF instance, we panic to indicate that the WAF service must be initialized before updating.

	instance, err := waf.New(m.rootFS, nil, directives, false, m.events)
	switch {
	case shouldPanic && err != nil:
		log.Panicf("Failed to update WAF instance: %v", err)
		return //ineffective, but makes the intent clear.
	case err != nil:
		log.Errorf("Failed to update WAF instance: %v", err)
	default:
	}

	// Update the current WAF service
	m.mu.Lock()
	m.generation++ // Increment the generation to indicate a new WAF instance has been created
	m.currentWAF = instance
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"generation": m.generation,
			"directives": directives,
			"ptr":        instance,
		}).Debug("WAF instance updated successfully")
	}
	m.mu.Unlock()
}
