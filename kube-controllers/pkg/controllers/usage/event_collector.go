package usage

import (
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

const defaultReportsPerDay = 4

// newEventCollector collects input events relevant to report generation and outputs them on its event channels.
func newEventCollector(stopCh chan struct{}, nodeInformer, podInformer cache.SharedIndexInformer, usageReportsPerDay int) eventCollector {
	return eventCollector{
		events: events{
			nodeUpdates:         make(chan event[*v1.Node]),
			podUpdates:          make(chan event[*v1.Pod]),
			intervalComplete:    make(chan bool),
			initialSyncComplete: make(chan bool),
		},
		nodeInformer:       nodeInformer,
		podInformer:        podInformer,
		usageReportsPerDay: defaultReportsPerDayIfNecessary(usageReportsPerDay),
		stopIssued:         stopCh,
	}
}

func (c *eventCollector) startCollectingEvents() {
	// Set up the tickers used by the core loop.
	completionTicker := time.NewTicker((24 * time.Hour) / time.Duration(c.usageReportsPerDay))
	checkSyncTicker := time.NewTicker(50 * time.Millisecond)
	defer completionTicker.Stop()
	defer checkSyncTicker.Stop()

	// Wire up the node event handler to the informer. This will feed the node update channel.
	nodeEventHandler := &eventHandler[*v1.Node]{eventChannel: c.nodeUpdates}
	nodeHandlerRegistration, _ := c.nodeInformer.AddEventHandler(nodeEventHandler)

	// Wire up the pod event handler to the informer. This will feed the pod update channel.
	podEventHandler := &eventHandler[*v1.Pod]{eventChannel: c.podUpdates}
	podHandlerRegistration, _ := c.podInformer.AddEventHandler(podEventHandler)

	// Watch for events on the tickers. These will feed the interval completion and initial sync channels.
	for {
		select {
		case <-completionTicker.C:
			log.Info("Interval completed")
			mustSend[bool](c.intervalComplete, true)

		case <-checkSyncTicker.C:
			if nodeHandlerRegistration.HasSynced() && podHandlerRegistration.HasSynced() {
				log.Info("Sync received")
				mustSend[bool](c.initialSyncComplete, true)
				checkSyncTicker.Stop()
			}

		case <-c.stopIssued:
			return
		}
	}
}

type eventCollector struct {
	events
	nodeInformer       cache.SharedIndexInformer
	podInformer        cache.SharedIndexInformer
	stopIssued         chan struct{}
	usageReportsPerDay int
}

func defaultReportsPerDayIfNecessary(reportsPerDay int) int {
	if reportsPerDay <= 0 {
		log.Warningf("Configured usage report per day value (%d) is <= 0. Defaulting to %d reports per day", reportsPerDay, defaultReportsPerDay)
		return defaultReportsPerDay
	}

	return reportsPerDay
}

type eventHandler[T metav1.Object] struct {
	eventChannel chan event[T]
}

type event[T metav1.Object] struct {
	old T
	new T
}

func (e *eventHandler[T]) OnAdd(obj any, isInInitialList bool) {
	if log.GetLevel() == log.DebugLevel {
		objBytes, err := json.Marshal(obj)
		log.Debugf("Create event received. json_err=%s obj=%s", err, string(objBytes))
	}
	mustSend[event[T]](e.eventChannel, event[T]{
		new: obj.(T),
	})
}
func (e *eventHandler[T]) OnUpdate(oldObj, newObj any) {
	if log.GetLevel() == log.DebugLevel {
		oldObjBytes, oldObjErr := json.Marshal(oldObj)
		newObjBytes, newObjErr := json.Marshal(newObj)
		log.Debugf("Update event received. old_json_err=%s old_obj=%s new_json_err=%s new_obj=%s", oldObjErr, string(oldObjBytes), newObjErr, string(newObjBytes))
	}
	mustSend[event[T]](e.eventChannel, event[T]{
		old: oldObj.(T),
		new: newObj.(T),
	})
}
func (e *eventHandler[T]) OnDelete(obj any) {
	if log.GetLevel() == log.DebugLevel {
		objBytes, err := json.Marshal(obj)
		log.Debugf("Delete event received. json_err=%s obj=%s", err, string(objBytes))
	}
	mustSend[event[T]](e.eventChannel, event[T]{
		old: obj.(T),
	})
}
