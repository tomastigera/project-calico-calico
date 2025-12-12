// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package dispatcher

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/alert"
	cache2 "github.com/projectcalico/calico/deep-packet-inspection/pkg/cache"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/config"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/dpiupdater"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/eventgenerator"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/exec"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/file"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/fileutils"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/processor"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	keyPrefixDPI = "DeepPacketInspection"
)

type Dispatcher interface {
	// Dispatch receives updates on WEP or DPI resource via CacheRequest array,
	// makes calls to start/stop event generator and snort processor for DPI resource.
	Dispatch(context.Context, []CacheRequest)
	// Close closes all the internal goroutines and processes, stops all running snort and event generators.
	Close()
}

// dispatcher is an implementation of Dispatcher interface.
type dispatcher struct {
	// cache stores all the labels and selectors and also the current mapping between the them.
	cache cache2.SelectorAndLabelCache

	// wepKeyToIface maps WEP key to interface, this is used in combination with wepKeyToDPIs to restart
	// affected snort processes if interface changes.
	wepKeyToIface map[interface{}]string

	// wepKeyToDPIs maps WEP key to set of DPI object as each WEP can map to multiple DPI selectors, it is used in
	// combination with wepKeyToIface to restart affected snort processes if interface changes.
	wepKeyToDPIs map[interface{}]set.Set[DPI]

	// dpiKeyToDPI maps DPI key to DPI object that has processor and event generator.
	dpiKeyToDPI map[interface{}]DPI

	// dirtyItems is updated when dispatcher receives updates and reset after those updates are processed.
	dirtyItems []dirtyItem

	snortProcessor      newProcessor
	eventGenerator      newEventGenerator
	cfg                 *config.Config
	dpiUpdater          dpiupdater.DPIStatusUpdater
	wepCache            cache2.WEPCache
	alertForwarder      alert.Forwarder
	alertFileMaintainer file.FileMaintainer
}

// CacheRequest is used to send resource updates from syncer.
type CacheRequest struct {
	UpdateType bapi.UpdateType
	KVPair     model.KVPair
}

type DPI struct {
	snortProcessor processor.Processor
	eventGenerator eventgenerator.EventGenerator
}

type newProcessor func(ctx context.Context,
	dpiKey model.ResourceKey,
	nodeName string,
	snortExecFn exec.Snort,
	snortAlertFileBasePath string,
	snortAlertFileSize int,
	dpiUpdater dpiupdater.DPIStatusUpdater) processor.Processor

type newEventGenerator func(cfg *config.Config,
	esForwarder alert.Forwarder,
	dpiUpdater dpiupdater.DPIStatusUpdater,
	dpiKey model.ResourceKey,
	wepCache cache2.WEPCache) eventgenerator.EventGenerator

type requestType int

const (
	labelOrSelectorMatchStarted requestType = iota
	labelOrSelectorMatchStopped
	ifaceUpdated
	ifaceDeleted
)

type dirtyItem struct {
	wepKey      interface{}
	dpiKey      interface{}
	ifaceName   string
	requestType requestType
}

func NewDispatcher(cfg *config.Config,
	snortProcessor newProcessor,
	eventGenerator newEventGenerator,
	esForwarder alert.Forwarder,
	dpiUpdater dpiupdater.DPIStatusUpdater,
	alertFileMaintainer file.FileMaintainer,
) Dispatcher {
	dispatch := &dispatcher{
		wepKeyToIface:       make(map[interface{}]string),
		dpiKeyToDPI:         make(map[interface{}]DPI),
		wepKeyToDPIs:        make(map[interface{}]set.Set[DPI]),
		snortProcessor:      snortProcessor,
		eventGenerator:      eventGenerator,
		cfg:                 cfg,
		dpiUpdater:          dpiUpdater,
		alertForwarder:      esForwarder,
		wepCache:            cache2.NewWEPCache(),
		alertFileMaintainer: alertFileMaintainer,
	}
	dispatch.cache = cache2.NewSelectorAndLabelCache(dispatch.onMatchStarted, dispatch.onMatchStopped)
	return dispatch
}

// Dispatch receives updates on WEP or DPI resource via CacheRequest array,
// makes calls to start/stop event generator and snort processor for DPI resource.
func (h *dispatcher) Dispatch(ctx context.Context, cacheRequests []CacheRequest) {
	for _, c := range cacheRequests {
		if wepKey, ok := c.KVPair.Key.(model.WorkloadEndpointKey); ok {
			h.wepCache.Update(c.UpdateType, c.KVPair)
			if wepKey.Hostname != h.cfg.NodeName {
				log.Debugf("Skipping WEP %s that does not belong to the current host", wepKey.WorkloadID)
				continue
			}
			switch c.UpdateType {
			case bapi.UpdateTypeKVNew, bapi.UpdateTypeKVUpdated:
				ep := c.KVPair.Value.(*model.WorkloadEndpoint)
				// If WEP interface has changed, add that to the dirtyItems list first before calling cache.UpdateLabels
				// this ensure new snort process are started using the correct WEP interface.
				if h.wepInterfaceUpdate(wepKey, ep.Name) {
					h.dirtyItems = append(h.dirtyItems, dirtyItem{
						wepKey:      wepKey,
						ifaceName:   ep.Name,
						requestType: ifaceUpdated,
					})
				}
				h.cache.UpdateLabels(c.KVPair.Key, ep.Labels)
			case bapi.UpdateTypeKVDeleted:
				// Call cache.DeleteLabel before adding to dirtyItems list, this ensures all
				// related the snort processes are stopped before deleting the WEP interface from wepKeyToIface.
				h.cache.DeleteLabel(c.KVPair.Key)
				h.dirtyItems = append(h.dirtyItems, dirtyItem{
					wepKey:      wepKey,
					requestType: ifaceDeleted,
				})
			default:
				log.Warn("Unknown update type for WorkloadEndpoint")
			}
		} else if strings.HasPrefix(c.KVPair.Key.String(), keyPrefixDPI) {
			switch c.UpdateType {
			case bapi.UpdateTypeKVNew, bapi.UpdateTypeKVUpdated:
				if dpi, ok := c.KVPair.Value.(*v3.DeepPacketInspection); ok {
					// Include namespace selector to the input selector
					updatedSelector := fmt.Sprintf("(%s) && (%s == '%s')", dpi.Spec.Selector, v3.LabelNamespace, dpi.Namespace)
					sel, err := selector.Parse(updatedSelector)
					if err != nil {
						// This panic is only triggered due to programming error, the original selector in DPI resource
						// is validated by the apiserver during create/update operation, failure to parse updated selector
						// must be due to programming error when appending namespace selector.
						log.WithError(err).Fatal("Failed to parse selector")
					}
					h.cache.UpdateSelector(c.KVPair.Key, sel)
				}
			case bapi.UpdateTypeKVDeleted:
				h.cache.DeleteSelector(c.KVPair.Key)
			default:
				log.Warn("Unknown update type for DeepPacketInspection")
			}
		} else {
			log.Warnf("Unknown object %#v", c)
		}
	}

	h.processDirtyItems(ctx)
}

// Close calls close on all the processors running and tracking snort processes.
func (h *dispatcher) Close() {
	for _, v := range h.dpiKeyToDPI {
		v.eventGenerator.Close()
		v.snortProcessor.Close()
	}
	h.wepCache.Flush()
}

// onMatchStarted is called when there is a new WEP with label that matches the selector in DPI.
// It adds the WEP and DPI key to dirtyItems, to later start snort on the WEP interface.
func (h *dispatcher) onMatchStarted(dpiKey, wepKey interface{}) {
	log.WithField("DPI", dpiKey).Debugf("Snort match available for WEP %v", wepKey)
	h.dirtyItems = append(h.dirtyItems, dirtyItem{
		wepKey:      wepKey,
		dpiKey:      dpiKey,
		requestType: labelOrSelectorMatchStarted,
	})
}

// onMatchStopped is called when previous WEP with label that matches the selector in DPI is no longer valid.
// It adds the WEP and DPI key to dirtyItems, to later stop snort on the WEP interface.
func (h *dispatcher) onMatchStopped(dpiKey, wepKey interface{}) {
	log.WithField("DPI", dpiKey).Debugf("Stopping previous match for WEP %v", wepKey)
	h.dirtyItems = append(h.dirtyItems, dirtyItem{
		wepKey:      wepKey,
		dpiKey:      dpiKey,
		requestType: labelOrSelectorMatchStopped,
	})
}

// wepInterfaceUpdate returns true if old WEP interface is different from the new WEP interface passed or
// if it is a WEP not in cache.
func (h *dispatcher) wepInterfaceUpdate(key model.WorkloadEndpointKey, iface string) bool {
	oldIface, ok := h.wepKeyToIface[key]
	return !ok || (oldIface != iface)
}

// processDirtyItems processes all the items in the dirtyItems list.
// If WEP interface is updated or deleted, update the cache that maps WEP key to interface,
// If labels or selectors are updated, either add or remove the WEP interface from the snortProcessor
// which in turn starts/stops snort process on that interface, also start/stop alert file event generator
// to send the snort alerts to ElasticSearch.
func (h *dispatcher) processDirtyItems(ctx context.Context) {
	for _, i := range h.dirtyItems {
		switch i.requestType {
		case ifaceUpdated:
			oldIface := h.wepKeyToIface[i.wepKey]
			log.Debugf("Updating the cached WEP interface from %s to %s for WEP %v", oldIface, i.ifaceName, i.wepKey)
			h.wepKeyToIface[i.wepKey] = i.ifaceName
			// stop and remove all old WEP interfaces
			prcs, ok := h.wepKeyToDPIs[i.wepKey]
			if ok {
				for dpi := range prcs.All() {
					h.startDPIOnWEP(ctx, dpi, i.dpiKey.(model.ResourceKey), i.wepKey.(model.WorkloadEndpointKey))
				}
				// add the updated WEP interfaces
				for dpi := range prcs.All() {
					h.startDPIOnWEP(ctx, dpi, i.dpiKey.(model.ResourceKey), i.wepKey.(model.WorkloadEndpointKey))
				}
			}
		case ifaceDeleted:
			log.Debugf("Deleting the cached WEP interface %s for WEP %v", i.ifaceName, i.wepKey)
			delete(h.wepKeyToIface, i.wepKey)
			delete(h.wepKeyToDPIs, i.wepKey)
		case labelOrSelectorMatchStarted:
			dpi, ok := h.dpiKeyToDPI[i.dpiKey]
			if !ok {
				dpi = h.initializeDPI(ctx, i.dpiKey.(model.ResourceKey))
				// Update the mapping of WEP interface to snortProcessor and also mapping of DPI key to snortProcessor
				dpis, ok := h.wepKeyToDPIs[i.wepKey]
				if !ok {
					dpis = set.New[DPI]()
				}
				dpis.Add(dpi)
				h.wepKeyToDPIs[i.wepKey] = dpis
				h.dpiKeyToDPI[i.dpiKey] = dpi
			}

			h.startDPIOnWEP(ctx, dpi, i.dpiKey.(model.ResourceKey), i.wepKey.(model.WorkloadEndpointKey))
		case labelOrSelectorMatchStopped:
			dpi, ok := h.dpiKeyToDPI[i.dpiKey]
			if ok {
				h.stopDPIOnWEP(dpi, i.dpiKey.(model.ResourceKey), i.wepKey.(model.WorkloadEndpointKey))
				if dpi.snortProcessor.WEPInterfaceCount() == 0 {
					h.stopDPI(dpi, i.dpiKey.(model.ResourceKey))
					v, ok := h.wepKeyToDPIs[i.wepKey]
					if ok {
						v.Discard(dpi)
					}
					h.wepKeyToDPIs[i.wepKey] = v
					delete(h.dpiKeyToDPI, i.dpiKey)
				}
			}
		}
	}

	// Clear the dirtyItems list after handling all the changes.
	h.dirtyItems = []dirtyItem{}
}

func (h *dispatcher) initializeDPI(ctx context.Context, dpiKey model.ResourceKey) DPI {
	log.Debugf("Initializing deep packet inspection for %v", dpiKey)
	processor := h.snortProcessor(ctx, dpiKey, h.cfg.NodeName, exec.NewExec, h.cfg.SnortAlertFileBasePath, h.cfg.SnortAlertFileSize, h.dpiUpdater)
	generator := h.eventGenerator(h.cfg, h.alertForwarder, h.dpiUpdater, dpiKey, h.wepCache)
	return DPI{
		snortProcessor: processor,
		eventGenerator: generator,
	}
}

func (h *dispatcher) startDPIOnWEP(ctx context.Context, dpiProcess DPI, dpiKey model.ResourceKey, wepKey model.WorkloadEndpointKey) {
	log.Debugf("Starting deep packet inspection %s on %s", dpiKey, wepKey)
	dpiProcess.snortProcessor.Add(ctx, wepKey, h.wepKeyToIface[wepKey])
	dpiProcess.eventGenerator.GenerateEventsForWEP(wepKey)
	h.alertFileMaintainer.Maintain(fileutils.AlertFileAbsolutePath(dpiKey, wepKey, h.cfg.SnortAlertFileBasePath))
}

func (h *dispatcher) stopDPIOnWEP(dpiProcess DPI, dpiKey model.ResourceKey, wepKey model.WorkloadEndpointKey) {
	log.Debugf("Stopping deep packet inspection %s on %s", dpiKey, wepKey)
	dpiProcess.snortProcessor.Remove(wepKey)
	dpiProcess.eventGenerator.StopGeneratingEventsForWEP(wepKey)
	h.alertFileMaintainer.Stop(fileutils.AlertFileAbsolutePath(dpiKey, wepKey, h.cfg.SnortAlertFileBasePath))
}

func (h *dispatcher) stopDPI(dpiProcess DPI, dpiKey model.ResourceKey) {
	log.Debugf("Cleaning up deep packet inspection %v", dpiKey)
	dpiProcess.snortProcessor.Close()
	dpiProcess.eventGenerator.Close()
}
