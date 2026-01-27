// Copyright (c) 2018-2020 Tigera, Inc. All rights reserved.
package dispatcherv1v3

import (
	"fmt"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/watchersyncer"
	"github.com/projectcalico/calico/queryserver/pkg/querycache/envoptions"
)

const (
	numUpdatesPerPerfLog = 500
)

type Interface interface {
	api.SyncerCallbacks
	RegisterHandler(kinds string, callbackFn CallbackFn)
}

type Update struct {
	UpdateV3 *api.Update
	UpdateV1 *api.Update
}

type CallbackFn func(update Update)

type Resource struct {
	Kind      string
	Converter Converter
}

type Converter interface {
	ConvertV3ToV1(*api.Update) *api.Update
}

func New(rs []Resource) Interface {
	resourceTypes := make(map[string]*resourceType, len(rs))
	resources := make(map[model.ResourceKey]struct{})
	for _, r := range rs {
		resourceTypes[r.Kind] = &resourceType{
			converter: r.Converter,
		}
	}

	return &dispatcher{
		resourceTypes:   resourceTypes,
		outputPerfStats: envoptions.OutputPerfStats(),
		resources:       resources,
	}
}

type resourceType struct {
	converter Converter
	callbacks []CallbackFn
}

type dispatcher struct {
	resourceTypes map[string]*resourceType

	// Performance statistics tracking
	startSync       time.Time
	updateIdx       int
	updateTime      time.Duration
	outputPerfStats bool
	memstats        runtime.MemStats
	resources       map[model.ResourceKey]struct{}
}

func (d *dispatcher) RegisterHandler(kind string, callbackFn CallbackFn) {
	rt, ok := d.resourceTypes[kind]
	if !ok {
		log.WithField("Kind", kind).Fatal("Registering handler for unknown resource type")
	}
	rt.callbacks = append(rt.callbacks, callbackFn)
}

// OnUpdates is a callback from the SyncerQuerySerializer to update our cache from a syncer
// update.  It is guaranteed not to be called at the same time as RunQuery and OnStatusUpdated.
func (d *dispatcher) OnUpdates(updates []api.Update) {
	for idx := range updates {
		update := &updates[idx]
		key := update.Key.(model.ResourceKey)
		rt, ok := d.resourceTypes[key.Kind]
		if !ok {
			log.WithField("Key", key).Info("No handler registered for resource kind - skipping")
			continue
		}

		updatev1v3 := Update{
			UpdateV3: update,
		}

		var startTime time.Time
		if d.outputPerfStats {
			startTime = time.Now()
		}

		// Convert the update to an equivalent set of v1 updates using the update processor.
		if rt.converter != nil {
			updatev1v3.UpdateV1 = rt.converter.ConvertV3ToV1(update)
		}

		// if the v1 update value is nil then it's filtered out, so treat this update as delete
		if updatev1v3.UpdateV1 != nil && updatev1v3.UpdateV1.Value == nil {
			updatev1v3.UpdateV3.UpdateType = api.UpdateTypeKVDeleted
		}

		// if update is of type delete and resource is not in cache then ignore the update, if present then delete the item
		if updatev1v3.UpdateV3.UpdateType == api.UpdateTypeKVDeleted {
			if _, found := d.resources[key]; !found {
				continue
			}
			delete(d.resources, key)
		}

		// if update is of type update and resource is not in cache then convert it to create and add to cache
		if updatev1v3.UpdateV3.UpdateType == api.UpdateTypeKVUpdated || updatev1v3.UpdateV3.UpdateType == api.UpdateTypeKVNew {
			if _, found := d.resources[key]; !found {
				updatev1v3.UpdateV3.UpdateType = api.UpdateTypeKVNew
				d.resources[key] = struct{}{}
			}
		}
		// sanitize the v1 update type to be the same as the v3 update type
		if updatev1v3.UpdateV1 != nil && updatev1v3.UpdateV3 != nil {
			updatev1v3.UpdateV1.UpdateType = updatev1v3.UpdateV3.UpdateType
		}
		// Invoke each callback in the registered order with the update.
		for _, cb := range rt.callbacks {
			cb(updatev1v3)
		}

		if d.outputPerfStats {
			d.updateTime += time.Since(startTime)
			if d.updateIdx%numUpdatesPerPerfLog == 0 {
				runtime.ReadMemStats(&d.memstats)
				duration := d.updateTime
				if d.updateIdx != 0 {
					duration = duration / time.Duration(numUpdatesPerPerfLog)
				}
				fmt.Printf("NumUpdate = %v\tAvgUpdateDuration = %v\t"+
					"HeapAlloc = %v\tSys = %v\tNumGC = %v\nNumGoRoutines = %v\n",
					d.updateIdx, duration, d.memstats.HeapAlloc/1024,
					d.memstats.Sys/1024, d.memstats.NumGC, runtime.NumGoroutine(),
				)
				d.updateTime = 0
			}
			d.updateIdx++
		}
	}
}

// OnStatusUpdated is a callback from the SyncerQuerySerializer to update our cache from a syncer
// update.  It is guaranteed not to be called at the same time as RunQuery and OnUpdates.
// This is a no-op.
func (d *dispatcher) OnStatusUpdated(status api.SyncStatus) {
	log.WithField("status", status).Debug("OnStatusUpdated")
	if d.outputPerfStats {
		switch status {
		case api.WaitForDatastore:
			fmt.Println("Waiting for datastore for sync")
		case api.ResyncInProgress:
			fmt.Println("Datastore sync started")
			d.startSync = time.Now()
		case api.InSync:
			fmt.Printf("Datastore sync completed after %v\n", time.Since(d.startSync))
		}
	}
}

// Create a Converter from a SyncerUpdateProcessor.  Care is needed here.  Updates only
// work if there is a fixed one to one mapping between the v1 and the v3 keys.  The upshot of
// this is that this cannot be used with SyncerUpdateProcessors that use an internal cache
// to maintain a relationship between the v1 and v3 keys (e.g. any resource where a change to the
// v3 Spec could result in a change to the v1 key, such as HostEndpoint).
func NewConverterFromSyncerUpdateProcessor(up watchersyncer.SyncerUpdateProcessor) Converter {
	return &supConverter{up: up}
}

type supConverter struct {
	up watchersyncer.SyncerUpdateProcessor
}

func (s *supConverter) ConvertV3ToV1(v3Update *api.Update) *api.Update {
	v1Updates, err := s.up.Process(&v3Update.KVPair)
	if err != nil {
		// Log error and return a nil value.
		log.WithError(err).WithField("key", v3Update.KVPair.Key).Warn("Unable to convert v3 value to v1")
		return nil
	}
	if v1Updates == nil {
		// Resource must have been filtered out.  Not a lot we can do here.  Return a nil
		// update.
		log.WithField("Resource", v3Update.Key).Info("The v1 resource has been filtered out")
		return nil
	}
	if len(v1Updates) != 1 {
		// The v3 update has resulted in a different number of v1 updates.  This will only happen if
		// the v3 resource is made up of multiple v1 resources, or there is not a fixed mapping between
		// the two sets of keys. In either case this is a code error and we should terminate.
		log.WithFields(log.Fields{
			"v3-update":  *v3Update,
			"v1-updates": v1Updates,
		}).Fatal("Unexpected v1 updates from a v3 update")
	}
	return &api.Update{
		UpdateType: v3Update.UpdateType,
		KVPair:     *v1Updates[0],
	}
}
