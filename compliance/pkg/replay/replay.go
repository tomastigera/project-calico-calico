package replay

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/event"
	"github.com/projectcalico/calico/compliance/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

type replayer struct {
	resources  map[metav1.TypeMeta]map[apiv3.ResourceID]resources.Resource
	start, end time.Time
	lister     api.ListDestination
	eventer    api.ReportEventFetcher
	cb         syncer.SyncerCallbacks
}

func New(start, end time.Time, lister api.ListDestination, eventer api.ReportEventFetcher, callbacks syncer.SyncerCallbacks) syncer.Starter {
	return &replayer{
		make(map[metav1.TypeMeta]map[apiv3.ResourceID]resources.Resource),
		start, end, lister, eventer, callbacks,
	}
}

// Start will first initialize the replayer to a synced state specified by the start Time, send an in-sync update,
// replay all the audit events between the start and end Times, and then send a complete update.
func (r *replayer) Start(ctx context.Context) {
	log.Info("Initializing replayer cache to start time")
	if err := r.initialize(ctx); err != nil {
		r.cb.OnStatusUpdate(syncer.NewStatusUpdateFailed(err))
		return
	}
	log.Info("Syncer status: in-sync")
	r.cb.OnStatusUpdate(syncer.NewStatusUpdateInSync())

	log.Info("Replaying audit events to end time")
	if err := r.replay(ctx, &r.start, &r.end, true); err != nil {
		log.Info("Syncer status: failed")
		r.cb.OnStatusUpdate(syncer.NewStatusUpdateFailed(err))
		return
	}
	log.Info("Syncer status: complete")
	r.cb.OnStatusUpdate(syncer.NewStatusUpdateComplete())
}

// Initialize performs the following for all resource types:
// - Retrieve most recent list from before the specified start time.
// - Retrieve events from the list's timestamp up until the specified start time.
// - Replay the retrieve events on top of the list.
func (r *replayer) initialize(ctx context.Context) error {
	var firstSnapshot *metav1.Time
	for _, rh := range resources.GetAllResourceHelpers() {
		kind := rh.TypeMeta()
		clog := log.WithField("kind", kind.String())
		clog.Debug("Initializing replayer")

		// Allocate map for resource.
		r.resources[kind] = make(map[apiv3.ResourceID]resources.Resource)

		// Get list for resource.
		l, err := r.lister.RetrieveList(kind, nil, &r.start, false)
		if err != nil {
			return err
		}
		clog.Debug("Retrieved list")

		// Track the earliest snapshot that we use - we need to play event stream back from this earliest point
		// to ensure we capture any namespace delete/create events.
		if firstSnapshot == nil || l.RequestStartedTimestamp.Before(firstSnapshot) {
			firstSnapshot = &l.RequestStartedTimestamp
		}

		// Extract the list into an array of runtime.Objects.
		objs, err := meta.ExtractList(l.ResourceList)
		if err != nil {
			return err
		}
		clog.WithField("length", len(objs)).Debug("Extracted list into array")

		// Iterate over objects and store into map.
		for i := range objs {
			res, ok := objs[i].(resources.Resource)
			if !ok {
				clog.WithField("obj", objs[i]).Warn("Failed to type assert resource")
				continue
			}
			res.GetObjectKind().SetGroupVersionKind((&kind).GroupVersionKind())
			id := resources.GetResourceID(res)
			r.resources[kind][id] = res
		}
		clog.Debug("Stored snapshots into internal cache - replaying events to start time")
	}

	// Replay events into the internal cache from the list time to the desired start time.
	if err := r.replay(ctx, &firstSnapshot.Time, &r.start, false); err != nil {
		return err
	}
	log.Debug("Replayed events to start time - publishing syncer updates")

	// Send Update to callbacks.
	for tm, cache := range r.resources {
		log.Infof("Sending initial snapshot for %s", tm)
		for id, res := range cache {
			log.WithField("id", id).Debug("Publishing syncer updates")
			r.cb.OnUpdates([]syncer.Update{{Type: syncer.UpdateTypeSet, ResourceID: id, Resource: res}})
		}
	}
	return nil
}

// replay fetches events for the given resource from the list's timestamp up until the specified start time.
func (r *replayer) replay(ctx context.Context, from, to *time.Time, notifyUpdates bool) error {
	for ev := range r.eventer.GetAuditEvents(ctx, from, to) {
		if ev.Err != nil {
			return ev.Err
		}

		clog := log.WithFields(log.Fields{"auditID": ev.AuditID, "verb": ev.Verb})

		// Determine proper resource to update for internal cache.
		res, err := event.ExtractResourceFromAuditEvent(ev.Event)
		if err != nil {
			// Inability to parse the audit event should not terminate the replayer. Best we can do here is log.
			clog.WithError(err).Error("Unable to parse audit event - skipping")
			continue
		}

		// Nil resource and nil error means a status object.
		if res == nil {
			clog.Debug("No resource in audit event (maybe a status event or wrong event type) - skipping")
			continue
		}

		// Update the internal cache and send the appropriate Update to the callbacks.
		kind := resources.GetTypeMeta(res)
		resMap, ok := r.resources[kind]
		if !ok {
			clog.Warn("Failed to retrieve map for kind - skipping")
			continue
		}

		id := resources.GetResourceID(res)
		update := syncer.Update{ResourceID: id, Resource: res}
		clog = clog.WithFields(log.Fields{"resID": id, "kind": kind})
		switch v1.Verb(ev.Verb) {
		case v1.Create, v1.Update, v1.Patch:
			clog.Debug("Set event")
			update.Type = syncer.UpdateTypeSet

			// Refuse to apply audit event if resource version of old resource is higher
			//  than the new one.
			oldRes, ok := resMap[id]
			if ok {
				oldResVer, err := resources.GetResourceVersion(oldRes)
				if err != nil {
					clog.WithError(err).Error("Failed to convert resourceVersion to number - skipping")
					continue
				}
				newResVer, err := resources.GetResourceVersion(res)
				if err != nil {
					clog.WithError(err).Error("Failed to convert resourceVersion to number - skipping")
					continue
				}
				if oldResVer > newResVer {
					clog.Debug("Resource version conflict detected - skipping")
					continue
				}
			}
			resMap[id] = res
		case v1.Delete:
			clog.Debug("Delete event")

			// Delete events will not actually contain the resource, so fix up the update from the cached value.
			if res, ok := resMap[id]; ok {
				update.Resource = res
			}
			update.Type = syncer.UpdateTypeDeleted
			delete(resMap, id)
		default:
			clog.Info("Unhandled event type")
		}

		// Convert the update to a slice.
		var updates []syncer.Update

		if update.Type == syncer.UpdateTypeDeleted && update.ResourceID.TypeMeta == resources.TypeK8sNamespaces {
			// This is a namespace deletion, perform some additional deletion and, if notifying, obtain the additional
			// set of updates.
			log.Infof("Handling deletion of namespace: %s", update.ResourceID.Name)
			updates = r.handleNamespaceDeletion(update.ResourceID.Name, notifyUpdates)
		}

		// Send the updates. We send in a single hit so that the xref cache can handle the updates as a group to avoid
		// extra churn.
		if notifyUpdates {
			updates = append(updates, update)
			log.Infof("Sending %d updates", len(updates))
			r.cb.OnUpdates(updates)
		}
	}
	return nil
}

// handleNamespaceDeletion is responsible for performing cross-resource updates when deleting a namespace.
func (r *replayer) handleNamespaceDeletion(namespace string, notifyUpdates bool) []syncer.Update {
	// Special processing is required for namespace deletion. Iterate through all of the caches and delete entries for
	// all resources in the same namespace. We'll end up iterating through non-namespaced resource types, but none will
	// match so we'll just skip - not the most efficient, but simple, and namespace deletion is not a frequent event.
	var updates []syncer.Update
	for tm, cache := range r.resources {
		log.Infof("Handling deletion %s in namespace %s", tm, namespace)
		for id, res := range cache {
			if id.Namespace != namespace {
				continue
			}

			// Namespace of this resource is the same as the deleted namespace, remove from the cache and add to our
			// updates.
			log.Infof("Deleting %s from replayer cache", id)

			if notifyUpdates {
				updates = append(updates, syncer.Update{
					Type:       syncer.UpdateTypeDeleted,
					ResourceID: id,
					Resource:   res,
				})
			}

			// Remove the entry from the cache. It is safe to modify the map during enumeration with golang.
			delete(cache, id)
		}
	}

	return updates
}
