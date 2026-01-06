package k8s

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/lib/std/chanutil"
)

type EventType = watch.EventType

const (
	Added               = watch.Added
	Modified            = watch.Modified
	Deleted             = watch.Deleted
	SyncStart EventType = "SYNC_START"
	SyncEnd   EventType = "SYNC_END"
)

type Event[T any] struct {
	Type EventType
	Obj  *T
}

// WatchManagedClusters watches for changes to managed clusters in the given namespace. It starts by listing the clusters
// and initiating a SyncStart event. It will write all the objects onto the result channel grabbed from the list, and when
// all have been written, it will send a SyncEnd event. At this point the watch starts.
//
// If the watch cannot continue and needs to be restarted and the resource version is no longer valid, another sync event
// will be sent and the process will repeat. The Sync events allow the callers to know that the watch has been interrupted
// and can't recover, and the state needs to be replaced.
func WatchManagedClusters(ctx context.Context, k8sCli ctrlclient.WithWatch, ns string, results chan Event[v3.ManagedCluster]) error {
	for {
		rs, err := syncResources(ctx, k8sCli, ns, results)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			logrus.WithError(err).Errorf("Failed to sync resources, will retry.")
		}

		err = startWatch(ctx, k8sCli, ns, rs, results)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			logrus.WithError(err).Errorf("watch closed")
		}
	}
}

func syncResources(ctx context.Context, k8sCli ctrlclient.WithWatch, ns string, results chan Event[v3.ManagedCluster]) (string, error) {
	managedClusterList := &v3.ManagedClusterList{}
	for {
		err := k8sCli.List(ctx, managedClusterList, &ctrlclient.ListOptions{Namespace: ns})
		if err != nil {
			logrus.WithError(err).Errorf("failed to list managed clusters")
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			continue
		}

		break
	}

	// Signal that the receiver needs to start syncing. This needs to be handled even (and especially) when the list is
	// empty to handle the case where all managed clusters were removed while the watch was down.
	if err := chanutil.Write(ctx, results, Event[v3.ManagedCluster]{Type: SyncStart}); err != nil {
		return "", err
	}

	if len(managedClusterList.Items) > 0 {
		for _, mc := range managedClusterList.Items {
			// Return if an error occurs here as that means something is wrong with the cluster or the context signaled
			// and error.
			if err := chanutil.Write(ctx, results, Event[v3.ManagedCluster]{Type: Added, Obj: &mc}); err != nil {
				return "", err
			}
		}
	}

	if err := chanutil.Write(ctx, results, Event[v3.ManagedCluster]{Type: SyncEnd}); err != nil {
		return "", err
	}

	return managedClusterList.ResourceVersion, nil
}

func startWatch(ctx context.Context, k8sCli ctrlclient.WithWatch, ns string, rs string, results chan Event[v3.ManagedCluster]) error {
	for {
		if ctx.Err() != nil {
			return nil
		}

		watcher, err := k8sCli.Watch(ctx, &v3.ManagedClusterList{},
			&ctrlclient.ListOptions{
				Namespace: ns,
				Raw:       &metav1.ListOptions{ResourceVersion: rs},
			},
		)
		if err != nil {
			logrus.WithError(err).Error("failed to create k8s watch")
			if errors.IsResourceExpired(err) || errors.IsGone(err) {
				return err
			}

			time.Sleep(time.Second)
			continue
		}
		eventCh := watcher.ResultChan()
	inner:
		for {
			select {
			case event, ok := <-eventCh:
				if !ok {
					logrus.Errorf("watcher stopped unexpectedly")
					break inner
				}

				mc, ok := event.Object.(*v3.ManagedCluster)
				if !ok {
					logrus.Errorf("Unexpected object type %T", event.Object)
					continue
				}

				logrus.Debugf("Watching K8s resource type: %s for cluster %s", event.Type, mc.Name)
				switch event.Type {
				case Added, Modified, Deleted:
					if err := chanutil.Write(ctx, results, Event[v3.ManagedCluster]{Type: event.Type, Obj: mc}); err != nil {
						logrus.Errorf("Failed to write event to channel: %s", err)
						break inner
					}
				default:
					logrus.Errorf("Watch event %s unsupported", event.Type)
				}

				rs = mc.ResourceVersion
			case <-ctx.Done():
				watcher.Stop()
				return nil
			}
		}
	}
}
