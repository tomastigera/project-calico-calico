// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package server

import (
	"context"
	"slices"
	"time"

	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/voltron/internal/pkg/config"
	"github.com/projectcalico/calico/voltron/internal/pkg/server/metrics"
)

type StatusConfig struct {
	tickPeriod     time.Duration
	initialBackoff time.Duration
	maxBackoff     time.Duration
	metricsPeriod  time.Duration
}

var (
	defaultStatusConfig = StatusConfig{
		tickPeriod:     time.Second,
		initialBackoff: time.Second,
		maxBackoff:     30 * time.Second,
		metricsPeriod:  5 * time.Second,
	}
)

type managedClusterStatusUpdate struct {
	status             v3.ManagedClusterStatusValue
	managedClusterName string
}

type updateAttemptResult struct {
	managedClusterName string
	status             updateStateType
	err                error
}

type finishedFunc func(updateStateType, error)

type managedClusterStatusRequest struct {
	status             v3.ManagedClusterStatusValue
	managedClusterName string
	finish             finishedFunc
}

type updateStateType string

const (
	updateStateInitial   updateStateType = "Initial"
	updateStateFailed    updateStateType = "Failed"
	updateStateSucceeded updateStateType = "Succeeded"
	updateStateNotFound  updateStateType = "NotFound"
)

type managedClusterStatusState struct {
	managedClusterStatusUpdate

	backoff          time.Duration
	retryTime        time.Time
	updateState      updateStateType
	updateInProgress bool
}

type StatusUpdater interface {
	IsRetryInProgress(string) bool
	SetStatus(managedClusterName string, status v3.ManagedClusterStatusValue)
}

type statusUpdaterImpl struct {
	connectionStatuses      map[string]*managedClusterStatusState
	statusHandlerChan       chan managedClusterStatusRequest
	metricsTenant           string
	managedClusterNamespace string
	statusUpdateChan        chan *managedClusterStatusUpdate
	config                  *StatusConfig
}

// statusUpdater is intended to be ran as a go thread that will read the last state sent to the statusUpdate channel
// and update the managedCluster resource with the connection status. It will retry the update with an increasing
// backoff up to 30 seconds. This function will stop when the context is done.
func NewStatusUpdater(ctx context.Context, client ctrlclient.WithWatch, cfg config.Config, sc *StatusConfig) StatusUpdater {
	if sc == nil {
		sc = &defaultStatusConfig
	}
	sui := statusUpdaterImpl{
		connectionStatuses:      make(map[string]*managedClusterStatusState),
		statusHandlerChan:       make(chan managedClusterStatusRequest, 1),
		metricsTenant:           cfg.TenantClaim,
		managedClusterNamespace: cfg.TenantNamespace,
		statusUpdateChan:        make(chan *managedClusterStatusUpdate, 20),
		config:                  sc,
	}
	go sui.run(ctx)
	go sui.listenForStatusUpdates(ctx, client)

	return &sui
}

func (su *statusUpdaterImpl) IsRetryInProgress(clusterName string) bool {
	x, ok := su.connectionStatuses[clusterName]
	return ok && x.updateState != updateStateSucceeded
}

func (su *statusUpdaterImpl) SetStatus(managedClusterName string, status v3.ManagedClusterStatusValue) {
	su.statusUpdateChan <- &managedClusterStatusUpdate{
		status:             status,
		managedClusterName: managedClusterName,
	}
}

// It is expected that a status update has already been attempted and may have succeeded before sending
// the update to the statusUpdateChan. We'll set up a retry for all updates to ensure that if there was
// a race condition between a previous retry and a new status update that the retry will ensure
// eventually we'll have the correct connection status.
func (su *statusUpdaterImpl) run(ctx context.Context) {
	retryTicker := time.NewTicker(su.config.tickPeriod)
	defer retryTicker.Stop()

	_, err := metrics.ConnectionStatusFailedAttempts.GetMetricWithLabelValues(su.metricsTenant)
	if err != nil {
		logrus.WithError(err).Warn("Failed to get status failed metric for initialization")
	}
	metricsTicker := time.NewTicker(su.config.metricsPeriod)
	defer metricsTicker.Stop()

	updateInProgress := false
	updateFinished := make(chan updateAttemptResult, 1)
	logrus.Debug("Starting statusUpdater")
	t := time.Now()
	for {
		select {
		case update := <-su.statusUpdateChan:
			logrus.Debugf("Handling connection status event %v for %s", update.status, update.managedClusterName)
			if x, ok := su.connectionStatuses[update.managedClusterName]; ok && x.updateInProgress {
				logrus.Infof("New status update received for %s while update is in progress", update.managedClusterName)
			}
			us := managedClusterStatusState{
				managedClusterStatusUpdate: *update,
				updateState:                updateStateInitial,
				updateInProgress:           false,
				backoff:                    su.config.initialBackoff,
			}
			// Use the last time we've seen (either initial time or last time from the retry tick) so that this
			// updateState will be acted on immediately.
			us.retryTime = t
			su.connectionStatuses[update.managedClusterName] = &us

		case t = <-retryTicker.C:
			// Nothing special to do here, fall out of the switch to the code below
		case uf := <-updateFinished:
			logrus.Debugf("Handling update attempt event %v for %s", uf.status, uf.managedClusterName)
			if _, ok := su.connectionStatuses[uf.managedClusterName]; !ok {
				logrus.Error("BUG: Update attempt event received for managed cluster that is not being tracked")
				break
			}
			setStatus := su.connectionStatuses[uf.managedClusterName].status
			name := uf.managedClusterName
			if uf.status == updateStateFailed {
				m, err := metrics.ConnectionStatusFailedAttempts.GetMetricWithLabelValues(su.metricsTenant)
				if err != nil {
					logrus.WithError(err).Warn("Failed to get status failed metric")
				}
				m.Inc()
			}
			// If the connectionStatuses for the managedClusterName that was just finished does not have
			// updateInProgress true, that means we've received a new update for the managed cluster
			// since we sent a request to the updateHandler channel so we assume that we still need
			// to make that update so basically ignore the result of the updateFinished we received.
			if su.connectionStatuses[uf.managedClusterName].updateInProgress {
				su.connectionStatuses[name].updateInProgress = false
				switch uf.status {
				case updateStateSucceeded:
					logrus.Infof("Connection status update %v for %s succeeded", setStatus, name)
					// No need to keep an entry for successful updates, so remove them from the map
					// We know that a new update has not been received because the updateInProgress was true.
					delete(su.connectionStatuses, name)
				case updateStateFailed:
					su.connectionStatuses[name].updateState = updateStateFailed
					b := su.connectionStatuses[name].backoff
					su.connectionStatuses[name].retryTime = time.Now().Add(b)
					logrus.WithError(uf.err).Errorf(
						"failed to update the connection status (%v) for cluster %s, retry at %s",
						setStatus,
						name,
						su.connectionStatuses[name].retryTime.Format(time.RFC3339))
					// The update failed again, increase the backoff (unless it is already at 30). Do this after setting
					// the retryTime for the update.
					b = 2 * b
					if b > su.config.maxBackoff {
						b = su.config.maxBackoff
					}
					su.connectionStatuses[name].backoff = b

				case updateStateNotFound:
					logrus.Infof("Connection status update for %s: ManagedCluster resource was not found, assuming it was removed", name)
					delete(su.connectionStatuses, name)
				}
			} else {
				logrus.Infof("Connection status update for %s was ignored because a new update was received while one was being processed", name)
			}

			updateInProgress = false

		case <-metricsTicker.C:
			updatesToSyncMetric, err := metrics.ConnectionStatusNotInSync.GetMetricWithLabelValues(su.metricsTenant)
			if err != nil {
				logrus.WithError(err).Warn("Failed to get status queue metric")
			}
			//logrus.Debugf("updating metrics %d", count)
			updatesToSyncMetric.Set(float64(len(su.connectionStatuses)))

			continue
		case <-ctx.Done():
			// Context is done, exit this thread
			logrus.Debug("Stopping statusUpdater")
			return
		}

		if !updateInProgress && len(su.connectionStatuses) > 0 {
			var pendingStatuses []*managedClusterStatusState
			for _, v := range su.connectionStatuses {
				pendingStatuses = append(pendingStatuses, v)
			}

			cs := slices.MinFunc(pendingStatuses, func(i, j *managedClusterStatusState) int {
				return i.retryTime.Compare(j.retryTime)
			})

			// The Compare function definition: If t is before v.retryTime, it returns -1;
			// if t is after v.retryTime, it returns +1; if they're the same, it returns 0.
			if t.Compare(cs.retryTime) >= 0 {
				updateInProgress = true
				cs.updateInProgress = true
				logrus.Debugf("Sending update to handler for %s", cs.managedClusterName)
				su.statusHandlerChan <- managedClusterStatusRequest{
					status:             cs.status,
					managedClusterName: cs.managedClusterName,
					finish: func(st updateStateType, err error) {
						updateFinished <- updateAttemptResult{
							managedClusterName: cs.managedClusterName,
							err:                err,
							status:             st,
						}
					},
				}
			}
		}
	}
}

func (su *statusUpdaterImpl) listenForStatusUpdates(ctx context.Context, client ctrlclient.WithWatch) {
	logrus.Debug("Starting statusHandler")

	for {
		select {
		case s := <-su.statusHandlerChan:
			err := setConnectedStatus(client, su.managedClusterNamespace, s.managedClusterName, s.status)
			if err != nil {
				if kerr.IsNotFound(err) {
					s.finish(updateStateNotFound, nil)
				} else {
					s.finish(updateStateFailed, err)
				}
			} else {
				s.finish(updateStateSucceeded, nil)
			}

		case <-ctx.Done():
			// Context is done, exit this thread
			logrus.Debug("Stopping statusHandler")
			return
		}
	}
}

// setConnectedStatus updates the MangedClusterConnected condition of this cluster's ManagedCluster CR.
func setConnectedStatus(client ctrlclient.WithWatch, namespace, managedClusterName string, status v3.ManagedClusterStatusValue) error {

	var mc = &v3.ManagedCluster{}
	ctx, cancel := context.WithTimeout(context.Background(), contextTimeout)
	defer cancel()
	err := client.Get(ctx, types.NamespacedName{Name: managedClusterName, Namespace: namespace}, mc)
	if err != nil {
		return err
	}

	var updatedConditions []v3.ManagedClusterStatusCondition

	connectedConditionFound := false
	for _, c := range mc.Status.Conditions {
		if c.Type == v3.ManagedClusterStatusTypeConnected {
			c.Status = status
			connectedConditionFound = true
		}
		updatedConditions = append(updatedConditions, c)
	}

	if !connectedConditionFound {
		updatedConditions = append(updatedConditions, v3.ManagedClusterStatusCondition{
			Type:   v3.ManagedClusterStatusTypeConnected,
			Status: status,
		})
	}

	mc.Status.Conditions = updatedConditions

	err = client.Update(ctx, mc)
	if err != nil {
		return err
	}

	return nil
}
