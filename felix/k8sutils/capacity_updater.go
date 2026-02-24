// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package k8sutils

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/clock"

	"github.com/projectcalico/calico/felix/aws"
)

// CapacityUpdater manages a background goroutine that maintains the "projectcalico.org/aws-secondary-ipv4"
// "extended resource" quota.
type CapacityUpdater struct {
	nodeName        string
	timeout         time.Duration
	refreshInterval time.Duration
	updateC         chan aws.SecondaryIfaceCapacities

	k8sClient KubeClient
	clock     clock.Clock

	lastCapacityUpdate *aws.SecondaryIfaceCapacities
}

const (
	ResourceSecondaryIPv4  = "projectcalico.org/aws-secondary-ipv4"
	defaultTimeout         = 30 * time.Second
	defaultRefreshInterval = 10 * time.Minute
)

type KubeClient interface {
	v1.NodesGetter
}

type CapacityUpdaterOpt func(updater *CapacityUpdater)

func OptClockOverride(c clock.Clock) CapacityUpdaterOpt {
	return func(updater *CapacityUpdater) {
		updater.clock = c
	}
}

func NewCapacityUpdater(nodeName string, k8sClient KubeClient, opts ...CapacityUpdaterOpt) *CapacityUpdater {
	cu := &CapacityUpdater{
		nodeName:        nodeName,
		k8sClient:       k8sClient,
		updateC:         make(chan aws.SecondaryIfaceCapacities, 1),
		clock:           clock.RealClock{},
		timeout:         defaultTimeout,
		refreshInterval: defaultRefreshInterval,
	}
	for _, op := range opts {
		op(cu)
	}
	return cu
}

func (u *CapacityUpdater) OnCapacityChange(capacities aws.SecondaryIfaceCapacities) {
	// Discard any queued update by doing a non-blocking read.
	select {
	case <-u.updateC:
	default:
	}

	// This write should never block.
	u.updateC <- capacities
}

func (u *CapacityUpdater) Start(ctx context.Context) chan struct{} {
	logrus.Info("Starting Kubernetes capacity updater")
	doneC := make(chan struct{})
	go u.loopUpdatingK8s(ctx, doneC)
	return doneC
}

func (u *CapacityUpdater) loopUpdatingK8s(ctx context.Context, doneC chan struct{}) {
	defer func() {
		logrus.WithField("doneC", doneC).Info("Kubernetes capacity updater stopping")
		close(doneC)
	}()
	logrus.WithField("nodeName", u.nodeName).Info("Kubernetes capacity updater running in background")

	// Set ourselves up for exponential backoff after a failure.  backoffMgr.Backoff() returns the same Timer
	// on each call so we need to stop it properly when cancelling it.
	var backoffTimer clock.Timer
	var backoffC <-chan time.Time
	backoffMgr := u.newBackoffManager()
	stopBackoffTimer := func() {
		if backoffTimer != nil {
			// Reset the timer before calling Backoff() again for correct behaviour. This is the standard
			// time.Timer.Stop() dance...
			logrus.Debug("Stopping backoff timer")
			if !backoffTimer.Stop() {
				<-backoffTimer.C()
			}
			backoffTimer = nil
			backoffC = nil
		}
	}
	defer stopBackoffTimer()

	// Set up for a jittered resync timer.  Not using our jitter package here since we want to be compatible
	// with the clock interface.  Large jitter on the first call to avoid thundering herd with lots of felixes
	// restarting.
	periodicRefreshTimer := u.clock.NewTimer(wait.Jitter(u.refreshInterval, 0.5))
	resetRefreshTimer := func() {
		if !periodicRefreshTimer.Stop() {
			<-periodicRefreshTimer.C()
		}
		periodicRefreshTimer.Reset(wait.Jitter(u.refreshInterval, 0.1))
	}

	var caps aws.SecondaryIfaceCapacities
	resyncNeeded := false
	seenFirstUpdate := false
	for {
		logrus.Debug("About to wait on channels...")
		select {
		case <-ctx.Done():
			logrus.Info("CapacityUpdater shutting down; context closed.")
			return
		case caps = <-u.updateC:
			if !seenFirstUpdate {
				logrus.WithField("capacity", caps).Info("Received first update of Kubernetes node capacity.")
				seenFirstUpdate = true
			}
			if u.lastCapacityUpdate != nil && u.lastCapacityUpdate.Equals(caps) {
				logrus.Debug("Capacity update made no changes")
			} else {
				resyncNeeded = true
			}
		case <-backoffC:
			// Important: nil out the timer so that stopBackoffTimer() won't try to stop it again (and deadlock).
			backoffC = nil
			backoffTimer = nil
			logrus.Warn("Retrying k8s resync after backoff.")
		case <-periodicRefreshTimer.C():
			logrus.WithField("seenFirstUpdate", seenFirstUpdate).Debug("Queueing periodic refresh.")
			periodicRefreshTimer.Reset(wait.Jitter(u.refreshInterval, 0.1))
			resyncNeeded = true
		}

		stopBackoffTimer()

		if seenFirstUpdate && resyncNeeded {
			logrus.Debug("Resync needed...")
			err := u.handleCapacityChange(caps)
			if err != nil {
				logrus.WithError(err).Error("Failed to resync with Kubernetes. Will retry after backoff.")
				backoffTimer = backoffMgr.Backoff()
				backoffC = backoffTimer.C()
			} else {
				resyncNeeded = false
			}
			resetRefreshTimer()
		}
	}
}

func (u *CapacityUpdater) handleCapacityChange(caps aws.SecondaryIfaceCapacities) error {
	ctx, cancel := u.newContext()
	defer cancel()

	nodeClient := u.k8sClient.Nodes()
	node, err := nodeClient.Get(ctx, u.nodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to look up our kubernetes node by name (%s): %w", u.nodeName, err)
	}

	res := node.Status.Capacity.Name(ResourceSecondaryIPv4, resource.DecimalSI)
	if res.Value() == int64(caps.MaxCalicoSecondaryIPs) {
		logrus.WithField("capacity", res.Value()).Debug("Kubernetes secondary IP capacity already correct")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"secondaryIPCap": caps.MaxCalicoSecondaryIPs,
		"nodeName":       u.nodeName,
	}).Info("Updating node capacity.")
	var capResource any
	if caps.MaxCalicoSecondaryIPs > 0 {
		capResource = fmt.Sprint(caps.MaxCalicoSecondaryIPs)
	}
	patch := map[string]any{
		"status": map[string]any{
			"capacity": map[string]any{
				ResourceSecondaryIPv4: capResource,
			},
		},
	}

	patchData, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("BUG: failed to marshall JSON patch: %w", err)
	}

	// Capacity updates must be done as a PATCH.  The API server doesn't support update/apply for those fields.
	_, err = nodeClient.PatchStatus(ctx, u.nodeName, patchData)
	if err != nil {
		return fmt.Errorf("failed to patch kubernetes Node resource: %w", err)
	}

	u.lastCapacityUpdate = &caps
	return nil
}

func (u *CapacityUpdater) newBackoffManager() wait.BackoffManager {
	const (
		initBackoff   = 1 * time.Second
		maxBackoff    = 1 * time.Minute
		resetDuration = 10 * time.Minute
		backoffFactor = 2.0
		jitter        = 0.1
	)
	//nolint:staticcheck // Ignore SA1019 deprecated
	backoffMgr := wait.NewExponentialBackoffManager(initBackoff, maxBackoff, resetDuration, backoffFactor, jitter, u.clock)
	return backoffMgr
}

func (u *CapacityUpdater) newContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), u.timeout)
}
