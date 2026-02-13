package monitor

import (
	"context"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"

	lapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/jitter"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	lclient "github.com/projectcalico/calico/licensing/client"
)

const (
	defaultPollInterval = 10 * time.Minute
	fastPollInterval    = 2 * time.Second
)

// LicenseMonitor is an interface which enables monitoring of license and feature enablement status.
type LicenseMonitor interface {
	GetFeatureStatus(string) bool
	GetLicenseStatus() lclient.LicenseStatus
	MonitorForever(context.Context) error
	RefreshLicense(context.Context) error
	SetPollInterval(duration time.Duration)
	SetFeaturesChangedCallback(func())
	SetStatusChangedCallback(f func(newLicenseStatus lclient.LicenseStatus))
}

type bapiClient interface {
	Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error)
	Watch(ctx context.Context, list model.ListInterface, options lapi.WatchOptions) (lapi.WatchInterface, error)
}

// licenseMonitor uses a libcalico-go (backend) client to monitor the status of the active license.
// It provides a thread-safe API for querying the current state of a feature.  Changes to the
// license or its validity are reflected by the API.
type licenseMonitor struct {
	PollInterval           time.Duration
	OnFeaturesChanged      func()
	OnLicenseStatusChanged func(newLicenseStatus lclient.LicenseStatus)

	datastoreClient bapiClient

	activeLicenseLock sync.Mutex
	activeRawLicense  *api.LicenseKey
	activeLicense     *lclient.LicenseClaims

	licenseTransitionTimer    timer
	licenseTransitionC        <-chan time.Time
	lastNotifiedLicenseStatus lclient.LicenseStatus

	// Shims for mocking...
	decodeLicense     func(lic api.LicenseKey) (lclient.LicenseClaims, error)
	now               func() time.Time
	newTimer          func(duration time.Duration) timer
	newJitteredTicker func(minDuration time.Duration, maxJitter time.Duration) *jitter.Ticker
}

type timer interface {
	Chan() <-chan time.Time
	Stop() bool
}
type timerWrapper time.Timer

func (w *timerWrapper) Stop() bool {
	return (*time.Timer)(w).Stop()
}

func (w *timerWrapper) Chan() <-chan time.Time {
	return (*time.Timer)(w).C
}

func New(client bapiClient) LicenseMonitor {
	return &licenseMonitor{
		PollInterval:    defaultPollInterval,
		datastoreClient: client,

		decodeLicense:     lclient.Decode,
		now:               time.Now,
		newTimer:          func(d time.Duration) timer { return (*timerWrapper)(time.NewTimer(d)) },
		newJitteredTicker: jitter.NewTicker,
	}
}

func (l *licenseMonitor) GetFeatureStatus(feature string) bool {
	l.activeLicenseLock.Lock()
	defer l.activeLicenseLock.Unlock()
	return l.activeLicense.ValidateFeature(feature)
}

func (l *licenseMonitor) GetLicenseStatus() lclient.LicenseStatus {
	l.activeLicenseLock.Lock()
	defer l.activeLicenseLock.Unlock()
	// Use the ValidateAtTime variant so that we use mocked time in the UTs.
	return l.activeLicense.ValidateAtTime(l.now())
}

func (l *licenseMonitor) SetPollInterval(d time.Duration) {
	l.PollInterval = d
}

// SetFeaturesChangedCallback sets a callback that will be called whenever the set of features allowed by the license
// changes.  Should be called before the monitoring loop is started.
func (l *licenseMonitor) SetFeaturesChangedCallback(f func()) {
	l.OnFeaturesChanged = f
}

// SetLicenseStatusChangedCallback sets a callback that will be called whenever the license transitions to a new
// state.  Should be called before the monitoring loop is started.
func (l *licenseMonitor) SetStatusChangedCallback(f func(newLicenseStatus lclient.LicenseStatus)) {
	l.OnLicenseStatusChanged = f
}

func (l *licenseMonitor) MonitorForever(ctx context.Context) error {

	licenseWatcher := l.createLicenseWatcher(ctx)

	// TODO: use jitter package in libcalico-go once it has been ported to libcalico-go-private.
	// Define a fast and slow ticker. Use the slow ticker when we are also watching.  Use the fast ticker when our
	// watch channel is not connected.
	slowRefreshTicker := l.newJitteredTicker(l.PollInterval, l.PollInterval/10)
	fastRefreshTicker := l.newJitteredTicker(fastPollInterval, fastPollInterval/10)
	defer slowRefreshTicker.Stop()
	defer fastRefreshTicker.Stop()

loop:
	for ctx.Err() == nil {
		// We may have already loaded the license (if someone called RefreshLicense() before calling this method).
		// Trigger any needed notification now and make sure the timer is scheduled.  We also hit this each time around
		// the loop after any license refresh and transition so this call covers all the bases.
		l.maybeNotifyLicenseStatusAndReschedule()

		var watchChan <-chan lapi.WatchEvent
		var refreshTicker *jitter.Ticker
		if licenseWatcher != nil {
			// We have a watcher, use the watcher results channel and the slow refresh.
			log.Debug("Active watcher, enabling slow poll.")
			watchChan = licenseWatcher.ResultChan()
			refreshTicker = slowRefreshTicker
		} else {
			// We don't have a watcher, use the fast refesh so that we attempt to recreate the watcher. The watcher
			// channel will be nil (which blocks forever on the select).
			log.Debug("No active watcher, enabling fast poll.")
			refreshTicker = fastRefreshTicker
		}

		select {
		case <-ctx.Done():
			log.Info("Context finished.")
			break loop
		case <-refreshTicker.C:
			_ = l.RefreshLicense(ctx)

			// For as long as this loop runs, we want to make sure we are watching incoming events.
			if licenseWatcher == nil || licenseWatcher.HasTerminated() {
				licenseWatcher = l.createLicenseWatcher(ctx)
			}

		case <-l.licenseTransitionC:
			log.Debug("License transition timer popped, checking license status...")
		case licUpdate, ok := <-watchChan:
			if !ok {
				log.Debug("License watch channel closed. Recreating the watcher.")
				// nil out the licenseWatcher, which will trigger a switch to the fast poll.  Since hitting this
				// "case" means that we must be using hte slow poller, the fast poller should pop straight away
				// unless we're tight looping.  If we're tight looping, the fast poller will throttle reconnection
				// attempts. No need to call Stop() here, closed channel implies the watcher has stopped.
				licenseWatcher = nil
				continue
			}
			if licUpdate.Error != nil {
				log.WithError(licUpdate.Error).Warn("License watch returned an error. Restarting the watch.")
				// As above, rely on the fast poll to restart the watch in a throttled way.  We do need to stop the
				// watcher after an error.
				licenseWatcher.Stop()
				licenseWatcher = nil
				continue
			}
			if licUpdate.New != nil {
				log.Debug("Received license update event.") // Not logging out the license here since it's sensitive.
				_ = l.refreshLicense(licUpdate.New)
			}
		}
	}
	return ctx.Err()
}

// createLicenseWatcher creates a watcher based on the libcalico library that creates a channel event on every license update.
func (l *licenseMonitor) createLicenseWatcher(ctx context.Context) lapi.WatchInterface {
	licenseWatcher, err := l.datastoreClient.Watch(ctx, model.ResourceListOptions{
		Kind:      api.KindLicenseKey,
		Name:      "default",
		Namespace: ""}, lapi.WatchOptions{})
	if err != nil {
		log.Errorf("An error occurred while creating a license watcher: %v", err)
		return nil
	}
	return licenseWatcher
}

// maybeNotifyLicenseStatusAndReschedule notifies the callback of any change in license state and reschedules the
// timer if needed.
func (l *licenseMonitor) maybeNotifyLicenseStatusAndReschedule() {
	// Clean up any old timer so we can reschedule it.
	l.cleanUpTransitionTimer()
	// Start the timer before we notify to avoid a missed update race.
	l.maybeStartTransitionTimer()
	l.maybeNotifyLicenseStatus()
}

// maybeNotifyLicenseStatus notifies the license state change callback if the license state has changed.
func (l *licenseMonitor) maybeNotifyLicenseStatus() {
	if l.OnLicenseStatusChanged == nil {
		log.Debug("Skipping license state notification, no callback to call")
		return
	}
	newStatus := l.GetLicenseStatus()
	if newStatus == l.lastNotifiedLicenseStatus {
		log.WithField("state", newStatus).Debug(
			"Skipping license state notification, no change in state")
		return
	}
	l.OnLicenseStatusChanged(newStatus)
	l.lastNotifiedLicenseStatus = newStatus
}

// cleanUpTransitionTimer stops and cleans up the transition timer.  Idempotent.
func (l *licenseMonitor) cleanUpTransitionTimer() {
	if l.licenseTransitionTimer == nil {
		return
	}
	l.licenseTransitionTimer.Stop()
	l.licenseTransitionTimer = nil
	l.licenseTransitionC = nil
}

// maybeStartTransitionTimer schedules the transition timer if the active license is in a state that will naturally
// transition.  i.e. if it's in the valid state or grace period.
func (l *licenseMonitor) maybeStartTransitionTimer() {
	licenseStatus := l.GetLicenseStatus()

	l.activeLicenseLock.Lock()
	defer l.activeLicenseLock.Unlock()

	var nextNotifyTime time.Time
	switch licenseStatus {
	case lclient.Valid:
		nextNotifyTime = l.activeLicense.Expiry.Time()
		log.WithField("atTime", nextNotifyTime).Debug("Next license transition is to grace period")
	case lclient.InGracePeriod:
		graceDuration := time.Duration(l.activeLicense.GracePeriod) * 24 * time.Hour
		nextNotifyTime = l.activeLicense.Expiry.Time().Add(graceDuration)
		log.WithField("atTime", nextNotifyTime).Debug("Next license transition is to expired")
	default:
		log.WithField("state", licenseStatus).Debug("License state doesn't require transition timer")
		return
	}

	timeToNextNotify := nextNotifyTime.Sub(l.now())
	log.WithField("timeToNextNotification", timeToNextNotify).Debug(
		"Calculated time to next license transition")
	if timeToNextNotify < 1*time.Second {
		// Step change in the system clock?  Just schedule a new check almost immediately.
		log.Debug("Calculated very short/negative License transition interval; limiting rate to 1/s")
		timeToNextNotify = 1 * time.Second
	}
	l.licenseTransitionTimer = l.newTimer(timeToNextNotify)
	l.licenseTransitionC = l.licenseTransitionTimer.Chan()
}

// RefreshLicense polls the datastore for a license and updates the active license field.  Typically called by
// the polling loop MonitorForever but may be called by client code in order to explicitly refresh the license.
func (l *licenseMonitor) refreshLicense(lic *model.KVPair) error {
	// invoke callback after the activeLicense is in place and the lock on activeLicense is done.
	var invokeCb bool
	defer func() {
		if invokeCb {
			if l.OnFeaturesChanged != nil {
				l.OnFeaturesChanged()
			}
		}
	}()

	l.activeLicenseLock.Lock()
	defer l.activeLicenseLock.Unlock()

	var ttl time.Duration
	oldFeatures := set.New[string]()
	if l.activeLicense != nil {
		ttl = l.activeLicense.Expiry.Time().Sub(l.now())
		oldFeatures = set.FromArray(l.activeLicense.Features)
		log.Debug("Existing license will expire after ", ttl)
	}

	license := lic.Value.(*api.LicenseKey)
	log.Debug("License resource found")

	if l.activeRawLicense != nil && reflect.DeepEqual(l.activeRawLicense.Spec, license.Spec) {
		log.Debug("Raw license key data hasn't changed, skipping parse")
		return nil
	}

	newActiveLicense, err := l.decodeLicense(*license)
	if err != nil {
		if ttl > 0 {
			log.WithError(err).Error("Failed to decode license key; please contact support; "+
				"already loaded license will expire after ", ttl, " or if component is restarted.")
		} else {
			log.WithError(err).Error("Failed to decode license key; please contact support.")
		}
		return err
	}

	newFeatures := set.FromArray(newActiveLicense.Features)
	log.WithFields(log.Fields{
		"oldFeatures": oldFeatures,
		"newFeatures": newFeatures,
	}).Debug("License features")
	if !reflect.DeepEqual(oldFeatures, newFeatures) {
		log.Info("Allowed product features have changed.")
		invokeCb = true
	}

	l.activeRawLicense = license
	l.activeLicense = &newActiveLicense
	return nil
}

// RefreshLicense polls the datastore for a license and updates the active license field.  Typically called by
// the polling loop MonitorForever but may be called by client code in order to explicitly refresh the license.
func (l *licenseMonitor) RefreshLicense(ctx context.Context) error {
	log.Debug("Refreshing license from datastore")
	lic, err := l.datastoreClient.Get(ctx, model.ResourceKey{
		Kind:      api.KindLicenseKey,
		Name:      "default",
		Namespace: "",
	}, "")

	l.activeLicenseLock.Lock()
	var ttl time.Duration
	active := l.activeLicense
	if active != nil {
		ttl = active.Expiry.Time().Sub(l.now())
	}
	l.activeLicenseLock.Unlock()
	if err != nil {
		switch err.(type) {
		case cerrors.ErrorResourceDoesNotExist:
			if ttl > 0 {
				log.WithError(err).Error("No product license found in the datastore; please contact support; "+
					"already loaded license will expire after ", ttl, " or if component is restarted.")
			} else {
				log.WithError(err).Error("No product license found in the datastore; please install a license " +
					"to enable commercial features.")
			}
			return err
		default:
			if ttl > 0 {
				log.WithError(err).Error("Failed to load product license from datastore; "+
					"already loaded license will expire after ", ttl, " or if component is restarted.")
			} else {
				log.WithError(err).Error("Failed to load product license from datastore.")
			}
			return err
		}
	}
	return l.refreshLicense(lic)
}
