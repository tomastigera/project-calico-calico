// Copyright 2020 Tigera Inc. All rights reserved.

package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/avast/retry-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/runloop"
	"github.com/projectcalico/calico/intrusion-detection-controller/pkg/storage"
	lsv1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	lmaAPI "github.com/projectcalico/calico/lma/pkg/api"
	lmav1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
)

const (
	// defaultPollingTimeRange is the default time interval to check for more data to forward.
	defaultPollingTimeRange = 300 * time.Second

	// defaultPollingInterval is the default time interval to check for more data to forward.
	defaultPollingInterval = 300 * time.Second

	// defaultNumForwardingAttempts is the default number of retry forwarding attempts to perform
	// (includes both querying for events and writing them to file).
	defaultNumForwardingAttempts = 10

	// defaultExportLogsDirectory is the default directory path for where logs will be exported.
	defaultExportLogsDirectory = "/var/log/calico/ids"

	// defaultExportLogsMaxFileSizeMB is the default size limit to maintain during log rotation
	// for each log file containing exported data.
	defaultExportLogsMaxFileSizeMB = 50

	// defaultExportLogsMaxFiles is the default max limit for number of files to keep during log
	// rotation for exported data.
	defaultExportLogsMaxFiles = 3

	// logDispatcherFilename specifies the filename to use for writing events to file
	// Note: If we move to 2 or more concurrent workers running, each one must write to a separate file
	logDispatcherFilename = "events.log"
)

// settings is a package level configuration object for the log forwarder.
var settings = forwarderSettings{}

// forwarderSettings contains configuration for how the log forwarder behaves.
type forwarderSettings struct {
	// pollingTimeRange specifies how large (in sec) the time window should be when polling for events.
	pollingTimeRange time.Duration

	// pollingInterval specifies how often (in sec) to check for more data to forward.
	pollingInterval time.Duration

	// numForwardingAttempts specifies how many retry attempts we should perform (for both querying
	// for events and writing events to file).
	numForwardingAttempts uint

	// exportLogsDirectory is the path location of the directory housing exported data.
	exportLogsDirectory string

	// exportLogsMaxFileSizeMB is the max size per file to keep during log rotation for exported data.
	exportLogsMaxFileSizeMB int

	// exportLogsMaxFiles is the max number of files to keep during log rotation for exported data.
	exportLogsMaxFiles int
}

func init() {
	setPollingTimeRange()
	setPollingInterval()
	setNumForwardingAttempts()
	setExportLogsDirectory()
	setExportLogsMaxFileSizeMB()
	setExportLogsMaxFiles()
}

// setPollingTimeRange sets the polling time range based on ENV variable or the default value.
func setPollingTimeRange() {
	settings.pollingTimeRange = defaultPollingTimeRange

	intervalStr := os.Getenv("IDS_FORWARDER_POLLING_TIMERANGE_SECS")
	if intervalStr != "" {
		if intervalInt, err := strconv.Atoi(intervalStr); err != nil {
			log.Panicf("Failed to parse value for polling time range for forwarder %s", intervalStr)
		} else {
			settings.pollingTimeRange = time.Duration(intervalInt) * time.Second
		}
	}
}

// setPollingInterval sets the polling interval based on ENV variable or the default value.
func setPollingInterval() {
	settings.pollingInterval = defaultPollingInterval

	intervalStr := os.Getenv("IDS_FORWARDER_POLLING_INTERVAL_SECS")
	if intervalStr != "" {
		if intervalInt, err := strconv.Atoi(intervalStr); err != nil {
			log.Panicf("Failed to parse value for polling interval for forwarder %s", intervalStr)
		} else {
			settings.pollingInterval = time.Duration(intervalInt) * time.Second
		}
	}
}

// setNumForwardingAttempts sets the polling interval based on ENV variable or the default value.
func setNumForwardingAttempts() {
	settings.numForwardingAttempts = defaultNumForwardingAttempts

	intervalStr := os.Getenv("IDS_FORWARDER_POLLING_NUM_RETRY")
	if intervalStr != "" {
		if intervalInt, err := strconv.ParseUint(intervalStr, 10, 0); err != nil {
			log.Panicf("Failed to parse value for number of polling retries for forwarder %s", intervalStr)
		} else {
			settings.numForwardingAttempts = uint(intervalInt)
		}
	}
}

// setExportLogsDirectory sets the directory where log data will be exported based on ENV variable
// or the default value.
func setExportLogsDirectory() {
	settings.exportLogsDirectory = defaultExportLogsDirectory

	dirStr := os.Getenv("IDS_FORWARDER_LOG_DIR")
	if dirStr != "" {
		settings.exportLogsDirectory = dirStr
	}
}

// setExportLogsMaxFileSizeMB sets the limit for log file size to keep in log rotation for the exported data.
func setExportLogsMaxFileSizeMB() {
	settings.exportLogsMaxFileSizeMB = defaultExportLogsMaxFileSizeMB

	maxFileSizeStr := os.Getenv("IDS_FORWARDER_MAX_FILESIZE_MB")
	if maxFileSizeStr != "" {
		if maxFileSizeInt, err := strconv.Atoi(maxFileSizeStr); err != nil {
			log.Panicf("Failed to parse value for max log file size for forwarder %s", maxFileSizeStr)
		} else {
			settings.exportLogsMaxFileSizeMB = maxFileSizeInt
		}
	}
}

// setExportLogsMaxFiles sets the limit for number of log files to keep in log rotation for the exported data.
func setExportLogsMaxFiles() {
	settings.exportLogsMaxFiles = defaultExportLogsMaxFiles

	maxNumFilesStr := os.Getenv("IDS_FORWARDER_MAX_NUMFILES")
	if maxNumFilesStr != "" {
		if maxNumFilesInt, err := strconv.Atoi(maxNumFilesStr); err != nil {
			log.Panicf("Failed to parse value for max number of log files for forwarder %s", maxNumFilesStr)
		} else {
			settings.exportLogsMaxFiles = maxNumFilesInt
		}
	}
}

// EventForwarder attempts to transport logs (events) from a source data store (Elasticsearch) to destination data store
// by way of log dispatcher (writing to file).
type EventForwarder interface {
	// Run executes forwarding action.
	Run(ctx context.Context)
	// Clean up execution context.
	Close()
}

// eventForwarder queries the source data store for logs and then dispatches them for forwarding to a final
// destination.
type eventForwarder struct {
	// Use a decorated logger so we have some extra metadata.
	logger *log.Entry

	once   sync.Once
	cancel context.CancelFunc
	ctx    context.Context

	// Provides access to retrieve events from the source data store
	events storage.Events

	// Writes data obtained by the forwarder to logs that will be taken to its final destination
	dispatcher LogDispatcher

	// Maintain state on forwarding process over time.
	config *storage.ForwarderConfig
}

// NewEventForwarder sets up a new log forwarder instance and returns it.
// Note: Log forwarder does not currently support concurrency of multiple instances.
func NewEventForwarder(events storage.Events) EventForwarder {
	log.WithFields(log.Fields{
		"exportLogsDirectory":     settings.exportLogsDirectory,
		"exportLogsMaxFileSizeMB": settings.exportLogsMaxFileSizeMB,
		"exportLogsMaxFiles":      settings.exportLogsMaxFiles,
		"pollingInterval":         settings.pollingInterval,
		"pollingTimeRange":        settings.pollingTimeRange,
		"numForwardingAttempts":   settings.numForwardingAttempts,
	}).Info("Creating new event forwarder")

	dispatcher := NewFileDispatcher(
		settings.exportLogsDirectory,
		logDispatcherFilename,
		settings.exportLogsMaxFileSizeMB,
		settings.exportLogsMaxFiles,
	)

	return &eventForwarder{
		logger: log.WithFields(log.Fields{
			"context": "eventforwarder",
			"logfile": fmt.Sprintf("%s/%s", settings.exportLogsDirectory, logDispatcherFilename),
		}),
		events:     events,
		dispatcher: dispatcher,
	}
}

// QueryError represents an error encountered while querying for events from the data store.
type QueryError struct {
	Err error
}

// Error returns the string representation of the given QueryError
func (e QueryError) Error() string {
	return fmt.Sprintf("Failed to retrieve events: %s", e.Err.Error())
}

// NewQueryError creates a new QueryError.
func NewQueryError(err error) QueryError {
	return QueryError{
		Err: err,
	}
}

// Run performs the log forwarding which includes querying for events from the data store and dispatching those events.
func (f *eventForwarder) Run(ctx context.Context) {
	l := f.logger.WithFields(log.Fields{"func": "Run"})

	f.once.Do(func() {
		f.ctx, f.cancel = context.WithCancel(ctx)
		l.Info("Starting alert forwarder ...")

		err := f.dispatcher.Initialize()
		if err != nil {
			log.Errorf("Could not initialize dispatcher (dispatcher) %s", err)
			return
		}

		// Use in-memory field to record progress (time from the last success event to be forwarder), in case save to datastore
		// fails.
		var lastSuccessfulEndTime *time.Time
		// Iterate forever, waiting for settings.pollingInterval seconds between iterations. On each iteration retrieve events
		// and export to logs using dispatcher.
		go runloop.RunLoop( // nolint: errcheck
			f.ctx,
			func() {
				var start, end time.Time
				var err error

				// ---------------------------------------------------------------------------------------------------
				// 1. Figure out the start time to use for retrieving the next batch of events to forward. We want to
				//    continue forwarding events by starting where the last successful run finished.
				// ---------------------------------------------------------------------------------------------------

				// If we have a successufl savepoint already, start from there
				if lastSuccessfulEndTime != nil {
					// Start the next run from the very next time tick (second), because the time range query includes
					// both start and end times.
					start = (*lastSuccessfulEndTime).Add(time.Second)
					l.Debugf("Continuing forwarder from time [%v]", start)
				} else {
					// Otherwise, let's try to recover a savepoint from the config in the datastore ...
					// If we have a savepoint for the last successful run, then use that to determine the time
					// range for the new run.
					f.config, err = f.events.GetForwarderConfig(f.ctx)
					if err == nil && f.config != nil {
						l.WithFields(log.Fields{
							"forwarderConfig": f.config,
						}).Debugf("Found forwarder config with events.GetForwarderConfig(...)")
						// Start the next run from the very next time tick (second), because the time range query includes
						// both start and end times.
						start = (*f.config.LastSuccessfulRunEndTime).Add(time.Second)
						l.Debugf("Continuing forwarder from time [%v]", start)
					} else {
						// In the case we don't have a savedpoint for where we left off on the last successful run,
						// we need to pick a starting point. In this special case, we will pick the time range that
						// ends at the current time (time.Now()) and starts -X seconds ago (where X = pollingTimeRange
						// from our setttings).
						start = time.Now().Add(-settings.pollingTimeRange)
						// Start with a blank slate for config
						f.config = &storage.ForwarderConfig{}
						l.Debugf("No config detected for forwarder, start from time [%v]", start)
					}
				}

				// ---------------------------------------------------------------------------------------------------
				// 2. Figure out the end of the query time range. Our time range will go from [start] to
				//    [start + settings.pollingTimeRange - 1]. We deduct a time.Second from the end to avoid time
				//    creep (since each period we add time.Second to the start time).
				// ---------------------------------------------------------------------------------------------------
				end = start.Add(settings.pollingTimeRange).Add(-time.Second)

				// Edge case: Ensure we don't start querying in a time window that hasn't happened yet (i.e. the end of
				// the time window should not be in the future). If it does, then bail on this run without doing anything
				// further. We will try again on the next run.
				if end.After(time.Now()) {
					l.WithFields(log.Fields{
						"start": start,
						"end":   end,
					}).Infof("Forwarder query time range has not occurred yet, cancelling run (wait until next interval).")
					return
				}

				// ---------------------------------------------------------------------------------------------------
				// 3. Attempt to retrieve next batch of events (using the computed start and end times).
				// ---------------------------------------------------------------------------------------------------
				// Create the list pager for security events
				params := lsv1.EventParams{}
				params.SetTimeRange(&lmav1.TimeRange{From: start, To: end})
				pager := client.NewListPager[lsv1.Event](&params)
				err = f.retrieveAndForward(pager, start, end, settings.numForwardingAttempts, time.Second)

				// ---------------------------------------------------------------------------------------------------
				// 4. If current run was successful, then persist the new last successful end time
				// ---------------------------------------------------------------------------------------------------
				if err == nil {
					lastSuccessfulEndTime = &end
					f.config.LastSuccessfulRunEndTime = &end

					l.Infof("Updated forwarder config after successful run [%+v]", f.config)

					// Attempt to back up forwarding progress (in case the forwarder crashes and we need to recover)
					err = retry.Do(
						func() error {
							return f.events.PutForwarderConfig(f.ctx, f.config)
						},
						retry.Attempts(settings.numForwardingAttempts),
						retry.Delay(500*time.Millisecond),
						retry.OnRetry(
							func(n uint, err error) {
								l.WithError(err).WithFields(log.Fields{
									"forwarderConfig": f.config,
								}).Infof("Retrying forwarder events.PutForwarderConfig(...)")
							},
						),
					)
					// If we were unable to persist the state after retries, we will continune onwards (since we have state
					// in memory). So long as we can get to the next run without crashing we can try to save again.
					if err != nil {
						l.Info("Failed to save forwarder config to datastore, even after retries")
					} else {
						l.Info("Successfully saved forwarder config to config map")
					}
				}
			},
			settings.pollingInterval,
		)
	})
}

// Close ensures we handle cleaning up the forwarder context.
func (f *eventForwarder) Close() {
	if f.cancel != nil {
		f.cancel()
	}
}

// retrieveAndForward handles the actual querying for events and forwarding to file.
func (f *eventForwarder) retrieveAndForward(pager client.ListPager[lsv1.Event], start, end time.Time, numAttempts uint, delay time.Duration) error {
	l := f.logger.WithFields(log.Fields{"func": "retrieveAndForward"})

	// ---------------------------------------------------------------------------------------------------
	// 1. Attempt to query for security events
	// ---------------------------------------------------------------------------------------------------
	doneCh := make(chan error, 2)
	defer close(doneCh)
	resultsCh := make(chan *lmaAPI.EventResult, 1000)
	numEvents := 0
	go func() {
		defer close(resultsCh)
		err := retry.Do(
			func() error {
				for e := range f.events.GetSecurityEvents(f.ctx, pager) {
					if e.Err != nil {
						return e.Err
					}
					resultsCh <- e
					numEvents++
				}
				return nil
			},
			retry.Attempts(numAttempts),
			retry.Delay(delay),
			retry.OnRetry(
				func(n uint, err error) {
					l.WithError(err).WithFields(log.Fields{
						"start": start,
						"end":   end,
					}).Infof("Retrying forwarder events.GetSecurityEvents(...)")
				},
			),
		)
		if err != nil {
			l.WithError(err).WithFields(log.Fields{
				"start": start,
				"end":   end,
			}).Error("Failed to get security event after retry ", numAttempts)
			doneCh <- NewQueryError(err)
		}
		// We successfully retrieved events (if any) for the given time range
		if numEvents > 0 {
			l.WithFields(log.Fields{"start": start, "end": end}).Debugf("Successfully retrieved %d events", numEvents)
		} else {
			l.WithFields(log.Fields{"start": start, "end": end}).Debugf("Retrieved no events for this time range")
		}

		doneCh <- nil
	}()

	// ---------------------------------------------------------------------------------------------------
	// 2. Attempt to write all retrieved events to file
	// ---------------------------------------------------------------------------------------------------
	go func() {
		for e := range resultsCh {
			err := retry.Do(
				func() error {
					sec, dec := math.Modf(float64(e.Time))
					epoch := time.Unix(int64(sec), int64(dec*(1e9)))

					b, err := json.Marshal(e.EventsData)
					if err != nil {
						return err
					}
					if err = f.dispatcher.Dispatch(b); err != nil {
						return err
					}
					f.config.LastSuccessfulEventTime = &epoch
					f.config.LastSuccessfulEventID = &e.ID
					return nil
				},
				retry.Attempts(numAttempts),
				retry.Delay(500*time.Millisecond),
				retry.OnRetry(
					func(n uint, err error) {
						l.WithError(err).WithFields(log.Fields{
							"eventId": e.ID,
						}).Infof("Retrying forwarder dispatcher.Dispatch(rawEvent) on event ")
					},
				),
			)
			if err != nil {
				l.Logger.WithError(err).Errorf("Forwader failed dispatcher.Dispatch(rawEvent) after %d attempts", numAttempts)
			}
		}
		doneCh <- nil
	}()

	l.Debugf("Waiting for retrieval and forward to finish")
	for range 2 {
		<-doneCh
	}
	return nil
}
