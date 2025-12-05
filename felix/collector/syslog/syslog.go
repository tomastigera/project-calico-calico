//go:build !windows

// Copyright (c) 2017-2023 Tigera, Inc. All rights reserved.

package syslog

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"net"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
)

const logQueueSize = 100
const DebugDisableLogDropping = false

type Syslog struct {
	slog *log.Logger
}

// Felix Metrics
var (
	counterDroppedLogs = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_reporter_logs_dropped",
		Help: "Number of logs dropped because the output stream was blocked in the Syslog reporter.",
	})
	counterLogErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_reporter_log_errors",
		Help: "Number of errors encountered while logging in the Syslog reporter.",
	})
)

func init() {
	prometheus.MustRegister(
		counterDroppedLogs,
		counterLogErrors,
	)
}

// New configures and returns a SyslogReporter.
// Network and Address can be used to configure remote syslogging. Leaving both
// of these values empty implies using local syslog such as /dev/log.
func New(network, address string) *Syslog {
	slog := log.New()
	priority := syslog.LOG_USER | syslog.LOG_INFO
	tag := "calico-felix"
	w, err := syslog.Dial(network, address, priority, tag)
	if err != nil {
		log.Warnf("Syslog Reporting is disabled - Syslog Hook could not be configured %v", err)
		return nil
	}
	syslogDest := logutils.NewSyslogDestination(
		log.InfoLevel,
		w,
		make(chan logutils.QueuedLog, logQueueSize),
		DebugDisableLogDropping,
		counterLogErrors,
	)

	hook := logutils.NewBackgroundHook([]log.Level{log.InfoLevel}, log.InfoLevel, []*logutils.Destination{syslogDest}, counterDroppedLogs)
	hook.Start()
	slog.Hooks.Add(hook)
	slog.Formatter = &DataOnlyJSONFormatter{}
	return &Syslog{
		slog: slog,
	}
}

func (s *Syslog) Start() error {
	log.Info("Starting Syslog Reporter")
	return nil
}

func (s *Syslog) Report(u any) error {
	mu, ok := u.(metric.Update)
	if !ok {
		return fmt.Errorf("invalid metric update")
	}
	if (mu.InMetric.DeltaPackets == 0 && mu.InMetric.DeltaBytes == 0) &&
		(mu.OutMetric.DeltaPackets == 0 && mu.OutMetric.DeltaBytes == 0) {
		// No update. It isn't an error.
		return nil
	}
	lastRuleID := mu.GetLastRuleID()
	if lastRuleID == nil {
		log.WithField("metric update", mu).Error("no rule id present")
		return errors.New("invalid metric update")
	}
	f := log.Fields{
		"proto":      strconv.Itoa(mu.Tuple.Proto),
		"srcIP":      net.IP(mu.Tuple.Src[:16]).String(),
		"srcPort":    strconv.Itoa(mu.Tuple.L4Src),
		"dstIP":      net.IP(mu.Tuple.Dst[:16]).String(),
		"dstPort":    strconv.Itoa(mu.Tuple.L4Dst),
		"tier":       lastRuleID.TierString(),
		"policy":     lastRuleID.NameString(),
		"rule":       lastRuleID.IndexStr,
		"action":     lastRuleID.ActionString(),
		"ruleDir":    lastRuleID.DirectionString(),
		"trafficDir": types.RuleDirToTrafficDir(lastRuleID.Direction).String(),
		"inPackets":  mu.InMetric.DeltaPackets,
		"inBytes":    mu.InMetric.DeltaBytes,
		"outPackets": mu.OutMetric.DeltaPackets,
		"outBytes":   mu.OutMetric.DeltaBytes,
		"updateType": mu.UpdateType,
	}
	s.slog.WithFields(f).Info("")
	return nil
}

// Logrus Formatter that strips the log entry of messages, time and log level and
// outputs *only* entry.Data.
type DataOnlyJSONFormatter struct{}

func (f *DataOnlyJSONFormatter) Format(entry *log.Entry) ([]byte, error) {
	serialized, err := json.Marshal(entry.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data to JSON %v", err)
	}
	return append(serialized, '\n'), nil
}
