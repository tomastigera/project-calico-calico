// Copyright (c) 2018-2023 Tigera, Inc. All rights reserved.

package file

import (
	"bufio"
	"encoding/json"
	"path"

	"github.com/DeRuina/timberjack"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector/dnslog"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/l7log"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

const (
	FlowLogFilename     = "flows.log"
	DNSLogFilename      = "dns.log"
	L7LogFilename       = "l7.log"
	WAFEventLogFilename = "waf.log"
)

// FileReporter is a Reporter that writes logs to a local,
// auto-rotated log file. We write one JSON-encoded log per line.
type FileReporter struct {
	directory string
	fileName  string
	maxMB     int
	numFiles  int
	logger    *bufio.Writer
}

func NewReporter(directory, fileName string, maxMB, numFiles int) *FileReporter {
	return &FileReporter{directory: directory, fileName: fileName, maxMB: maxMB, numFiles: numFiles}
}

func (f *FileReporter) Start() error {
	if f.logger != nil {
		// Already initialized; no-op
		return nil
	}
	logger := &timberjack.Logger{
		Filename:    path.Join(f.directory, f.fileName),
		FileMode:    0o644,
		Compression: "zstd",
		MaxSize:     f.maxMB,
		MaxBackups:  f.numFiles,
	}
	f.logger = bufio.NewWriterSize(logger, 1<<16)
	return nil
}

func (f *FileReporter) Report(logSlice interface{}) (err error) {
	enc := json.NewEncoder(f.logger)

	defer func() {
		flushErr := f.logger.Flush()
		if flushErr != nil {
			log.WithError(flushErr).Error("Failed to flush log file.")
			if err == nil {
				err = flushErr
			}
		}
	}()

	switch logs := logSlice.(type) {
	case []*flowlog.FlowLog:
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("num", len(logs)).Debug("Dispatching flow logs to file")
		}
		// Optimisation: we re-use the same output object for each log to avoid
		// a (large) allocation per log.
		var output flowlog.JSONOutput
		for _, l := range logs {
			output.FillFrom(l)
			err := enc.Encode(&output)
			if err != nil {
				log.WithError(err).
					WithField("flowLog", output).
					Error("Unable to serialize flow log to file.")
				return err
			}
		}
	case []*v1.DNSLog:
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("num", len(logs)).Debug("Dispatching DNS logs to file")
		}
		// Optimisation: put this outside the loop to avoid an allocation per
		// excess log.
		var excessLog dnslog.DNSExcessLog
		for _, l := range logs {
			var err error
			if l.Type == v1.DNSLogTypeUnlogged {
				excessLog = dnslog.DNSExcessLog{
					StartTime: l.StartTime,
					EndTime:   l.EndTime,
					Type:      l.Type,
					Count:     l.Count,
				}
				err = enc.Encode(&excessLog)
			} else {
				err = enc.Encode(l)
			}
			if err != nil {
				log.WithError(err).
					WithField("dnsLog", l).
					Error("Unable to serialize DNS log to JSON")
				return err
			}
		}
	case []*l7log.L7Log:
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("num", len(logs)).Debug("Dispatching L7 logs to file")
		}
		for _, l := range logs {
			err := enc.Encode(l)
			if err != nil {
				log.WithError(err).
					WithField("l7Log", l).
					Error("Unable to serialize L7 log to JSON")
				return err
			}
		}
	case []*v1.WAFLog:
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithField("num", len(logs)).Debug("Dispatching WAFEvent logs to file")
		}
		for _, l := range logs {
			err := enc.Encode(l)
			if err != nil {
				log.WithError(err).
					WithField("wafEventLog", l).
					Error("Unable to serialize WAFEvent log to JSON")
				return err
			}
		}
	default:
		log.Panic("Unexpected kind of log in file dispatcher")
	}
	return nil
}
