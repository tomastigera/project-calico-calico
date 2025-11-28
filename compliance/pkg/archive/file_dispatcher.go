// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package archive

import (
	"encoding/json"
	"io"
	"path"

	"github.com/DeRuina/timberjack"
	log "github.com/sirupsen/logrus"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

// LogDispatcher is the external interface for dispatchers. For now there is only the file dispatcher.
type LogDispatcher interface {
	Initialize() error
	Dispatch(logSlice interface{}) error
}

// fileDispatcher is a LogDispatcher that writes logs to a local,
// auto-rotated log file.  We write one JSON-encoded log per line.
type fileDispatcher struct {
	directory string
	fileName  string
	maxMB     int
	numFiles  int
	logger    io.WriteCloser
}

// NewFileDispatcher returns a new LogDispatcher of type file dispatcher
func NewFileDispatcher(directory, fileName string, maxMB, numFiles int) LogDispatcher {
	return &fileDispatcher{
		directory: directory,
		fileName:  fileName,
		maxMB:     maxMB,
		numFiles:  numFiles,
	}
}

// Initialize the given file dispatcher
func (d *fileDispatcher) Initialize() error {
	if d.logger != nil {
		// Already initialized; no-op
		return nil
	}
	d.logger = &timberjack.Logger{
		Filename:   path.Join(d.directory, d.fileName),
		FileMode:   0o644,
		MaxSize:    d.maxMB,
		MaxBackups: d.numFiles,
	}
	return nil
}

// Dispatch serializes and writes the given data. It must be a valid type of data (currently only
// ReportData is allowed).
func (d *fileDispatcher) Dispatch(data interface{}) error {
	writeLog := func(b []byte) error {
		b = append(b, '\n')
		// It is an error to call Dispatch before Initialize, so it's safe to
		// assume d.logger is non-nil.
		_, err := d.logger.Write(b)
		if err != nil {
			log.WithError(err).Error("unable to write archive data to file")
			return err
		}
		return nil
	}
	switch d := data.(type) {
	case v1.ReportData:
		log.Debug("Dispatching report data to file")
		b, err := json.Marshal(d)
		if err != nil {
			// This indicates a bug, not a runtime error since we should always
			// be able to serialize.
			log.WithError(err).
				WithField("Report", d).
				Panic("unable to serialize archive data to JSON")
		}
		if err = writeLog(b); err != nil {
			return err
		}
	default:
		log.Panic("Unexpected kind of archive data in file dispatcher")
	}
	return nil
}
