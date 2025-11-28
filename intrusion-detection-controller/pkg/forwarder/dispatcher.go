// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package forwarder

import (
	"io"
	"path"

	"github.com/DeRuina/timberjack"
	log "github.com/sirupsen/logrus"
)

// LogDispatcher is the external interface for dispatchers. For now there is only the file dispatcher.
type LogDispatcher interface {
	Initialize() error
	Dispatch(data []byte) error
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
		Filename:    path.Join(d.directory, d.fileName),
		FileMode:    0o644,
		Compression: "zstd",
		MaxSize:     d.maxMB,
		MaxBackups:  d.numFiles,
	}
	return nil
}

// Dispatch takes in serialized data and writes it to the pre-configured destination file.
func (d *fileDispatcher) Dispatch(data []byte) error {
	writeLog := func(b []byte) (int, error) {
		b = append(b, '\n')
		// It is an error to call Dispatch before Initialize, so it's safe to
		// assume d.logger is non-nil.
		n, err := d.logger.Write(b)
		if err != nil {
			log.WithError(err).Error("unable to dispatch data to file")
			return n, err
		}
		return n, nil
	}
	bytesWritten, err := writeLog(data)
	if err != nil {
		return err
	}
	log.Debugf("Dispatcher wrote %d bytes", bytesWritten)
	return nil
}
