// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package file

import (
	"context"
	"fmt"
	"os"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/fileutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const (
	maxAllowedAlertFiles = 5
)

// FileMaintainer wakes up on interval, loops through all alert files, deletes if there are more than max allowed files.
type FileMaintainer interface {
	Run(ctx context.Context)
	// Maintain accepts the directory path in which the total file count should be maintained.
	Maintain(path string)
	// Stop stops maintaining the total file count in the given directory path.
	Stop(path string)
}

func NewFileMaintainer(fileMaintenanceInterval time.Duration) FileMaintainer {
	return &fileMaintainer{filePaths: set.New[string](), fileMaintenanceInterval: fileMaintenanceInterval}
}

type fileMaintainer struct {
	filePaths               set.Set[string]
	fileMaintenanceInterval time.Duration
}

func (f fileMaintainer) Run(ctx context.Context) {
	go f.run(ctx)
}

func (f fileMaintainer) Maintain(path string) {
	f.filePaths.Add(path)
}

func (f fileMaintainer) Stop(path string) {
	f.filePaths.Discard(path)
}

// run runs a loop that ensure that only maximum number of allowed alert files are available in each directory.
func (f fileMaintainer) run(ctx context.Context) {
	ticker := time.NewTicker(f.fileMaintenanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for path := range f.filePaths.All() {
				// loop through all files in this path and delete files if there are more than 5
				// Delete all older files if there are more than maxAllowedAlertFiles files
				files, err := os.ReadDir(path)
				if err != nil {
					log.WithError(err).Errorf("Failed to read alert files from %s", path)
					continue
				}

				sort.Sort(fileutils.SortFile(files))

				// Delete old files irrespective of status of ElasticSearch
				if len(files) > maxAllowedAlertFiles {
					for i := len(files) - 1; i >= maxAllowedAlertFiles; i-- {
						log.Debugf("Removing older file %s", files[i].Name())
						f := fmt.Sprintf("%s/%s", path, files[i].Name())
						if err := os.Remove(f); err != nil {
							log.WithError(err).Errorf("Failed to remove older alert files from %s", f)
						}
					}
				}
			}
		case <-ctx.Done():
			return
		}
	}
}
