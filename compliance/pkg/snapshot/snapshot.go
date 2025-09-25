// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package snapshot

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	restclient "k8s.io/client-go/rest"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/list"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
)

const (
	oneDay            = 24 * time.Hour
	keepAliveInterval = 10 * time.Second
)

var allResources = resources.GetAllResourceHelpers()

// Run is the entrypoint to start running the snapshotter.
func Run(ctx context.Context, cfg *config.Config, listSrc list.Source, listDest api.ListDestination, healthy func(bool)) error {
	return (&snapshotter{
		ctx:      ctx,
		cfg:      cfg,
		healthy:  healthy,
		listSrc:  listSrc,
		listDest: listDest,
	}).run()
}

type snapshotter struct {
	ctx      context.Context
	cfg      *config.Config
	healthy  func(bool)
	listSrc  list.Source
	listDest api.ListDestination
}

type ComplianceWarningHandler struct{}

func (h *ComplianceWarningHandler) HandleWarningHeader(code int, agent string, text string) {
	if strings.Contains(text, "v1 Endpoints is deprecated") {
		// We suppress warning about Endpoints api deprecation in k8s 1.33+
		// TODO: remove this suppression when Compliance stops using Endpoints and migrate to EndpointSlices
		return
	}
	restclient.WarningLogger{}.HandleWarningHeader(code, agent, text)
}

// Run aligns the current state with the last time a snapshot was made with the expected time of the next snapshot and
// then continuously snapshots with daily periodicity.
func (s *snapshotter) run() error {
	restclient.SetDefaultWarningHandler(&ComplianceWarningHandler{})

	log.Infof("Executing snapshot continuously once every day at required time (%0.2d00hr)", s.cfg.SnapshotHour)

	// Assume we are initially healthy.
	s.healthy(true)

	// Initialize keep alive ticker.
	keepAliveTicker := time.NewTicker(keepAliveInterval)

	// Initialize resourceSnapshotters
	snapshotters := map[metav1.TypeMeta]*resourceSnapshotter{}
	for _, rh := range allResources {
		tm := rh.TypeMeta()
		snapshotters[tm] = &resourceSnapshotter{
			ctx:      s.ctx,
			kind:     tm,
			clog:     log.WithField("kind", fmt.Sprintf("%s.%s", tm.Kind, tm.APIVersion)),
			listSrc:  s.listSrc,
			listDest: s.listDest,
		}
	}

	// Run snapshot infinitely.
	for {
		// Determine if time for snapshot.
		prev, next := s.timeOfNextSnapshot()

		// Iterate over resources and store snapshot for each.
		errChan := make(chan error, len(allResources))
		wg := sync.WaitGroup{}
		for _, rh := range allResources {
			wg.Add(1)
			go func(rh resources.ResourceHelper) {
				defer wg.Done()
				tm := rh.TypeMeta()

				// Take the snapshot.
				errChan <- snapshotters[tm].maybeTakeSnapshot(prev, next)
			}(rh)
		}
		wg.Wait()
		close(errChan)

		// Iterate over all the responses coming through the channel and flag unhealthy.
		for err := range errChan {
			if err != nil {
				log.WithError(err).Error("Snapshot failed")
				s.healthy(false)
				break
			}
		}

		select {
		case <-s.ctx.Done():
			// Context cancelled.
			log.Info("Process terminating")
			keepAliveTicker.Stop()
			return nil

		case <-keepAliveTicker.C:
			// Keep alive timer fired; notify health aggregator.
			log.Debug("Waking up from keep-alive timer")
			s.healthy(true)
		}
	}
}

// timeOfNextSnapshot determines the fire time of the previous and next day.
func (s *snapshotter) timeOfNextSnapshot() (time.Time, time.Time) {
	now := time.Now()
	year, month, day := now.Date()
	fireTime := time.Date(year, month, day, s.cfg.SnapshotHour, 0, 0, 0, now.Location())
	if fireTime.Before(now) {
		return fireTime, fireTime.Add(oneDay)
	}
	return fireTime.Add(-oneDay), fireTime
}

type resourceSnapshotter struct {
	ctx                context.Context
	kind               metav1.TypeMeta
	clog               *log.Entry
	listSrc            list.Source
	listDest           api.ListDestination
	timeOfLastSnapshot *time.Time
}

func (r *resourceSnapshotter) maybeTakeSnapshot(prev, next time.Time) error {
	// If timeOfLastSnapshot is not known then populate from a linseed query.
	if r.timeOfLastSnapshot == nil {
		dayAgo := time.Now().Add(-oneDay)
		trlist, err := r.listDest.RetrieveList(r.kind, &dayAgo, nil, false)
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
				r.clog.Info("No archived snapshot")
				r.timeOfLastSnapshot = &time.Time{}
			} else {
				r.clog.WithError(err).Error("Failed to retrieve most recent archived snapshot")
				return err
			}
		} else if trlist != nil {
			r.clog.WithField("lastSnapshotTime", trlist.RequestCompletedTimestamp).Info("Found most recent archived snapshot")
			r.timeOfLastSnapshot = &trlist.RequestCompletedTimestamp.Time
		}
	}

	// If timeOfLastSnapshot is < prev then we haven't taken a snapshot in this interval. Take a snapshot.
	if r.timeOfLastSnapshot.Before(prev) {
		r.clog.Info("Taking snapshot")
		trlist, err := r.listSrc.RetrieveList(r.kind)
		if err != nil {
			r.clog.WithError(err).Error("Failed to take snapshot")
			return err
		}

		r.clog.Info("Archiving snapshot")
		if err = r.listDest.StoreList(r.kind, trlist); err != nil {
			r.clog.WithError(err).Error("Failed to archive snapshot")
			return err
		}

		r.timeOfLastSnapshot = &trlist.RequestCompletedTimestamp.Time
		r.clog.Info("Successfully archived snapshot")
	} else {
		r.clog.WithField("nextSnapshot", next.Sub(*r.timeOfLastSnapshot)).Debug("Time to next snapshot.")
	}
	return nil
}
