// Copyright (c) 2018-2019 Tigera, Inc. All rights reserved.
package client

import (
	"context"
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// NewSerializedSyncerQuery returns a wrapped SyncerCallbacks and QueryInterface. The wrapped
// interfaces ensures that invocations of methods in both interfaces is serialized.
func NewSerializedSyncerQuery(sc api.SyncerCallbacks, qh QueryInterface) (api.SyncerCallbacks, QueryInterface) {
	sqh := &syncerQuerySerializer{
		sc: sc,
		qh: qh,
		// The val channel should be blocking - this allows us to make use of select to
		// timeout a request if the updates are taking precedence and backed up.
		query: make(chan queryReq),
		// Give the updates channel a small amount of buffer so that we preferentially
		// select updates over queries.
		updates: make(chan any, 10),
	}
	go sqh.run()
	return sqh, sqh
}

type syncerQuerySerializer struct {
	sc      api.SyncerCallbacks
	qh      QueryInterface
	updates chan any
	query   chan queryReq
}

type queryReq struct {
	ctx  context.Context
	val  any
	resp chan queryResp
}

type queryResp struct {
	val any
	err error
}

func (uqf *syncerQuerySerializer) RunQuery(ctx context.Context, val any) (any, error) {
	log.WithField("Request", reflect.TypeOf(val)).Info("Run query")
	qrq := queryReq{
		ctx:  ctx,
		val:  val,
		resp: make(chan queryResp, 1),
	}
	select {
	case <-ctx.Done():
		log.WithError(ctx.Err()).Info("Query context expired")
		return nil, ctx.Err()
	case uqf.query <- qrq:
		// Request sent, wait for the response.
		qrp := <-qrq.resp
		log.Debug("Received query response")
		return qrp.val, qrp.err
	}
}

func (uqf *syncerQuerySerializer) OnStatusUpdated(status api.SyncStatus) {
	uqf.updates <- status
}

func (uqf *syncerQuerySerializer) OnUpdates(updates []api.Update) {
	uqf.updates <- updates
}

// run() is a blocking command - it runs the main processing loop responsible for coordinating
// query requests and syncer updates.
func (uqf *syncerQuerySerializer) run() {
	// Don't attempt to handle any queries until we have received our initial in-sync.
	log.Info("Processing updates, no queries")
SyncLoop:
	for {
		u := <-uqf.updates
		switch ut := u.(type) {
		case api.SyncStatus:
			uqf.sc.OnStatusUpdated(ut)
			if ut == api.InSync {
				log.Info("Received InSync message from syncer")
				break SyncLoop
			}
		case []api.Update:
			uqf.sc.OnUpdates(ut)
		}
	}

	// We are in sync, so handle both updates and queries.
	log.Info("Processing updates and queries")
	for {
		select {
		case u := <-uqf.updates:
			switch ut := u.(type) {
			case api.SyncStatus:
				// We don't handle going in and out of sync - so log fatal to restart our process.
				log.WithField("OnStatusUpdated", ut).Fatal("Received OnStatusUpdate message after an InSync")
			case []api.Update:
				uqf.sc.OnUpdates(ut)
			}
			// TODO(rlb): May want to flush the update buffer here so that updates take precedence over the queries

		case q := <-uqf.query:
			val, err := uqf.qh.RunQuery(q.ctx, q.val)
			q.resp <- queryResp{
				val: val,
				err: err,
			}
		}
	}
}
