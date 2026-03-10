// Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package syncher

import (
	"context"
	"io"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	healthzv1 "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/projectcalico/calico/app-policy/health"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/statscache"
	"github.com/projectcalico/calico/felix/proto"
)

const (
	// The stats reporting and flush interval. Currently set to half the hardcoded expiration time of cache entries in
	// the Felix stats collector component.
	DefaultSubscriptionType   = "per-pod-policies"
	DefaultStatsFlushInterval = 5 * time.Second
	PolicySyncRetryTime       = 1000 * time.Millisecond
)

type SyncClient struct {
	target           string
	dialOpts         []grpc.DialOption
	subscriptionType string
	inSync           bool
	storeManager     policystore.PolicyStoreManager
	stats            chan map[statscache.Tuple]statscache.Values
	wafEvents        chan *proto.WAFEvent
	client           proto.PolicySyncClient
}

type ClientOptions func(*SyncClient)

func WithSubscriptionType(subscriptionType string) ClientOptions {
	return func(s *SyncClient) {
		switch subscriptionType {
		case "":
			s.subscriptionType = "per-pod-policies"
		case "per-pod-policies", "per-host-policies":
			s.subscriptionType = subscriptionType
		default:
			log.Panicf("invalid subscription type: '%s'", subscriptionType)
		}
	}
}

// NewClient creates a new syncClient.
func NewClient(target string, policyStoreManager policystore.PolicyStoreManager, dialOpts []grpc.DialOption, clientOpts ...ClientOptions) *SyncClient {
	syncClient := &SyncClient{
		target: target, dialOpts: dialOpts,
		storeManager:     policyStoreManager,
		stats:            make(chan map[statscache.Tuple]statscache.Values),
		wafEvents:        make(chan *proto.WAFEvent),
		subscriptionType: DefaultSubscriptionType,
	}
	for _, opt := range clientOpts {
		opt(syncClient)
	}
	return syncClient
}

func (s *SyncClient) syncRequest() *proto.SyncRequest {
	return &proto.SyncRequest{
		SupportsDropActionOverride: true,
		SupportsDataplaneStats:     true,
		SubscriptionType:           s.subscriptionType,
	}
}

func (s *SyncClient) RegisterGRPCServices(gs *grpc.Server) {
	healthzv1.RegisterHealthServer(gs, health.NewHealthCheckService(s))
}

func (s *SyncClient) Start(ctx context.Context) error {
	// Create the connection with policySync
	cc, err := grpc.NewClient(s.target, s.dialOpts...)
	if err != nil {
		return err
	}
	s.client = proto.NewPolicySyncClient(cc)
	// go routine to close the connection when the context is Done
	go func() {
		<-ctx.Done()
		_ = cc.Close()
	}()

	go s.sync(ctx)
	go s.sendStats(ctx)
	go s.sendWAFEvents(ctx)

	return nil
}

func (s *SyncClient) OnStatsCacheFlush(v map[statscache.Tuple]statscache.Values) {
	// Only send stats if we are in sync.
	if !s.inSync {
		return
	}
	s.stats <- v
}

func (s *SyncClient) OnWAFEvent(v *proto.WAFEvent) {
	s.wafEvents <- v
}

func (s *SyncClient) sync(ctx context.Context) {
	updateC := make(chan *proto.ToDataplane)
	retryC := make(chan struct{})
	log.Info("connecting and syncing with policy server")
	s.connectSyncStream(ctx, updateC, retryC)

	for {
		select {
		case <-ctx.Done():
			s.inSync = false
			return
		case <-retryC:
			// Retry the connection to the sync stream.
			log.Info("retrying connection to policy server")
			s.connectSyncStream(ctx, updateC, retryC)
		case update := <-updateC:
			switch update.Payload.(type) {
			case *proto.ToDataplane_InSync:
				s.inSync = true
				log.Info("connected and in sync with policy server.")
				s.storeManager.OnInSync()
			default:
				// Process the update.
				if log.IsLevelEnabled(log.DebugLevel) {
					log.WithField("update", update).Debug("received update from policy server")
				}
				s.storeManager.DoWithLock(func(ps *policystore.PolicyStore) {
					ps.ProcessUpdate(s.subscriptionType, update, false)
				})
			}
		}
	}
}

func (s *SyncClient) connectSyncStream(ctx context.Context, updateC chan<- *proto.ToDataplane, retryC chan<- struct{}) {
	retryFn := func() {
		select {
		case <-time.After(PolicySyncRetryTime):
		case <-ctx.Done():
			return
		}
		retryC <- struct{}{}
	}

	// try to create the stream
	log.Debugf("trying to connect Sync stream with PolicySync")
	s.inSync = false
	s.storeManager.OnReconnecting()
	stream, err := s.client.Sync(ctx, s.syncRequest())
	if err != nil {
		log.WithError(err).Error("failed to start Sync stream with PolicySync server")
		go retryFn()
		return
	}
	// read the stream on a go routine
	go func() {
		defer retryFn()
		for {
			update, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				log.WithError(err).Error("failed to read Sync message from PolicySync")
				return
			}
			updateC <- update
		}
	}()
}

// Readiness returns whether the SyncClient is InSync.
func (s *SyncClient) Readiness() (ready bool) {

	return s.inSync
}

// sendStats is the main stats reporting loop.
func (s *SyncClient) sendStats(ctx context.Context) {
	log.Debug("start: sendStats --> policySync server")
readLoop:
	for {
		select {
		case <-ctx.Done():
			log.Debug("end: sendStats --x policySync server")
			return
		case a := <-s.stats:
			for t, v := range a {
				if err := s.report(ctx, t, v); err != nil {
					log.WithError(err).Warning("Error reporting stats")
					continue readLoop
				}
			}
		}
	}
}

// sendWAFEvents is the main WAFEvents reporting loop.
func (s *SyncClient) sendWAFEvents(ctx context.Context) {
	var batch []*proto.WAFEvent
	var batchC = make(chan []*proto.WAFEvent)
	var batchCMasked chan []*proto.WAFEvent

	log.Info("Starting sending WAFEvents to Policy Sync server")

	go s.processWAFEventsBatch(ctx, batchC)

	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.wafEvents:
			batch = append(batch, e)
			batchCMasked = batchC
		case batchCMasked <- batch:
			batch = nil
			batchCMasked = nil
		}
	}
}

func (s *SyncClient) processWAFEventsBatch(ctx context.Context, batchC <-chan []*proto.WAFEvent) {
	var (
		currentBatch []*proto.WAFEvent
		ptrBatchC    = batchC
		retryC       <-chan time.Time
		stream       proto.PolicySync_ReportWAFClient
		err          error
	)

loop:
	for {
		select {
		case <-ctx.Done():
			return
		case currentBatch = <-ptrBatchC:
			// Mask channel until we've finished processing this batch.
			ptrBatchC = nil
		case <-retryC:
		}

		if stream == nil {
			stream, err = s.client.ReportWAF(ctx)
			if err != nil {
				log.WithError(err).Error("Error creating ReportWAF stream")
				retryC = time.After(PolicySyncRetryTime)
				continue
			}
		}

		for i, e := range currentBatch {
			log.WithField("wafEvent", e).Debug("Sending WAFEvent")
			if err := stream.Send(e); err != nil {
				log.WithField("wafEvent", e).Debug("Failed to send WAFEvent")
				currentBatch = currentBatch[i:]
				stream = nil
				retryC = time.After(PolicySyncRetryTime)
				continue loop
			}
		}

		ptrBatchC = batchC
	}
}

// report converts the statscache formatted stats and reports it as a proto.DataplaneStats to Felix.
func (s *SyncClient) report(ctx context.Context, t statscache.Tuple, v statscache.Values) error {
	log.Debugf("Reporting statistic to Felix: %s=%s", t, v)

	d := &proto.DataplaneStats{
		SrcIp:    t.SrcIp,
		DstIp:    t.DstIp,
		SrcPort:  t.SrcPort,
		DstPort:  t.DstPort,
		Protocol: &proto.Protocol{NumberOrName: &proto.Protocol_Name{Name: t.Protocol}},
	}
	if v.HTTPRequestsAllowed > 0 {
		d.Stats = append(d.Stats, &proto.Statistic{
			Direction:  proto.Statistic_IN,
			Relativity: proto.Statistic_DELTA,
			Kind:       proto.Statistic_HTTP_REQUESTS,
			Action:     proto.Action_ALLOWED,
			Value:      v.HTTPRequestsAllowed,
		})
	}
	if v.HTTPRequestsDenied > 0 {
		d.Stats = append(d.Stats, &proto.Statistic{
			Direction:  proto.Statistic_IN,
			Relativity: proto.Statistic_DELTA,
			Kind:       proto.Statistic_HTTP_REQUESTS,
			Action:     proto.Action_DENIED,
			Value:      v.HTTPRequestsDenied,
		})
	}
	if r, err := s.client.Report(ctx, d); err != nil {
		// Error sending stats, must be a connection issue, so exit now to force a reconnect.
		return err
	} else if !r.Successful {
		// If the remote end indicates unsuccessful then the remote end is likely transitioning from having
		// stats enabled to having stats disabled. This should be transient, so log a warning, but otherwise
		// treat as a successful report.
		log.Warning("Remote end indicates dataplane statistics not processed successfully")
		return nil
	}
	return nil
}
