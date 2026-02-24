// Copyright (c) 2018-2021 Tigera, Inc. All rights reserved.

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

package policysync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/projectcalico/calico/felix/collector"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/pod2daemon/binder"
)

const (
	OrchestratorId = "k8s"
	EndpointId     = "eth0"
)
const OutputQueueLen = 100

// Server implements the API that each sync agent connects to in order to get information.
// There is a single instance of the Server, it disambiguates connections from different clients by the
// credentials present in the gRPC request.
type Server struct {
	proto.UnimplementedPolicySyncServer

	JoinUpdates     chan<- any
	stats           chan<- *proto.DataplaneStats
	wafEventHandler func(*proto.WAFEvent)
	nextJoinUID     func() uint64
}

func NewServer(joins chan<- any, collector collector.Collector, allocUID func() uint64) *Server {
	var stats chan<- *proto.DataplaneStats
	var WafEventHandler func(*proto.WAFEvent)
	if collector != nil {
		stats = collector.ReportingChannel()
		WafEventHandler = collector.WAFReportingHandler()
	}
	return &Server{
		JoinUpdates:     joins,
		stats:           stats,
		wafEventHandler: WafEventHandler,
		nextJoinUID:     allocUID,
	}
}

func (s *Server) RegisterGrpc(g *grpc.Server) {
	log.Debug("Registering with grpc.Server")
	proto.RegisterPolicySyncServer(g, s)
}

func workloadIdFromCallerContext(ctx context.Context) (string, error) {
	// Extract the workload ID from the request.
	creds, ok := binder.CallerFromContext(ctx)
	if !ok {
		return "", errors.New("unable to authenticate client")
	}
	return creds.Namespace + "/" + creds.Workload, nil
}

func (s *Server) Sync(syncRequest *proto.SyncRequest, stream proto.PolicySync_SyncServer) error {
	log.Info("New sync connection with subscription type ", syncRequest.SubscriptionType)

	// Validate for correct syncRequest first:
	st, err := NewSubscriptionType(syncRequest.SubscriptionType)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	var workloadID string
	_, tolerateUnsafe := os.LookupEnv("FELIX_POLICYSYNC_UNSAFE_CALLER")
	workloadID, err = workloadIdFromCallerContext(stream.Context())
	if err != nil {
		if !tolerateUnsafe {
			return status.Error(codes.PermissionDenied, err.Error())
		}
		hn, _ := os.Hostname()
		workloadID = fmt.Sprintf("calico-system/%s", hn)
	}

	// Allocate a new unique join ID, this allows the processor to disambiguate if there are multiple connections
	// for the same workload, which can happen transiently over client restart.  In particular, if our "leave"
	// request races with the "join" request of the new connection.
	myJoinUID := s.nextJoinUID()
	logCxt := log.WithFields(log.Fields{
		"workload": workloadID,
		"joinID":   myJoinUID,
	})
	logCxt.Info("New sync connection identified")

	// Send a join request to the processor to ask it to start sending us updates.
	updates := make(chan *proto.ToDataplane, OutputQueueLen)
	epID := types.WorkloadEndpointID{
		OrchestratorId: OrchestratorId,
		EndpointId:     EndpointId,
		WorkloadId:     workloadID,
	}
	joinMeta := JoinMetadata{
		EndpointID: epID,
		JoinUID:    myJoinUID,
	}
	s.JoinUpdates <- JoinRequest{
		SubscriptionType: st,
		JoinMetadata:     joinMeta,
		SyncRequest:      syncRequest,
		C:                updates,
	}

	// Defer the cleanup of the join and the updates channel.
	defer func() {
		logCxt.Info("Shutting down sync connection")
		joinsCopy := s.JoinUpdates
		leaveRequest := LeaveRequest{JoinMetadata: joinMeta, SubscriptionType: st}
		// Since the processor closes the update channel, we need to keep draining the updates channel to avoid
		// blocking the processor.
		//
		// We also need to send the processor a leave request to ask it to stop sending updates.
		//
		// Make sure we don't block on either operation, or we could deadlock with the processor.
		for updates != nil || joinsCopy != nil {
			select {
			case msg, ok := <-updates:
				if !ok {
					logCxt.Info("Shutting down: updates channel was closed by processor.")
					updates = nil
				}
				logCxt.WithField("msg", msg).Debug("Shutting down: discarded a message from the processor")
			case joinsCopy <- leaveRequest:
				logCxt.Info("Shutting down: Leave request sent to processor")
				joinsCopy = nil
			}
		}
		logCxt.Info("Finished shutting down sync connection")
	}()

	for update := range updates {
		err := stream.Send(update)
		if err != nil {
			logCxt.WithError(err).Warn("Failed to send update to sync client")
			return err
		}
	}
	return nil
}

func (s *Server) Report(ctx context.Context, d *proto.DataplaneStats) (*proto.ReportResult, error) {
	if s.stats == nil {
		return &proto.ReportResult{Successful: false}, nil
	}
	select {
	case s.stats <- d:
		return &proto.ReportResult{Successful: true}, nil
	case <-ctx.Done():
		return &proto.ReportResult{Successful: false}, ctx.Err()
	}
}

func (s *Server) ReportWAF(stream proto.PolicySync_ReportWAFServer) error {
	if s.wafEventHandler == nil {
		log.Error("ReportWAF called but no WAF handler")
		return errors.New("WAFEvents disabled")
	}

	for {
		wafEvent, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&proto.WAFEventResult{Successful: true})
		}
		if err != nil {
			return err
		}
		s.wafEventHandler(wafEvent)
	}
}

type UIDAllocator struct {
	l       sync.Mutex
	nextUID uint64
}

func NewUIDAllocator() *UIDAllocator {
	return &UIDAllocator{}
}

func (a *UIDAllocator) NextUID() uint64 {
	a.l.Lock()
	a.nextUID++ // Increment first so that we don't use the 0 value.
	uid := a.nextUID
	a.l.Unlock()
	return uid
}
