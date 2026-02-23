// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package policysync_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/policysync"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
)

type perHostMockClient struct {
	lock sync.Mutex

	name, subscriptionType string
	uidAllocator           *policysync.UIDAllocator
	meta                   policysync.JoinMetadata
	observations           []*proto.ToDataplane
	onLeaveCancel          context.CancelFunc
}

func newPerHostMockClient(name, subscriptionType string, uidAllocator *policysync.UIDAllocator) *perHostMockClient {
	return &perHostMockClient{name: name, subscriptionType: subscriptionType, uidAllocator: uidAllocator}
}

func (cl *perHostMockClient) join(ctx context.Context, toUpdates chan any) {
	sr := &proto.SyncRequest{
		SubscriptionType: cl.subscriptionType,
	}

	// Buffer outputs so that Processor won't block.
	output := make(chan *proto.ToDataplane)
	cl.meta = policysync.JoinMetadata{
		EndpointID: testId(cl.name),
		JoinUID:    cl.uidAllocator.NextUID(),
	}
	st, err := policysync.NewSubscriptionType(sr.SubscriptionType)
	if err != nil {
		logrus.Panicf("wrong subscription type specified in test %s %v", sr.SubscriptionType, err)
	}
	jr := policysync.JoinRequest{
		SubscriptionType: st,
		JoinMetadata:     cl.meta,
		SyncRequest:      sr,
		C:                output,
	}

	toUpdates <- jr

	cctx, cancel := context.WithCancel(ctx)
	go cl.observe(cctx, output)
	cl.onLeaveCancel = cancel
}

func (cl *perHostMockClient) observe(ctx context.Context, output chan *proto.ToDataplane) {
	for {
		select {
		case observation := <-output:
			cl.lock.Lock()
			cl.observations = append(cl.observations, observation)
			cl.lock.Unlock()
		case <-ctx.Done():
			return
		}
	}
}

func (cl *perHostMockClient) readObservations(readFn func([]*proto.ToDataplane)) {
	cl.lock.Lock()
	defer cl.lock.Unlock()

	readFn(cl.observations)
}

func (cl *perHostMockClient) leave(ctx context.Context, toUpdates chan any) {
	defer cl.onLeaveCancel()
	lr := policysync.LeaveRequest{JoinMetadata: cl.meta}
	toUpdates <- lr
}

func wepUpdate(name string) *proto.WorkloadEndpointUpdate {
	id := testId(name)
	return &proto.WorkloadEndpointUpdate{
		Id:       types.WorkloadEndpointIDToProto(id),
		Endpoint: &proto.WorkloadEndpoint{},
	}
}

func profileUpdate(name string) *proto.ActiveProfileUpdate {
	logrus.Debug("sending profile update: ", name)
	id := proto.ProfileID{Name: name}
	return &proto.ActiveProfileUpdate{
		Id: &id,
	}
}

func TestProcessorWithHostmodeClients(t *testing.T) {
	ctx := t.Context()

	const subscriptionType = "per-host-policies"
	uidAllocator := policysync.NewUIDAllocator()

	updates := make(chan any)
	configParams := &config.Config{
		DropActionOverride: "LogAndDrop",
	}
	processor := policysync.NewProcessor(configParams, updates)
	go processor.StartWithCtx(ctx)
	registration := processor.JoinUpdates

	// setup clients
	d1 := newPerHostMockClient("dikastes-1", subscriptionType, uidAllocator)
	d2 := newPerHostMockClient("dikastes-2", subscriptionType, uidAllocator)
	d3 := newPerHostMockClient("dikastes-2", subscriptionType, uidAllocator)

	// d1 joins ahead of updates happening
	d1.join(ctx, registration)

	// send wep/profile update.. updates
	wepNames := []string{"a", "b", "c"}
	profileNames := []string{"j", "k", "l"}
	for _, wepName := range wepNames {
		logrus.Info("send wep", wepName)
		updates <- wepUpdate(wepName)
	}
	for _, profileName := range profileNames {
		updates <- profileUpdate(profileName)
	}
	updates <- &proto.InSync{}

	// late joiners should receive same wep updates even if it already happened
	// exceptions are: remove 'updates
	d2.join(ctx, registration)
	d3.join(ctx, registration)

	expectedUpdatesCount := len(wepNames) + len(profileNames) + 1

	// all clients should have same observations on updates
	expectedObservations := []*proto.ToDataplane{
		{
			Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
				WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						OrchestratorId: "k8s",
						WorkloadId:     "a",
						EndpointId:     "eth0",
					},
					Endpoint: &proto.WorkloadEndpoint{},
				},
			},
		},
		{
			Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
				WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						OrchestratorId: "k8s",
						WorkloadId:     "b",
						EndpointId:     "eth0",
					},
					Endpoint: &proto.WorkloadEndpoint{},
				},
			},
		},
		{
			Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
				WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
					Id: &proto.WorkloadEndpointID{
						OrchestratorId: "k8s",
						WorkloadId:     "c",
						EndpointId:     "eth0",
					},
					Endpoint: &proto.WorkloadEndpoint{},
				},
			},
		},
		{
			Payload: &proto.ToDataplane_ActiveProfileUpdate{
				ActiveProfileUpdate: &proto.ActiveProfileUpdate{
					Id: &proto.ProfileID{Name: "j"},
				},
			},
		},
		{
			Payload: &proto.ToDataplane_ActiveProfileUpdate{
				ActiveProfileUpdate: &proto.ActiveProfileUpdate{
					Id: &proto.ProfileID{Name: "k"},
				},
			},
		},
		{
			Payload: &proto.ToDataplane_ActiveProfileUpdate{
				ActiveProfileUpdate: &proto.ActiveProfileUpdate{
					Id: &proto.ProfileID{Name: "l"},
				},
			},
		},
		{
			Payload: &proto.ToDataplane_InSync{
				InSync: &proto.InSync{},
			},
		},
	}

	for _, d := range []*perHostMockClient{d1, d2, d3} {
		var observations []*proto.ToDataplane
		hasNumberOfObservations := func() (res bool) {
			d.readObservations(func(o []*proto.ToDataplane) {
				res = len(o) == expectedUpdatesCount
				if res {
					observations = o
				}
			})
			return
		}
		assert.Eventually(t,
			hasNumberOfObservations,
			time.Second*2, time.Millisecond*200,
			"didn't get the number of expected updates in time",
		)
		assert.Len(t, observations, expectedUpdatesCount, "clients connected AFTER updates should have the correct number of updates")

		visited := make([]bool, len(observations))
		for _, eo := range expectedObservations {
			found := false
			for i, o := range observations {
				if !visited[i] && googleproto.Equal(eo, o) {
					visited[i] = true
					found = true
					break
				}
			}
			assert.True(t, found, "expected observation not found: %v", eo)
		}
	}

	// clients leave
	d1.leave(ctx, registration)
	d2.leave(ctx, registration)
	d3.leave(ctx, registration)
}
