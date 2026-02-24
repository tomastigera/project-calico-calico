// Copyright (c) 2023 Tigera, Inc. All rights reserved.
package policystore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
)

type mockWorkloadCallbacks struct {
	callStack []string
}

func (m *mockWorkloadCallbacks) Update(k ip.Addr, v *proto.WorkloadEndpointUpdate) {
	m.callStack = append(m.callStack, fmt.Sprint("Update ", k, v))
}

func (m *mockWorkloadCallbacks) Delete(k ip.Addr, v *proto.WorkloadEndpointRemove) {
	m.callStack = append(m.callStack, fmt.Sprint("Delete ", k))
}

func (m *mockWorkloadCallbacks) Get(k ip.Addr) []*proto.WorkloadEndpoint {
	return nil
}

func (m *mockWorkloadCallbacks) Keys(k ip.Addr) []proto.WorkloadEndpointID {
	return nil
}

type workloadsTestCase struct {
	comment  string
	updates  []any
	mock     *mockWorkloadCallbacks
	expected []string
}

func runTestCase(t *testing.T, comment string, updates []any, expected []string) {
	tc := &workloadsTestCase{comment, updates, &mockWorkloadCallbacks{}, expected}
	tc.runAssertions(t)
}

func (tc *workloadsTestCase) runAssertions(t *testing.T) {
	handler := newWorkloadEndpointUpdateHandler()
	for _, upd := range tc.updates {
		handler.onResourceUpdate(upd, tc.mock)
	}
	assert.ElementsMatch(t, tc.expected, tc.mock.callStack, fmt.Sprintf("test case failed: %v", tc.comment))
}

func wepUpdate(name string, ip4s ...string) *proto.WorkloadEndpointUpdate {
	return &proto.WorkloadEndpointUpdate{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: "kubernetes",
			EndpointId:     "eth0",
			WorkloadId:     name,
		},
		Endpoint: &proto.WorkloadEndpoint{
			Name:     name,
			Ipv4Nets: ip4s,
		},
	}
}

func wepRemove(name string) *proto.WorkloadEndpointRemove {
	return &proto.WorkloadEndpointRemove{
		Id: &proto.WorkloadEndpointID{
			OrchestratorId: "kubernetes",
			EndpointId:     "eth0",
			WorkloadId:     name,
		},
	}
}

func TestWorkloads(t *testing.T) {
	runTestCase(t,
		"single workload endpoint update and remove",
		[]any{
			wepUpdate("some-pod-1", "10.0.0.1"),
			wepRemove("some-pod-1"),
		},
		[]string{
			fmt.Sprintf("Update 10.0.0.1 %v", wepUpdate("some-pod-1", "10.0.0.1")),
			"Delete 10.0.0.1",
		},
	)

	runTestCase(t,
		"single workload endpoint multi-ips update and remove",
		[]any{
			wepUpdate("some-pod-1", "10.0.0.1/32", "10.0.0.2/32"),
			wepRemove("some-pod-1"),
		},
		[]string{
			fmt.Sprintf("Update 10.0.0.1 %v", wepUpdate("some-pod-1", "10.0.0.1/32", "10.0.0.2/32")),
			fmt.Sprintf("Update 10.0.0.2 %v", wepUpdate("some-pod-1", "10.0.0.1/32", "10.0.0.2/32")),
			"Delete 10.0.0.1",
			"Delete 10.0.0.2",
		},
	)

	runTestCase(t,
		"multi workload endpoint update and remove",
		[]any{
			wepUpdate("some-pod-1", "10.0.0.1/32"),
			wepUpdate("some-pod-2", "10.0.0.2/32"),
			wepUpdate("some-pod-2", "10.0.2.1"), // mixed update: doesn't have suffix!
			wepRemove("some-pod-1"),
			wepRemove("some-pod-2"),
		},
		[]string{
			fmt.Sprintf("Update 10.0.0.1 %v", wepUpdate("some-pod-1", "10.0.0.1/32")),
			fmt.Sprintf("Update 10.0.0.2 %v", wepUpdate("some-pod-2", "10.0.0.2/32")),
			"Delete 10.0.0.2",
			// update without suffix still handled
			fmt.Sprintf("Update 10.0.2.1 %v", wepUpdate("some-pod-2", "10.0.2.1")),
			"Delete 10.0.0.1",
			"Delete 10.0.2.1",
		},
	)

	runTestCase(t,
		"single workload endpoint changing ips",
		[]any{
			wepUpdate("some-pod-1", "10.0.0.1", "10.0.0.2"),
			wepUpdate("some-pod-1", "10.0.0.1"),
			wepRemove("some-pod-1"),
		},
		[]string{
			fmt.Sprintf("Update 10.0.0.1 %s", wepUpdate("some-pod-1", "10.0.0.1", "10.0.0.2")),
			fmt.Sprintf("Update 10.0.0.2 %v", wepUpdate("some-pod-1", "10.0.0.1", "10.0.0.2")),
			"Delete 10.0.0.2",
			fmt.Sprintf("Update 10.0.0.1 %s", wepUpdate("some-pod-1", "10.0.0.1")),
			"Delete 10.0.0.1",
		},
	)
}
