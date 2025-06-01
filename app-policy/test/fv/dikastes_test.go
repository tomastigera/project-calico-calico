package fv_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"google.golang.org/genproto/googleapis/rpc/code"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/tproxydefs"
)

func (s *dikastesTestSuite) TestBasicExtAuthz() {

	inboundRule := &proto.Rule{
		Action: "Allow",
		HttpMatch: &proto.HTTPMatch{
			Methods: []string{"GET"},
			Paths: []*proto.HTTPMatch_PathMatch{
				{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/public"}},
			},
		},
	}

	steps := []dikastesTestCaseStep{
		// be wary that within steps, dikastes retains data
		{
			comment: "basics: has wep, no policy",
			updates: []*proto.ToDataplane{
				wepUpdate("pod-1", []string{"10.0.1.1"}, nil),
				ipsetUpdate(tproxydefs.ApplicationLayerPolicyIPSet, []string{"10.0.1.1"}),
				inSync(),
			},
			checks: []dikastesTestCaseData{
				{
					comment: "GET 10.0.0.1/public yields deny when no profiles",
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/public", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					// no active profiles.. so we expect a deny!
					expectedResp: newResponseWithStatus(int32(code.Code_PERMISSION_DENIED)),
					expectedErr:  nil,
				},
			},
		},
		{
			comment: "basics: has wep, staged policy only policy -- so no effect",
			updates: []*proto.ToDataplane{
				stagedPolicyUpdate("default", "secure", inboundRule),
				inSync(),
			},
			checks: []dikastesTestCaseData{
				{
					comment: "GET 10.0.0.1/public yields deny when no profiles",
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/public", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					// no active profiles.. so we expect a deny!
					expectedResp: newResponseWithStatus(int32(code.Code_PERMISSION_DENIED)),
					expectedErr:  nil,
				},
			},
		},
		{
			comment: "basics: info about policy arrives",
			updates: append([]*proto.ToDataplane{
				wepUpdate("pod-1", []string{"10.0.1.1"}, []string{"default"}),
			}, policyAndProfileUpdate("secure", "default", inboundRule)...),
			checks: []dikastesTestCaseData{
				{
					comment: "GET 10.0.0.1/public yields allow when profiles available",
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/public", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					expectedResp: newResponseWithStatus(int32(code.Code_OK)),
					expectedErr:  nil,
				},
				{
					comment: "GET 10.0.0.1/public yields deny when profiles available",
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/denied", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					expectedResp: newResponseWithStatus(int32(code.Code_PERMISSION_DENIED)),
					expectedErr:  nil,
				},
			},
		},
		{
			comment: "basics: wep gets removed",
			updates: []*proto.ToDataplane{
				wepRemove("pod-1"),
			},
			checks: []dikastesTestCaseData{
				{
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/public", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					expectedResp: newResponseWithStatus(int32(code.Code_UNKNOWN)),
					expectedErr:  nil,
				},
				{
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/denied", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					expectedResp: newResponseWithStatus(int32(code.Code_UNKNOWN)),
					expectedErr:  nil,
				},
			},
		},
	}
	for _, step := range steps {
		step.runAssertions(s)
	}
}

func (s *dikastesTestSuite) TestDikastesRecov() {
	inboundRule := &proto.Rule{
		Action: "Allow",
		HttpMatch: &proto.HTTPMatch{
			Methods: []string{"GET"},
			Paths: []*proto.HTTPMatch_PathMatch{
				{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/public"}},
			},
		},
	}

	steps := []*dikastesTestCaseStep{
		{
			comment: "basics: wep with policy and profile",
			updates: append([]*proto.ToDataplane{
				wepUpdate("pod-1", []string{"10.0.1.1"}, []string{"default"}),
				ipsetUpdate(tproxydefs.ApplicationLayerPolicyIPSet, []string{"10.0.1.1"}),
				inSync(),
			}, policyAndProfileUpdate("secure", "default", inboundRule)...),
			checks: []dikastesTestCaseData{
				{
					comment: "GET 10.0.0.1/public yields allow when profiles available",
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/public", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					expectedResp: newResponseWithStatus(int32(code.Code_OK)),
					expectedErr:  nil,
				},
				{
					comment: "GET 10.0.0.1/public yields deny when profiles available",
					inputReq: newRequest(
						s.uidAlloc.NextUID(), "GET", "http://10.0.1.1/denied", nil,
						newPeer("10.0.0.1", "default", "default"),
						newPeer("10.0.1.1", "default", "default"),
					),
					expectedResp: newResponseWithStatus(int32(code.Code_PERMISSION_DENIED)),
					expectedErr:  nil,
				},
			},
		},
	}

	steps[0].runAssertions(s)
	s.policySync.StopAndDisconnect()
	<-time.After(500 * time.Millisecond)
	s.policySync.Resume()

	// do same assertions
	steps[0].runAssertions(s)
}

func TestDikastesSuite(t *testing.T) {
	s := &dikastesTestSuite{uidAlloc: NewUIDAllocator()}
	suite.Run(t, s)
}

func TestDikastesBasicAuthz(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// define test data
	updates, checks := basicDikastesExtAuthzData(t)
	// get a dikastes + policysync harness
	harness := harnessSetupAndStart(ctx, t)
	t.Cleanup(func() {
		if err := harness.Cleanup(); err != nil {
			t.Errorf("error cleaning up harness: %v", err)
		}
	})

	harness.SendUpdates(updates...)

	_, err := harness.Checks(ctx, checks)
	if err != nil {
		t.Errorf("error occured while performing check(s): %v", err)
	}

	// assert.Equal(t, []*dikastesHarnessResultPair{
	// 	{
	// 		response: &authzv3.CheckResponse{
	// 			Status: &status.Status{Code: 0},
	// 		},
	// 		err: nil,
	// 	},
	// }, results)
}
