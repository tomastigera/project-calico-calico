package fv_test

import (
	"context"
	"testing"

	authzv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/tproxydefs"
)

func BenchmarkDikastesExtAuthz(b *testing.B) {
	log.SetLevel(log.PanicLevel)
	ctx := b.Context()

	// define test data
	updates, checks := basicDikastesExtAuthzData(b)
	// get a dikastes + policysync harness
	harness := harnessSetupAndStart(ctx, b)
	b.Cleanup(func() {
		if err := harness.Cleanup(); err != nil {
			b.Errorf("error cleaning up harness: %v", err)
		}
	})

	b.RunParallel(func(p *testing.PB) {
		// fill dikastes with data
		for p.Next() {
			harness.SendUpdates(updates...)
		}
	})

	b.RunParallel(func(p *testing.PB) {
		// do checks
		for p.Next() {
			_, err := harness.Checks(ctx, checks)
			if err != nil {
				b.Errorf("error occured while performing check(s): %v", err)
			}
		}
	})
}

func basicDikastesExtAuthzData(tb testing.TB) (updates []*proto.ToDataplane, checks []*authzv3.CheckRequest) {
	// exclude this data routine from bench stats
	tb.Helper()

	inboundRule := &proto.Rule{
		Action: "Allow",
		HttpMatch: &proto.HTTPMatch{
			Methods: []string{"GET"},
			Paths: []*proto.HTTPMatch_PathMatch{
				{PathMatch: &proto.HTTPMatch_PathMatch_Prefix{Prefix: "/public"}},
			},
		},
	}

	updates = append([]*proto.ToDataplane{
		wepUpdate("pod-1", []string{"10.0.1.1/32"}, []string{"default"}),
		ipsetUpdate(tproxydefs.ApplicationLayerPolicyIPSet, []string{"10.0.1.1"}),
		inSync(),
	}, policyAndProfileUpdate("secure", "default", inboundRule)...)

	return updates, []*authzv3.CheckRequest{
		newRequest(
			0, "GET", "http://10.0.1.1/public", nil,
			newPeer("10.0.0.1", "default", "default"),
			newPeer("10.0.1.1", "default", "default"),
		),
	}
}

func harnessSetupAndStart(ctx context.Context, tb testing.TB) *dikastesHarness {
	// exclude this setup routine from bench stats
	tb.Helper()

	harness, err := NewDikastesTestHarness(tb.TempDir())
	if err != nil {
		tb.Fatalf("failure setting up test harness: %v", err)
	}
	if err := harness.Start(ctx); err != nil {
		tb.Fatalf("failure starting up test harness: %v", err)
	}
	return harness
}
