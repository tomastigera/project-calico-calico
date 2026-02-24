package checker_test

import (
	"testing"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/code"

	"github.com/projectcalico/calico/app-policy/checker"
	"github.com/projectcalico/calico/app-policy/policystore"
	"github.com/projectcalico/calico/app-policy/statscache"
	"github.com/projectcalico/calico/felix/proto"
)

func TestCheckAuthScenarios(t *testing.T) {
	ctx := t.Context()

	for _, scenario := range perHostCheckProviderScenarios() {
		ps := policystore.NewPolicyStoreManager()
		ps.DoWithLock(func(ps *policystore.PolicyStore) {
			for _, update := range append(scenario.updates, inSync()) {
				ps.ProcessUpdate(scenario.subscriptionType, update, false)
			}
		})
		ps.OnInSync()
		dpStats := statscache.New()
		checkServer := checker.NewServer(
			ctx, ps, dpStats,
			checker.WithSubscriptionType(scenario.subscriptionType),
			checker.WithRegisteredCheckProvider(
				checker.NewALPCheckProvider(scenario.subscriptionType, scenario.alpTproxy),
			),
		)

		for _, c := range scenario.cases {
			res, err := checkServer.Check(ctx, c.req)
			if err != nil {
				t.Errorf(
					"checkAuth %s/%s: check failed with error %v",
					scenario.comment, c.comment, err,
				)
			}
			if res.Status.Code != c.res {
				t.Errorf(
					"checkAuth %s/%s: expected %s, got %s.",
					scenario.comment, c.comment,
					code.Code(c.res),
					code.Code(res.Status.Code),
				)
			}
		}
		ps.OnReconnecting()
	}
}

type checkAuthScenario struct {
	comment, subscriptionType string
	alpTproxy                 bool
	updates                   []*proto.ToDataplane
	cases                     []*checkAuthScenarioCases
}

type checkAuthScenarioCases struct {
	comment string
	req     *authz.CheckRequest
	res     int32
}

func wepUpdate(name string, ip4s, profiles []string, appLayer *proto.ApplicationLayer) *proto.ToDataplane {
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
			WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "kubernetes",
					EndpointId:     "eth0",
					WorkloadId:     name,
				},
				Endpoint: &proto.WorkloadEndpoint{
					Name:             name,
					Ipv4Nets:         ip4s,
					ProfileIds:       profiles,
					ApplicationLayer: appLayer,
				},
			},
		},
	}
}

func ipsetUpdate(id string, members []string) *proto.ToDataplane {
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_IpsetUpdate{
			IpsetUpdate: &proto.IPSetUpdate{
				Id:      id,
				Members: members,
				Type:    proto.IPSetUpdate_IP,
			},
		},
	}
}

func policyAndProfileUpdate(policyName, profileName string, inboundRule *proto.Rule) (res []*proto.ToDataplane) {
	policy := &proto.Policy{
		InboundRules: []*proto.Rule{
			inboundRule,
		},
	}

	res = append(res, &proto.ToDataplane{
		Payload: &proto.ToDataplane_ActiveProfileUpdate{
			ActiveProfileUpdate: &proto.ActiveProfileUpdate{
				Id: &proto.ProfileID{Name: profileName},
				Profile: &proto.Profile{
					InboundRules: []*proto.Rule{
						inboundRule,
					},
				},
			},
		},
	})

	res = append(res, &proto.ToDataplane{
		Payload: &proto.ToDataplane_ActivePolicyUpdate{
			ActivePolicyUpdate: &proto.ActivePolicyUpdate{
				Id:     &proto.PolicyID{Name: policyName},
				Policy: policy,
			},
		},
	})

	return res
}

func inSync() *proto.ToDataplane {
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_InSync{
			InSync: &proto.InSync{},
		},
	}
}
