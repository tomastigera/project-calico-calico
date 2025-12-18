// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"fmt"
	"net/url"
	"sync"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authzv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

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

func inSync() *proto.ToDataplane {
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_InSync{
			InSync: &proto.InSync{},
		},
	}
}

func wepUpdate(name string, ip4s, profiles []string) *proto.ToDataplane {
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_WorkloadEndpointUpdate{
			WorkloadEndpointUpdate: &proto.WorkloadEndpointUpdate{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "kubernetes",
					EndpointId:     "eth0",
					WorkloadId:     name,
				},
				Endpoint: &proto.WorkloadEndpoint{
					Name:       name,
					Ipv4Nets:   ip4s,
					ProfileIds: profiles,
				},
			},
		},
	}
}

func wepRemove(name string) *proto.ToDataplane {
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_WorkloadEndpointRemove{
			WorkloadEndpointRemove: &proto.WorkloadEndpointRemove{
				Id: &proto.WorkloadEndpointID{
					OrchestratorId: "kubernetes",
					EndpointId:     "eth0",
					WorkloadId:     name,
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
				Id:     &proto.PolicyID{Name: policyName, Kind: v3.KindGlobalNetworkPolicy},
				Policy: policy,
			},
		},
	})

	return res
}

func stagedPolicyUpdate(name, ns string, inboundRule *proto.Rule) *proto.ToDataplane {
	policy := &proto.Policy{
		InboundRules: []*proto.Rule{
			inboundRule,
		},
	}
	return &proto.ToDataplane{
		Payload: &proto.ToDataplane_ActivePolicyUpdate{
			ActivePolicyUpdate: &proto.ActivePolicyUpdate{
				Id: &proto.PolicyID{
					Name:      name,
					Namespace: ns,
					Kind:      v3.KindStagedNetworkPolicy,
				},
				Policy: policy,
			},
		},
	}
}

func newRequest(
	id uint64,
	method, requestUrl string,
	// todo: add body, rawbody for waf processing tests
	headers map[string]string,
	src, dst *authzv3.AttributeContext_Peer,
) *authzv3.CheckRequest {
	u, _ := url.Parse(requestUrl)

	return &authzv3.CheckRequest{
		Attributes: &authzv3.AttributeContext{
			Source:      src,
			Destination: dst,
			Request: &authzv3.AttributeContext_Request{
				Time: timestamppb.Now(),
				Http: &authzv3.AttributeContext_HttpRequest{
					Id:      fmt.Sprint(id),
					Scheme:  u.Scheme,
					Host:    u.Host,
					Method:  method,
					Path:    u.Path,
					Query:   u.RawQuery,
					Headers: headers,
				},
			},
		},
	}
}

func newPeer(address, ns, sa string) *authzv3.AttributeContext_Peer {
	return &authzv3.AttributeContext_Peer{
		Principal: fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", ns, sa),
		Address: &corev3.Address{
			Address: &corev3.Address_SocketAddress{
				SocketAddress: &corev3.SocketAddress{
					Protocol: corev3.SocketAddress_TCP,
					Address:  address,
				},
			},
		},
	}
}

func newResponseWithStatus(code int32) *authzv3.CheckResponse {
	return &authzv3.CheckResponse{
		Status: &status.Status{
			Code: code,
		},
	}
}

func TestStagedPolicyUpdate(t *testing.T) {
	stagedPolicy := stagedPolicyUpdate("test", "default", &proto.Rule{})
	if !model.KindIsStaged(stagedPolicy.GetActivePolicyUpdate().GetId().GetKind()) {
		t.Error("Expected staged policy")
	}
}
