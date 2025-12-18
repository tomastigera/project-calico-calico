// Copyright (c) 2018-2024 Tigera, Inc. All rights reserved.
//
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

package policysync_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"
	googleproto "google.golang.org/protobuf/proto"

	"github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/policysync"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/types"
	"github.com/projectcalico/calico/pod2daemon/binder"
)

const (
	IPSetName   = "testset"
	ProfileName = "testpro"
	TierName    = "testtier"
	PolicyName  = "testpolicy"
)

func init() {
	resolver.SetDefaultScheme("passthrough")
}

var _ = Describe("Processor", func() {
	var configParams *config.Config
	var uut *policysync.Processor
	var updates chan interface{}
	var updateServiceAccount func(name, namespace string)
	var removeServiceAccount func(name, namespace string)
	var updateNamespace func(name string)
	var removeNamespace func(name string)
	var updateRoute func(dst, dstNodeName, dstNodeIp string)
	var removeRoute func(dst string)
	var join func(sr *proto.SyncRequest, w string, jid uint64) (chan *proto.ToDataplane, policysync.JoinMetadata)
	var leave func(jm policysync.JoinMetadata)

	BeforeEach(func() {
		updates = make(chan interface{})
		configParams = &config.Config{
			DropActionOverride: "LogAndDrop",
		}
		uut = policysync.NewProcessor(configParams, updates)

		updateServiceAccount = func(name, namespace string) {
			updates <- &proto.ServiceAccountUpdate{
				Id: &proto.ServiceAccountID{Name: name, Namespace: namespace},
			}
		}
		removeServiceAccount = func(name, namespace string) {
			updates <- &proto.ServiceAccountRemove{
				Id: &proto.ServiceAccountID{Name: name, Namespace: namespace},
			}
		}
		updateNamespace = func(name string) {
			updates <- &proto.NamespaceUpdate{
				Id: &proto.NamespaceID{Name: name},
			}
		}
		removeNamespace = func(name string) {
			updates <- &proto.NamespaceRemove{
				Id: &proto.NamespaceID{Name: name},
			}
		}
		updateRoute = func(dst, dstNodeName, dstNodeIp string) {
			updates <- &proto.RouteUpdate{
				Types:       proto.RouteType_REMOTE_WORKLOAD,
				IpPoolType:  proto.IPPoolType_NONE,
				Dst:         dst,
				DstNodeName: dstNodeName,
				DstNodeIp:   dstNodeIp,
			}
		}
		removeRoute = func(dst string) {
			updates <- &proto.RouteRemove{
				Dst: dst,
			}
		}
		join = func(sr *proto.SyncRequest, w string, jid uint64) (chan *proto.ToDataplane, policysync.JoinMetadata) {
			// Buffer outputs so that Processor won't block.
			output := make(chan *proto.ToDataplane, 100)
			joinMeta := policysync.JoinMetadata{
				EndpointID: testId(w),
				JoinUID:    jid,
			}
			st, err := policysync.NewSubscriptionType(sr.SubscriptionType)
			if err != nil {
				logrus.Panicf("wrong subscription type specified in test %s %v", sr.SubscriptionType, err)
			}
			jr := policysync.JoinRequest{
				SubscriptionType: st,
				JoinMetadata:     joinMeta,
				SyncRequest:      sr,
				C:                output,
			}
			uut.JoinUpdates <- jr
			return output, joinMeta
		}
		leave = func(jm policysync.JoinMetadata) {
			lr := policysync.LeaveRequest{JoinMetadata: jm}
			uut.JoinUpdates <- lr
		}
	})

	Context("with Processor started", func() {
		BeforeEach(func() {
			uut.Start()
		})

		Describe("ServiceAccount update/remove", func() {
			Context("updates before any join", func() {
				BeforeEach(func() {
					// Add, delete, re-add
					updateServiceAccount("test_serviceaccount0", "test_namespace0")
					removeServiceAccount("test_serviceaccount0", "test_namespace0")
					updateServiceAccount("test_serviceaccount0", "test_namespace0")

					// Some simple adds
					updateServiceAccount("test_serviceaccount0", "test_namespace1")
					updateServiceAccount("test_serviceaccount1", "test_namespace0")

					// Add, delete
					updateServiceAccount("removed", "removed")
					removeServiceAccount("removed", "removed")
				})

				Context("on new policy sync join", func() {
					var output chan *proto.ToDataplane
					var accounts [3]types.ServiceAccountID

					BeforeEach(func() {
						output, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
						for i := 0; i < 3; i++ {
							msg := <-output
							accounts[i] = types.ProtoToServiceAccountID(
								msg.GetServiceAccountUpdate().GetId(),
							)
						}
					})

					It("should get 3 updates", func() {
						Expect(accounts).To(ContainElement(types.ServiceAccountID{
							Name: "test_serviceaccount0", Namespace: "test_namespace0",
						}))
						Expect(accounts).To(ContainElement(types.ServiceAccountID{
							Name: "test_serviceaccount0", Namespace: "test_namespace1",
						}))
						Expect(accounts).To(ContainElement(types.ServiceAccountID{
							Name: "test_serviceaccount1", Namespace: "test_namespace0",
						}))
					})

					It("should pass updates", func() {
						updateServiceAccount("t0", "t5")
						msg := <-output
						Expect(googleproto.Equal(
							msg.GetServiceAccountUpdate().GetId(), &proto.ServiceAccountID{Name: "t0", Namespace: "t5"},
						)).To(BeTrue())
					})

					It("should pass removes", func() {
						removeServiceAccount("test_serviceaccount0", "test_namespace0")
						msg := <-output
						Expect(googleproto.Equal(
							msg.GetServiceAccountRemove().GetId(),
							&proto.ServiceAccountID{Name: "test_serviceaccount0", Namespace: "test_namespace0"},
						)).To(BeTrue())
					})
				})

				Context("on new route sync join", func() {
					var output chan *proto.ToDataplane

					BeforeEach(func() {
						output, _ = join(&proto.SyncRequest{SubscriptionType: "l3-routes"}, "test", 1)
					})

					It("should get no updates", func() {
						Expect(len(output)).To(BeZero())
					})

					It("should not pass updates", func() {
						updateServiceAccount("t0", "t5")
						Expect(len(output)).To(BeZero())
					})

					It("should not pass removes", func() {
						removeServiceAccount("test_serviceaccount0", "test_namespace0")
						Expect(len(output)).To(BeZero())
					})
				})
			})

			Context("with two joined policy sync endpoints", func() {
				var output [2]chan *proto.ToDataplane

				BeforeEach(func() {
					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						d := types.WorkloadEndpointIDToProto(testId(w))
						output[i], _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, w, uint64(i))

						// Ensure the joins are completed by sending a workload endpoint for each.
						updates <- &proto.WorkloadEndpointUpdate{
							Id:       d,
							Endpoint: &proto.WorkloadEndpoint{},
						}
						<-output[i]
					}
				})

				It("should forward updates to both endpoints", func() {
					updateServiceAccount("t23", "t2")
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
				})

				It("should forward removes to both endpoints", func() {
					removeServiceAccount("t23", "t2")
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							ServiceAccountRemove: &proto.ServiceAccountRemove{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							ServiceAccountRemove: &proto.ServiceAccountRemove{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
				})
			})

			Context("with two joined policy sync endpoints each with different drop action override settings", func() {
				var output [2]chan *proto.ToDataplane

				BeforeEach(func() {
					sr := [2]*proto.SyncRequest{{
						SupportsDropActionOverride: true,
						SubscriptionType:           "per-pod-policies",
					}, {}}

					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						output[i], _ = join(sr[i], w, uint64(i))

						// Ensure the joins are completed by sending service account updates.
						updateServiceAccount("t23", "t2")
					}
				})

				It("should forward a config update to endpoint 0 only, followed by SA updates to both endpoints", func() {
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ConfigUpdate{
							ConfigUpdate: &proto.ConfigUpdate{
								Config: map[string]string{
									"DropActionOverride": "LogAndDrop",
								},
							},
						},
					})).To(BeTrue())
					g = <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
				})
			})
		})

		Describe("Namespace update/remove", func() {
			Context("updates before any join", func() {
				BeforeEach(func() {
					// Add, delete, re-add
					updateNamespace("test_namespace0")
					removeNamespace("test_namespace0")
					updateNamespace("test_namespace0")

					// Some simple adds
					updateNamespace("test_namespace1")
					updateNamespace("test_namespace2")

					// Add, delete
					updateNamespace("removed")
					removeNamespace("removed")
				})

				Context("on new policy sync join", func() {
					var output chan *proto.ToDataplane
					var accounts [3]types.NamespaceID

					BeforeEach(func() {
						output, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
						for i := 0; i < 3; i++ {
							msg := <-output
							accounts[i] = types.ProtoToNamespaceID(
								msg.GetNamespaceUpdate().GetId(),
							)
						}
					})

					It("should get 3 updates", func() {
						Expect(accounts).To(ContainElement(types.NamespaceID{Name: "test_namespace0"}))
						Expect(accounts).To(ContainElement(types.NamespaceID{Name: "test_namespace1"}))
						Expect(accounts).To(ContainElement(types.NamespaceID{Name: "test_namespace2"}))
					})

					It("should pass updates", func() {
						updateNamespace("t0")
						msg := <-output
						Expect(googleproto.Equal(msg.GetNamespaceUpdate().GetId(), &proto.NamespaceID{Name: "t0"})).To(BeTrue())
					})

					It("should pass removes", func() {
						removeNamespace("test_namespace0")
						msg := <-output
						Expect(googleproto.Equal(msg.GetNamespaceRemove().GetId(), &proto.NamespaceID{Name: "test_namespace0"})).To(BeTrue())
					})
				})

				Context("on new route sync join", func() {
					var output chan *proto.ToDataplane

					BeforeEach(func() {
						output, _ = join(&proto.SyncRequest{SubscriptionType: "l3-routes"}, "test", 1)
					})

					It("should get no updates", func() {
						Expect(len(output)).To(BeZero())
					})

					It("should not pass updates", func() {
						updateNamespace("t0")
						Expect(len(output)).To(BeZero())
					})

					It("should not pass removes", func() {
						removeNamespace("test_namespace0")
						Expect(len(output)).To(BeZero())
					})
				})
			})

			Context("with two joined policy sync endpoints", func() {
				var output [2]chan *proto.ToDataplane

				BeforeEach(func() {
					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						d := types.WorkloadEndpointIDToProto(testId(w))
						output[i], _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, w, uint64(i))

						// Ensure the joins are completed by sending a workload endpoint for each.
						updates <- &proto.WorkloadEndpointUpdate{
							Id:       d,
							Endpoint: &proto.WorkloadEndpoint{},
						}
						<-output[i]
					}
				})

				It("should forward updates to both endpoints", func() {
					updateNamespace("t23")
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceUpdate{
							NamespaceUpdate: &proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "t23"}},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceUpdate{
							NamespaceUpdate: &proto.NamespaceUpdate{Id: &proto.NamespaceID{Name: "t23"}},
						},
					})).To(BeTrue())
				})

				It("should forward removes to both endpoints", func() {
					removeNamespace("t23")
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceRemove{
							NamespaceRemove: &proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "t23"}},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_NamespaceRemove{
							NamespaceRemove: &proto.NamespaceRemove{Id: &proto.NamespaceID{Name: "t23"}},
						},
					})).To(BeTrue())
				})
			})
		})

		Describe("IP Set updates", func() {
			Context("with two joined endpoints, one with active profile", func() {
				var refdOutput chan *proto.ToDataplane
				var unrefdOutput chan *proto.ToDataplane
				var refdId types.WorkloadEndpointID
				var unrefdId types.WorkloadEndpointID
				var assertInactiveNoUpdate func()
				var proUpd *proto.ActiveProfileUpdate
				var ipSetUpd *proto.IPSetUpdate

				BeforeEach(func(done Done) {
					refdId = testId("refd")
					refdOutput, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "refd", 1)
					unrefdId = testId("unrefd")
					unrefdOutput, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "unrefd", 2)

					// Ensure the joins are completed by sending a workload endpoint for each.
					refUpd := &proto.WorkloadEndpointUpdate{
						Id:       types.WorkloadEndpointIDToProto(refdId),
						Endpoint: &proto.WorkloadEndpoint{},
					}
					updates <- refUpd
					g := <-refdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), refUpd)).To(BeTrue())
					unrefUpd := &proto.WorkloadEndpointUpdate{
						Id:       types.WorkloadEndpointIDToProto(unrefdId),
						Endpoint: &proto.WorkloadEndpoint{},
					}
					updates <- unrefUpd
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), unrefUpd)).To(BeTrue())

					// Send the IPSet, a Profile referring to it, and a WEP update referring to the
					// Profile. This "activates" the WEP relative to the IPSet
					ipSetUpd = updateIpSet(IPSetName, 0)
					updates <- ipSetUpd
					proUpd = &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{InboundRules: []*proto.Rule{
							{
								Action:      "allow",
								SrcIpSetIds: []string{IPSetName},
							},
						}},
					}
					updates <- proUpd
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id:       types.WorkloadEndpointIDToProto(refdId),
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					updates <- wepUpd
					// All three updates get pushed to the active endpoint (1)
					g = <-refdOutput
					Expect(googleproto.Equal(g.GetIpsetUpdate(), ipSetUpd)).To(BeTrue())
					g = <-refdOutput
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpd)).To(BeTrue())
					g = <-refdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					assertInactiveNoUpdate = func() {
						// Send a WEP update for the inactive and check we get it from the output
						// channel. This ensures that the inactive endpoint didn't get the IPSetUpdate
						// without having to wait for a timeout.
						u := &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(unrefdId),
							Endpoint: &proto.WorkloadEndpoint{},
						}
						updates <- u
						g := <-unrefdOutput
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), u)).To(BeTrue())
					}

					close(done)
				})

				It("should send IPSetUpdate to only to ref'd endpoint", func(done Done) {
					msg := updateIpSet(IPSetName, 2)
					updates <- msg
					g := <-refdOutput
					Expect(googleproto.Equal(g, &proto.ToDataplane{Payload: &proto.ToDataplane_IpsetUpdate{IpsetUpdate: msg}})).To(BeTrue())

					assertInactiveNoUpdate()
					close(done)
				})

				It("should send IPSetDeltaUpdate to ref'd endpoint", func(done Done) {
					// Try combinations of adds, removes, and both to ensure the splitting logic
					// doesn't split these up strangely.

					msg2 := deltaUpdateIpSet(IPSetName, 2, 2)
					updates <- msg2
					g := <-refdOutput
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_IpsetDeltaUpdate{IpsetDeltaUpdate: msg2},
					})).To(BeTrue())

					msg2 = deltaUpdateIpSet(IPSetName, 2, 0)
					updates <- msg2
					g = <-refdOutput
					// Split these tests to separate expects for add and delete so that
					// we don't distinguish nil vs [] for empty lists.
					Expect(g.GetIpsetDeltaUpdate().GetAddedMembers()).To(Equal(msg2.AddedMembers))
					Expect(g.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

					msg2 = deltaUpdateIpSet(IPSetName, 0, 2)
					updates <- msg2
					g = <-refdOutput
					// Split these tests to separate expects for add and delete so that
					// we don't distinguish nil vs [] for empty lists.
					Expect(g.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
					Expect(g.GetIpsetDeltaUpdate().GetRemovedMembers()).To(Equal(msg2.RemovedMembers))

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetUpdate when endpoint newly refs wep update", func(done Done) {
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id:       types.WorkloadEndpointIDToProto(unrefdId),
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					updates <- wepUpd
					g := <-unrefdOutput
					Expect(googleproto.Equal(g.GetIpsetUpdate(), ipSetUpd)).To(BeTrue())

					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpd)).To(BeTrue())

					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					close(done)
				})

				It("should send IPSetRemove when endpoint stops ref wep update", func(done Done) {
					wepUpd := &proto.WorkloadEndpointUpdate{
						Id:       types.WorkloadEndpointIDToProto(refdId),
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
					}
					updates <- wepUpd
					g := <-refdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())
					g = <-refdOutput
					Expect(googleproto.Equal(
						g.GetActiveProfileRemove(), &proto.ActiveProfileRemove{Id: &proto.ProfileID{Name: ProfileName}},
					)).To(BeTrue())
					g = <-refdOutput
					Expect(googleproto.Equal(g.GetIpsetRemove(), &proto.IPSetRemove{Id: IPSetName})).To(BeTrue())

					// Remove the IPSet since nothing references it.
					updates <- removeIpSet(IPSetName)

					// Send & receive a repeat WEPUpdate to ensure we didn't get a second remove.
					updates <- wepUpd
					g = <-refdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					assertInactiveNoUpdate()
					close(done)
				})

				It("should send IPSetUpdate when endpoint newly refs profile update", func(done Done) {
					newSetName := "new-set"
					updates <- updateIpSet(newSetName, 6)
					pu := &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName, newSetName}},
							},
						},
					}
					updates <- pu

					// We should get the IPSetUpdate first, then the Profile that newly references it.
					g := <-refdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(6))

					g = <-refdOutput
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), pu)).To(BeTrue())

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetRemove when endpoint stops ref profile update", func(done Done) {
					pu := &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}
					updates <- pu

					// We should get ActiveProfileUpdate first, then IPSetRemove.
					g := <-refdOutput
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), pu)).To(BeTrue())
					g = <-refdOutput
					Expect(googleproto.Equal(g.GetIpsetRemove(), &proto.IPSetRemove{Id: IPSetName})).To(BeTrue())

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send Update & remove profile update changes IPSet", func(done Done) {
					newSetName := "new-set"
					updates <- updateIpSet(newSetName, 6)
					pu := &proto.ActiveProfileUpdate{
						Id: &proto.ProfileID{Name: ProfileName},
						Profile: &proto.Profile{
							InboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{newSetName}},
							},
						},
					}
					updates <- pu

					// We should get the IPSetUpdate first, then the Profile that newly references it.
					g := <-refdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(6))

					g = <-refdOutput
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), pu)).To(BeTrue())

					// Lastly, it should clean up the no-longer referenced set.
					g = <-refdOutput
					Expect(googleproto.Equal(g.GetIpsetRemove(), &proto.IPSetRemove{Id: IPSetName})).To(BeTrue())

					assertInactiveNoUpdate()

					close(done)
				})

				It("should send IPSetUpdate/Remove when endpoint newly refs policy update", func(done Done) {
					// Create the policy without the ref, and link it to the unref'd WEP.
					policyID := &proto.PolicyID{Name: "testpolicy", Kind: v3.KindGlobalNetworkPolicy}
					tier := "tier0"
					pu := &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							Tier: tier,
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}
					updates <- pu
					wepu := &proto.WorkloadEndpointUpdate{
						Id: types.WorkloadEndpointIDToProto(unrefdId),
						Endpoint: &proto.WorkloadEndpoint{
							Tiers: []*proto.TierInfo{
								{
									Name:            tier,
									IngressPolicies: []*proto.PolicyID{policyID},
								},
							},
						},
					}
					updates <- wepu
					g := <-unrefdOutput
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), pu)).To(BeTrue())
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepu)).To(BeTrue())

					// Now the WEP has an active policy that doesn't reference the IPSet. Send in
					// a Policy update that references the IPSet.
					pu = &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							Tier: tier,
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName}},
							},
						},
					}
					updates <- pu

					// Should get IPSetUpdate, followed by Policy update
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetIpsetUpdate(), ipSetUpd)).To(BeTrue())
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), pu)).To(BeTrue())

					// Now, remove the ref and get an IPSetRemove
					pu = &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							Tier: tier,
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{}},
							},
						},
					}
					updates <- pu

					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), pu)).To(BeTrue())
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetIpsetRemove(), &proto.IPSetRemove{Id: IPSetName})).To(BeTrue())
					close(done)
				})

				It("should send IPSetUpdate/Remove when policy changes IPset", func(done Done) {
					// Create policy referencing the existing IPSet and link to the unreferenced WEP
					policyID := &proto.PolicyID{Name: "testpolicy", Kind: v3.KindGlobalNetworkPolicy}
					tier := "tier0"
					pu := &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							Tier: tier,
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{IPSetName}},
							},
						},
					}
					updates <- pu
					wepu := &proto.WorkloadEndpointUpdate{
						Id: types.WorkloadEndpointIDToProto(unrefdId),
						Endpoint: &proto.WorkloadEndpoint{
							Tiers: []*proto.TierInfo{
								{
									Name:            tier,
									IngressPolicies: []*proto.PolicyID{policyID},
								},
							},
						},
					}
					updates <- wepu
					g := <-unrefdOutput
					Expect(googleproto.Equal(g.GetIpsetUpdate(), ipSetUpd)).To(BeTrue())
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), pu)).To(BeTrue())
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepu)).To(BeTrue())

					// Now the WEP has an active policy that references the old IPSet.  Create the new IPset and
					// then point the policy to it.
					newSetName := "new-set"
					updates <- updateIpSet(newSetName, 6)
					pu = &proto.ActivePolicyUpdate{
						Id: policyID,
						Policy: &proto.Policy{
							Tier: tier,
							OutboundRules: []*proto.Rule{
								{Action: "allow", SrcIpSetIds: []string{newSetName}},
							},
						},
					}
					updates <- pu

					// Should get IPSetUpdate, followed by Policy update, followed by remove of old IPSet.
					g = <-unrefdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(6))
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), pu)).To(BeTrue())
					g = <-unrefdOutput
					Expect(googleproto.Equal(g.GetIpsetRemove(), &proto.IPSetRemove{Id: IPSetName})).To(BeTrue())

					// Updates of new IPSet should be sent to the endpoint.
					updates <- updateIpSet(newSetName, 12)
					g = <-unrefdOutput
					Expect(g.GetIpsetUpdate().GetId()).To(Equal(newSetName))
					Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(12))

					close(done)
				})
			})

			Context("with SyncServer", func() {
				var syncServer *policysync.Server
				var gRPCServer *grpc.Server
				var listener net.Listener
				var socketDir string

				BeforeEach(func() {
					uidAllocator := policysync.NewUIDAllocator()
					syncServer = policysync.NewServer(uut.JoinUpdates, nil, uidAllocator.NextUID)

					gRPCServer = grpc.NewServer(grpc.Creds(testCreds{}))
					proto.RegisterPolicySyncServer(gRPCServer, syncServer)
					socketDir = makeTmpListenerDir()
					listener = openListener(socketDir)
					go func() {
						defer GinkgoRecover()
						err := gRPCServer.Serve(listener)

						// When we close down the listener, the server will return an error that it is closed. This is
						// expected behavior.
						Expect(err).To(BeAssignableToTypeOf(&net.OpError{}))
						opErr, ok := err.(*net.OpError)
						Expect(ok).To(BeTrue())
						Expect(opErr.Err.Error()).To(Equal("use of closed network connection"))
					}()
				})

				AfterEach(func() {
					listener.Close()
					os.RemoveAll(socketDir)
				})

				Context("with joined, active policy sync endpoint", func() {
					var wepId types.WorkloadEndpointID
					var syncClient proto.PolicySyncClient
					var clientConn *grpc.ClientConn
					var syncContext context.Context
					var clientCancel func()
					var syncStream proto.PolicySync_SyncClient

					BeforeEach(func(done Done) {
						wepId = testId("default/withsync")

						opts := getDialOptions()
						var err error
						clientConn, err = grpc.NewClient(path.Join(socketDir, ListenerSocket), opts...)
						Expect(err).ToNot(HaveOccurred())

						syncClient = proto.NewPolicySyncClient(clientConn)
						syncContext, clientCancel = context.WithCancel(context.Background())
						syncStream, err = syncClient.Sync(syncContext, &proto.SyncRequest{})
						Expect(err).ToNot(HaveOccurred())

						// Send the IPSet, a Profile referring to it, and a WEP update referring to the
						// Profile. This "activates" the WEP relative to the IPSet
						updates <- updateIpSet(IPSetName, 0)
						pu := &proto.ActiveProfileUpdate{
							Id: &proto.ProfileID{Name: ProfileName},
							Profile: &proto.Profile{InboundRules: []*proto.Rule{
								{
									Action:      "allow",
									SrcIpSetIds: []string{IPSetName},
								},
							}},
						}
						updates <- pu
						wepUpd := &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(wepId),
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
						}
						updates <- wepUpd
						// All three updates get pushed
						var g *proto.ToDataplane
						g, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(g.GetIpsetUpdate().GetId()).To(Equal(IPSetName))
						Expect(g.GetIpsetUpdate().GetMembers()).To(HaveLen(0))
						g, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(googleproto.Equal(g.GetActiveProfileUpdate(), pu)).To(BeTrue())
						g, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

						close(done)
					}, 2)

					It("should split large IPSetUpdate", func(done Done) {
						msg := updateIpSet(IPSetName, 82250)
						By("sending a large IPSetUpdate")
						updates <- msg

						By("receiving the first part")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetUpdate().GetMembers()).To(HaveLen(82200))

						By("receiving the second part")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(50))
						close(done)
					}, 5)

					It("should split IpSetDeltaUpdates with both large adds and removes", func(done Done) {
						msg2 := deltaUpdateIpSet(IPSetName, 82250, 82250)
						By("sending a large IPSetDeltaUpdate")
						updates <- msg2

						By("receiving the first part with added members")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(82200))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

						By("receiving the second part with added and removed members")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(50))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(50))

						By("receiving the third part with removed members")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(82200))

						close(done)
					}, 5)

					It("should split IpSetDeltaUpdates with large adds", func(done Done) {
						msg2 := deltaUpdateIpSet(IPSetName, 82250, 0)
						By("sending a large IPSetDeltaUpdate")
						updates <- msg2

						By("receiving the first part")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(82200))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

						By("receiving the second part")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(50))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(0))

						close(done)
					}, 5)

					It("should split IpSetDeltaUpdates with large removes", func(done Done) {
						msg2 := deltaUpdateIpSet(IPSetName, 0, 82250)
						By("sending a large IPSetDeltaUpdate")
						updates <- msg2

						By("receiving the first part")
						out, err := syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(50))

						By("receiving the second part")
						out, err = syncStream.Recv()
						Expect(err).ToNot(HaveOccurred())
						Expect(out.GetIpsetDeltaUpdate().GetAddedMembers()).To(HaveLen(0))
						Expect(out.GetIpsetDeltaUpdate().GetRemovedMembers()).To(HaveLen(82200))

						close(done)
					}, 5)

					AfterEach(func() {
						clientCancel()
						clientConn.Close()
					})
				})
			})

			Context("on new route sync join", func() {
				var output chan *proto.ToDataplane

				BeforeEach(func() {
					output, _ = join(&proto.SyncRequest{SubscriptionType: "l3-routes"}, "test", 1)
				})

				It("should get no updates", func() {
					Expect(len(output)).To(BeZero())
				})

				It("should not pass updates", func() {
					updates <- updateIpSet(IPSetName, 6)
					Expect(len(output)).To(BeZero())
				})

				It("should not pass delta updates", func() {
					updates <- deltaUpdateIpSet(IPSetName, 3, 2)
					Expect(len(output)).To(BeZero())
				})

				It("should not pass removes", func() {
					updates <- removeIpSet(IPSetName)
					Expect(len(output)).To(BeZero())
				})
			})
		})

		Describe("Profile & Policy updates", func() {
			Context("with two joined endpoints", func() {
				var output [2]chan *proto.ToDataplane
				var wepID [2]types.WorkloadEndpointID
				var assertNoUpdate func(i int)

				BeforeEach(func() {
					assertNoUpdate = func(i int) {
						wepu := &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(wepID[i]),
							Endpoint: &proto.WorkloadEndpoint{},
						}
						updates <- wepu
						g := <-output[i]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepu)).To(BeTrue())
					}

					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						wepID[i] = testId(w)
						output[i], _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, w, uint64(i))

						// Ensure the joins are completed by sending a workload endpoint for each.
						assertNoUpdate(i)
					}
				})

				Context("with active profile", func() {
					profileID := proto.ProfileID{Name: ProfileName}
					var proUpdate *proto.ActiveProfileUpdate

					BeforeEach(func() {
						proUpdate = &proto.ActiveProfileUpdate{
							Id: &profileID,
						}
						updates <- proUpdate
					})

					It("should add & remove profile when ref'd or not by WEP", func(done Done) {
						msg := &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
						}
						updates <- msg
						g := <-output[0]
						Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpdate)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg)).To(BeTrue())

						// Remove reference
						msg = &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
						}
						updates <- msg

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg)).To(BeTrue())
						g = <-output[0]
						Expect(googleproto.Equal(g.GetActiveProfileRemove(), &proto.ActiveProfileRemove{Id: &profileID})).To(BeTrue())

						assertNoUpdate(1)

						// Calc graph removes the profile, but we should not get another Remove.
						updates <- &proto.ActiveProfileRemove{Id: &profileID}

						// Test that there isn't a remove waiting by repeating the WEP update and getting it.
						updates <- msg
						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg)).To(BeTrue())

						close(done)
					})

					It("should add new & remove old when ref changes", func(done Done) {
						// Add new profile
						newName := "new-profile-name"
						newProfileID := proto.ProfileID{Name: newName}
						msg := &proto.ActiveProfileUpdate{Id: &newProfileID}
						updates <- msg

						msg2 := &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
						}
						updates <- msg2
						g := <-output[0]
						Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpdate)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg2)).To(BeTrue())

						// Switch profiles
						msg2 = &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{newName}},
						}
						updates <- msg2

						g = <-output[0]
						Expect(googleproto.Equal(g.GetActiveProfileUpdate(), msg)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg2)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetActiveProfileRemove(), &proto.ActiveProfileRemove{Id: &profileID})).To(BeTrue())

						assertNoUpdate(1)

						// Calc graph removes old profile, but we should not get another remove.
						updates <- &proto.ActiveProfileRemove{Id: &profileID}

						// Test that there isn't a remove queued by sending a WEP update
						updates <- msg2
						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg2)).To(BeTrue())

						close(done)
					})
				})

				Context("with active policy", func() {
					policyID := proto.PolicyID{Name: PolicyName, Kind: v3.KindGlobalNetworkPolicy}
					var polUpd *proto.ActivePolicyUpdate

					BeforeEach(func() {
						polUpd = &proto.ActivePolicyUpdate{
							Id: &policyID,
						}
						updates <- polUpd
					})

					It("should add & remove policy when ref'd or not by WEP", func(done Done) {
						msg := &proto.WorkloadEndpointUpdate{
							Id: types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name:            TierName,
									IngressPolicies: []*proto.PolicyID{&policyID},
								},
							}},
						}
						updates <- msg
						g := <-output[0]
						Expect(googleproto.Equal(g.GetActivePolicyUpdate(), polUpd)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg)).To(BeTrue())

						// Remove reference
						msg = &proto.WorkloadEndpointUpdate{
							Id: types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name: TierName,
								},
							}},
						}
						updates <- msg

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg)).To(BeTrue())
						g = <-output[0]
						Expect(googleproto.Equal(g.GetActivePolicyRemove(), &proto.ActivePolicyRemove{Id: &policyID})).To(BeTrue())

						assertNoUpdate(1)

						// Calc graph removes the policy.
						updates <- &proto.ActivePolicyRemove{Id: &policyID}

						// Test we don't get another remove by sending another WEP update
						updates <- msg
						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg)).To(BeTrue())

						close(done)
					})

					It("should add new & remove old when ref changes", func(done Done) {
						// Add new policy
						newName := "new-policy-name"
						newPolicyID := proto.PolicyID{Name: newName, Kind: v3.KindGlobalNetworkPolicy}
						msg := &proto.ActivePolicyUpdate{Id: &newPolicyID}
						updates <- msg

						msg2 := &proto.WorkloadEndpointUpdate{
							Id: types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name:           TierName,
									EgressPolicies: []*proto.PolicyID{&policyID},
								},
							}},
						}
						updates <- msg2
						g := <-output[0]
						Expect(googleproto.Equal(g.GetActivePolicyUpdate(), polUpd)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg2)).To(BeTrue())

						// Switch profiles
						msg2 = &proto.WorkloadEndpointUpdate{
							Id: types.WorkloadEndpointIDToProto(wepID[0]),
							Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
								{
									Name:           TierName,
									EgressPolicies: []*proto.PolicyID{&newPolicyID},
								},
							}},
						}
						updates <- msg2

						g = <-output[0]
						Expect(googleproto.Equal(g.GetActivePolicyUpdate(), msg)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg2)).To(BeTrue())

						g = <-output[0]
						Expect(googleproto.Equal(g.GetActivePolicyRemove(), &proto.ActivePolicyRemove{Id: &policyID})).To(BeTrue())

						// Calc graph removes the old policy.
						updates <- &proto.ActivePolicyRemove{Id: &policyID}

						// Test we don't get another remove by sending another WEP update
						updates <- msg2
						g = <-output[0]
						Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), msg2)).To(BeTrue())

						close(done)
					})
				})
			})

			Context("with profile & wep added before joining", func() {
				profileID := proto.ProfileID{Name: ProfileName}
				wepId := testId("test")
				var wepUpd *proto.WorkloadEndpointUpdate
				var proUpdate *proto.ActiveProfileUpdate

				BeforeEach(func() {
					proUpdate = &proto.ActiveProfileUpdate{
						Id: &profileID,
					}
					wepUpd = &proto.WorkloadEndpointUpdate{
						Id:       types.WorkloadEndpointIDToProto(wepId),
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{ProfileName}},
					}
					updates <- proUpdate
					updates <- wepUpd
				})

				It("should sync profile & wep when wep joins", func(done Done) {
					output, _ := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)

					g := <-output
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpdate)).To(BeTrue())

					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					close(done)
				})

				It("should resync profile & wep", func(done Done) {
					output, jm := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
					g := <-output
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpdate)).To(BeTrue())
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					// Leave
					leave(jm)

					output, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 2)
					g = <-output
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpdate)).To(BeTrue())
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					close(done)
				})

				It("should not resync removed profile", func(done Done) {
					output, jm := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
					g := <-output
					Expect(googleproto.Equal(g.GetActiveProfileUpdate(), proUpdate)).To(BeTrue())
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					// Leave
					leave(jm)

					// Remove reference to profile from WEP
					wepUpd2 := &proto.WorkloadEndpointUpdate{
						Id:       types.WorkloadEndpointIDToProto(wepId),
						Endpoint: &proto.WorkloadEndpoint{ProfileIds: []string{}},
					}
					updates <- wepUpd2

					output, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 2)
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd2)).To(BeTrue())

					close(done)
				})
			})

			Context("with policy & wep added before joining", func() {
				policyID := proto.PolicyID{Name: PolicyName, Kind: v3.KindGlobalNetworkPolicy}
				wepId := testId("test")
				var wepUpd *proto.WorkloadEndpointUpdate
				var polUpd *proto.ActivePolicyUpdate

				BeforeEach(func() {
					polUpd = &proto.ActivePolicyUpdate{
						Id: &policyID,
					}
					updates <- polUpd
					wepUpd = &proto.WorkloadEndpointUpdate{
						Id: types.WorkloadEndpointIDToProto(wepId),
						Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
							{
								Name:           TierName,
								EgressPolicies: []*proto.PolicyID{&policyID},
							},
						}},
					}
					updates <- wepUpd
				})

				It("should sync policy & wep when wep joins", func(done Done) {
					output, _ := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)

					g := <-output
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), polUpd)).To(BeTrue())

					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					close(done)
				})

				It("should resync policy & wep", func(done Done) {
					output, jm := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
					g := <-output
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), polUpd)).To(BeTrue())
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					// Leave
					leave(jm)

					output, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 2)
					g = <-output
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), polUpd)).To(BeTrue())
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					close(done)
				})

				It("should not resync removed policy", func(done Done) {
					output, jm := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
					g := <-output
					Expect(googleproto.Equal(g.GetActivePolicyUpdate(), polUpd)).To(BeTrue())
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					// Leave
					leave(jm)

					// Remove reference to policy from WEP
					wepUpd2 := &proto.WorkloadEndpointUpdate{
						Id: types.WorkloadEndpointIDToProto(wepId),
					}
					updates <- wepUpd2

					output, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 2)
					g = <-output
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd2)).To(BeTrue())

					close(done)
				})
			})

			Context("on new route sync join", func() {
				var output chan *proto.ToDataplane
				wepId := testId("test")
				policyID := proto.PolicyID{Name: PolicyName, Kind: v3.KindGlobalNetworkPolicy}
				profileID := proto.ProfileID{Name: ProfileName}
				var wepUpd *proto.WorkloadEndpointUpdate
				var polUpd *proto.ActivePolicyUpdate
				var proUpdate *proto.ActiveProfileUpdate

				BeforeEach(func() {
					polUpd = &proto.ActivePolicyUpdate{Id: &policyID}
					updates <- polUpd
					wepUpd = &proto.WorkloadEndpointUpdate{
						Id: types.WorkloadEndpointIDToProto(wepId),
						Endpoint: &proto.WorkloadEndpoint{Tiers: []*proto.TierInfo{
							{
								Name:           TierName,
								EgressPolicies: []*proto.PolicyID{&policyID},
							},
						}},
					}
					updates <- wepUpd
					proUpdate = &proto.ActiveProfileUpdate{
						Id: &profileID,
					}
					updates <- proUpdate

					output, _ = join(&proto.SyncRequest{SubscriptionType: "l3-routes"}, "test", 1)
				})

				It("should get no updates", func() {
					Expect(len(output)).To(BeZero())
				})

				It("should not pass updates", func() {
					updates <- &proto.ActivePolicyUpdate{
						Id: &proto.PolicyID{Name: "new-policy", Kind: v3.KindGlobalNetworkPolicy},
					}
					Expect(len(output)).To(BeZero())
				})

				It("should not pass removes", func() {
					updates <- &proto.ActivePolicyRemove{
						Id: &proto.PolicyID{Name: "new-policy", Kind: v3.KindGlobalNetworkPolicy},
					}
					Expect(len(output)).To(BeZero())
				})
			})
		})

		Describe("Route update/remove", func() {
			Context("updates before any join", func() {
				BeforeEach(func() {
					// Add, delete, re-add
					updateRoute("172.0.2.1/32", "node1", "172.0.1.1")
					removeRoute("172.0.2.1/32")
					updateRoute("172.0.2.1/32", "node1", "172.0.1.1")

					// Some simple adds
					updateRoute("172.0.2.2/32", "node2", "172.0.1.2")
					updateRoute("172.0.2.3/32", "node3", "172.0.1.3")

					// Add, delete
					updateRoute("172.0.2.4/32", "node4", "172.0.1.4")
					removeRoute("172.0.2.4/32")
				})

				Context("on new route sync join", func() {
					var output chan *proto.ToDataplane
					var routes [3]*proto.RouteUpdate

					BeforeEach(func() {
						output, _ = join(&proto.SyncRequest{SubscriptionType: "l3-routes"}, "test", 1)
						for i := 0; i < 3; i++ {
							msg := <-output
							routes[i] = msg.GetRouteUpdate()
						}
					})

					It("should get 3 updates", func() {
						expectedRouteUpdates := []*proto.RouteUpdate{
							{
								Types:       proto.RouteType_REMOTE_WORKLOAD,
								IpPoolType:  proto.IPPoolType_NONE,
								Dst:         "172.0.2.1/32",
								DstNodeName: "node1",
								DstNodeIp:   "172.0.1.1",
							},
							{
								Types:       proto.RouteType_REMOTE_WORKLOAD,
								IpPoolType:  proto.IPPoolType_NONE,
								Dst:         "172.0.2.2/32",
								DstNodeName: "node2",
								DstNodeIp:   "172.0.1.2",
							},
							{
								Types:       proto.RouteType_REMOTE_WORKLOAD,
								IpPoolType:  proto.IPPoolType_NONE,
								Dst:         "172.0.2.3/32",
								DstNodeName: "node3",
								DstNodeIp:   "172.0.1.3",
							},
						}

						for _, expected := range expectedRouteUpdates {
							found := false
							for _, r := range routes {
								if googleproto.Equal(r, expected) {
									found = true
									break
								}
							}
							Expect(found).To(BeTrue())
						}
					})

					It("should pass updates", func() {
						updateRoute("172.0.2.4/32", "node4", "172.0.1.4")
						msg := <-output
						expectedRouteUpdate := &proto.RouteUpdate{
							Types:       proto.RouteType_REMOTE_WORKLOAD,
							IpPoolType:  proto.IPPoolType_NONE,
							Dst:         "172.0.2.4/32",
							DstNodeName: "node4",
							DstNodeIp:   "172.0.1.4",
						}
						Expect(googleproto.Equal(msg.GetRouteUpdate(), expectedRouteUpdate)).To(BeTrue())
					})

					It("should pass removes", func() {
						removeRoute("172.0.2.4/32")
						msg := <-output
						expectedRouteRemove := &proto.RouteRemove{Dst: "172.0.2.4/32"}
						Expect(googleproto.Equal(msg.GetRouteRemove(), expectedRouteRemove)).To(BeTrue())
					})
				})

				Context("on new policy sync join", func() {
					var output chan *proto.ToDataplane

					BeforeEach(func() {
						output, _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
					})

					It("should get no updates", func() {
						Expect(len(output)).To(BeZero())
					})

					It("should not pass updates", func() {
						updateRoute("172.0.2.5/32", "node5", "172.0.1.5")
						Expect(len(output)).To(BeZero())
					})

					It("should not pass removes", func() {
						removeRoute("172.0.2.5/32")
						Expect(len(output)).To(BeZero())
					})
				})
			})

			Context("with two joined policy sync endpoints", func() {
				var output [2]chan *proto.ToDataplane

				BeforeEach(func() {
					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						d := testId(w)
						output[i], _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, w, uint64(i))

						// Ensure the joins are completed by sending a workload endpoint for each.
						updates <- &proto.WorkloadEndpointUpdate{
							Id:       types.WorkloadEndpointIDToProto(d),
							Endpoint: &proto.WorkloadEndpoint{},
						}
						<-output[i]
					}
				})

				It("should forward updates to both endpoints", func() {
					updateServiceAccount("t23", "t2")
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
				})

				It("should forward removes to both endpoints", func() {
					removeServiceAccount("t23", "t2")
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							ServiceAccountRemove: &proto.ServiceAccountRemove{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountRemove{
							ServiceAccountRemove: &proto.ServiceAccountRemove{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
				})
			})

			Context("with two joined policy sync endpoints each with different drop action override settings", func() {
				var output [2]chan *proto.ToDataplane

				BeforeEach(func() {
					sr := [2]*proto.SyncRequest{{
						SupportsDropActionOverride: true,
						SubscriptionType:           "per-pod-policies",
					}, {}}

					for i := 0; i < 2; i++ {
						w := fmt.Sprintf("test%d", i)
						output[i], _ = join(sr[i], w, uint64(i))

						// Ensure the joins are completed by sending service account updates.
						updateServiceAccount("t23", "t2")
					}
				})

				It("should forward a config update to endpoint 0 only, followed by SA updates to both endpoints", func() {
					g := <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ConfigUpdate{
							ConfigUpdate: &proto.ConfigUpdate{
								Config: map[string]string{
									"DropActionOverride": "LogAndDrop",
								},
							},
						},
					})).To(BeTrue())
					g = <-output[0]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
					g = <-output[1]
					Expect(googleproto.Equal(g, &proto.ToDataplane{
						Payload: &proto.ToDataplane_ServiceAccountUpdate{
							ServiceAccountUpdate: &proto.ServiceAccountUpdate{
								Id: &proto.ServiceAccountID{Name: "t23", Namespace: "t2"},
							},
						},
					})).To(BeTrue())
				})
			})
		})

		Describe("join / leave processing", func() {
			Context("with WEP before any join", func() {
				wepId := testId("test")
				var wepUpd *proto.WorkloadEndpointUpdate

				BeforeEach(func() {
					wepUpd = &proto.WorkloadEndpointUpdate{
						Id: types.WorkloadEndpointIDToProto(wepId),
					}
					updates <- wepUpd
				})

				It("should close old channel on new join", func(done Done) {
					oldChan, _ := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
					g := <-oldChan
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					newChan, _ := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 2)
					g = <-newChan
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					Expect(oldChan).To(BeClosed())

					close(done)
				})

				It("should ignore stale leave requests", func(done Done) {
					oldChan, oldMeta := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
					g := <-oldChan
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					newChan, _ := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 2)
					g = <-newChan
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					leave(oldMeta)

					// New channel should still be open.
					updates <- wepUpd
					g = <-newChan
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					close(done)
				})

				It("should close active connection on clean leave", func(done Done) {
					c, m := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)

					g := <-c
					Expect(googleproto.Equal(g.GetWorkloadEndpointUpdate(), wepUpd)).To(BeTrue())

					rm := &proto.WorkloadEndpointRemove{Id: types.WorkloadEndpointIDToProto(wepId)}
					updates <- rm
					g = <-c
					Expect(googleproto.Equal(g.GetWorkloadEndpointRemove(), rm)).To(BeTrue())

					leave(m)

					Eventually(c).Should(BeClosed())

					close(done)
				})
			})

			It("should handle join & leave without WEP update", func() {
				c, m := join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, "test", 1)
				leave(m)
				Eventually(c).Should(BeClosed())
			})
		})

		Describe("InSync processing", func() {
			It("should send InSync on all open outputs", func(done Done) {
				var c [2]chan *proto.ToDataplane
				for i := 0; i < 2; i++ {
					c[i], _ = join(&proto.SyncRequest{SubscriptionType: "per-pod-policies"}, fmt.Sprintf("test%d", i), uint64(i))
				}
				is := &proto.InSync{}
				updates <- is
				for i := 0; i < 2; i++ {
					g := <-c[i]
					Expect(googleproto.Equal(g.GetInSync(), is)).To(BeTrue())
				}
				close(done)
			})
		})
	})
})

var _ = DescribeTable("Config negotiation tests",
	func(req *proto.SyncRequest, configParams config.Config, expected map[string]string) {
		updates := make(chan interface{})
		uut := policysync.NewProcessor(&configParams, updates)
		uut.Start()
		join := func(sr *proto.SyncRequest, w string, jid uint64) (chan *proto.ToDataplane, policysync.JoinMetadata) {
			// Buffer outputs so that Processor won't block.
			output := make(chan *proto.ToDataplane, 100)
			joinMeta := policysync.JoinMetadata{
				EndpointID: testId(w),
				JoinUID:    jid,
			}
			jr := policysync.JoinRequest{JoinMetadata: joinMeta, SyncRequest: sr, C: output}
			uut.JoinUpdates <- jr
			return output, joinMeta
		}

		c, _ := join(req, "test", 1)
		cfg := <-c
		Expect(cfg).To(HavePayload(&proto.ConfigUpdate{Config: expected}))
	},

	Entry("Supports DropActionOverride",
		&proto.SyncRequest{SupportsDropActionOverride: true},
		config.Config{DropActionOverride: "LOGandACCEPT"},
		map[string]string{"DropActionOverride": "LOGandACCEPT"},
	),

	Entry("Supports DataplaneStats and DropActionOverride",
		&proto.SyncRequest{SupportsDataplaneStats: true, SupportsDropActionOverride: true},
		config.Config{DropActionOverride: "LOGandACCEPT"},
		map[string]string{
			"DropActionOverride":              "LOGandACCEPT",
			"DataplaneStatsEnabledForAllowed": "false",
			"DataplaneStatsEnabledForDenied":  "false",
		},
	),

	Entry("Supports DataplaneStats (FlowLogFile allowed/denied enabled, but overall disabled)",
		&proto.SyncRequest{SupportsDataplaneStats: true},
		config.Config{
			FlowLogsFileEnabled:           false,
			FlowLogsFileEnabledForAllowed: true,
			FlowLogsFileEnabledForDenied:  true,
		},
		map[string]string{
			"DataplaneStatsEnabledForAllowed": "false",
			"DataplaneStatsEnabledForDenied":  "false",
		},
	),

	Entry("Supports DataplaneStats (FlowLogFile enabled; allowed enabled, denied disabled)",
		&proto.SyncRequest{SupportsDataplaneStats: true},
		config.Config{
			FlowLogsFileEnabled:           true,
			FlowLogsFileEnabledForAllowed: true,
			FlowLogsFileEnabledForDenied:  false,
		},
		map[string]string{
			"DataplaneStatsEnabledForAllowed": "true",
			"DataplaneStatsEnabledForDenied":  "false",
		},
	),

	Entry("Supports DataplaneStats (FlowLogFile enabled; allowed disabled, denied enabled)",
		&proto.SyncRequest{SupportsDataplaneStats: true},
		config.Config{
			FlowLogsFileEnabled:           true,
			FlowLogsFileEnabledForAllowed: false,
			FlowLogsFileEnabledForDenied:  true,
		},
		map[string]string{
			"DataplaneStatsEnabledForAllowed": "false",
			"DataplaneStatsEnabledForDenied":  "true",
		},
	),
)

func testId(w string) types.WorkloadEndpointID {
	return types.WorkloadEndpointID{
		OrchestratorId: policysync.OrchestratorId,
		WorkloadId:     w,
		EndpointId:     policysync.EndpointId,
	}
}

func updateIpSet(id string, num int) *proto.IPSetUpdate {
	msg := &proto.IPSetUpdate{
		Id:      id,
		Type:    proto.IPSetUpdate_IP_AND_PORT,
		Members: []string{},
	}
	for i := 0; i < num; i++ {
		msg.Members = append(msg.Members, makeIPAndPort(i))
	}
	return msg
}

func removeIpSet(id string) *proto.IPSetRemove {
	msg := &proto.IPSetRemove{
		Id: id,
	}
	return msg
}

func deltaUpdateIpSet(id string, add, del int) *proto.IPSetDeltaUpdate {
	msg := &proto.IPSetDeltaUpdate{
		Id: id,
	}
	for i := 0; i < add; i++ {
		msg.AddedMembers = append(msg.AddedMembers, makeIPAndPort(i))
	}
	for i := add; i < add+del; i++ {
		msg.RemovedMembers = append(msg.RemovedMembers, makeIPAndPort(i))
	}
	return msg
}

func makeIPAndPort(i int) string {
	// Goal here is to make the IPSet members as long as possible when stringified.
	// assume 20 bits of variable and 108 bits of fixed prefix
	lsbHex := fmt.Sprintf("%05x", i)

	return "fe80:1111:2222:3333:4444:5555:666" + string(lsbHex[0]) + ":" + lsbHex[1:] + ",tcp:65535"
}

func getDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(getDialer("unix")),
	}
}

func getDialer(proto string) func(context.Context, string) (net.Conn, error) {
	d := &net.Dialer{}
	return func(ctx context.Context, target string) (net.Conn, error) {
		return d.DialContext(ctx, proto, target)
	}
}

const ListenerSocket = "policysync.sock"

func makeTmpListenerDir() string {
	dirPath, err := os.MkdirTemp("/tmp", "felixut")
	Expect(err).ToNot(HaveOccurred())
	return dirPath
}

func openListener(dir string) net.Listener {
	socketPath := path.Join(dir, ListenerSocket)
	lis, err := net.Listen("unix", socketPath)
	Expect(err).ToNot(HaveOccurred())
	return lis
}

type testCreds struct{}

func (t testCreds) ClientHandshake(cxt context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, binder.Credentials{}, errors.New("client handshake unsupported")
}

func (t testCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, binder.Credentials{
		Uid:            "test",
		Workload:       "withsync",
		Namespace:      "default",
		ServiceAccount: "default",
	}, nil
}

func (t testCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "felixut",
		SecurityVersion:  "test",
		ServerName:       "test",
	}
}

func (t testCreds) Clone() credentials.TransportCredentials {
	return t
}

func (t testCreds) OverrideServerName(string) error { return nil }

func HavePayload(expected interface{}) gomegatypes.GomegaMatcher {
	return &payloadMatcher{equal: Equal(expected)}
}

type payloadMatcher struct {
	equal   gomegatypes.GomegaMatcher
	payload interface{}
}

func (p *payloadMatcher) Match(actual interface{}) (success bool, err error) {
	td, ok := actual.(*proto.ToDataplane)
	if !ok {
		return false, fmt.Errorf("HasPayload expects a *proto.ToDataplane, got %v", reflect.TypeOf(actual))
	}
	p.payload = reflect.ValueOf(td.Payload).Elem().Field(0).Interface()
	return p.equal.Match(p.payload)
}

func (p *payloadMatcher) FailureMessage(actual interface{}) (message string) {
	return p.equal.FailureMessage(p.payload)
}

func (p *payloadMatcher) NegatedFailureMessage(actual interface{}) (message string) {
	return p.equal.NegatedFailureMessage(p.payload)
}
