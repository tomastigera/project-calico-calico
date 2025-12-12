// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package calc_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/proto"
)

var _ = Describe("EndpointComputedData ApplyTo methods", func() {
	Describe("IstioCalculator.ApplyTo", func() {
		var (
			cie *calc.ComputedIstioEndpoint
			wep *proto.WorkloadEndpoint
		)

		BeforeEach(func() {
			cie = &calc.ComputedIstioEndpoint{}
			wep = &proto.WorkloadEndpoint{
				State:          "up",
				Name:           "test-endpoint",
				IsIstioAmbient: false,
			}
		})

		It("should set IsIstioAmbient to true", func() {
			Expect(wep.IsIstioAmbient).To(BeFalse())
			cie.ApplyTo(wep)
			Expect(wep.IsIstioAmbient).To(BeTrue())
		})

		It("should set IsIstioAmbient to true even if already true", func() {
			wep.IsIstioAmbient = true
			cie.ApplyTo(wep)
			Expect(wep.IsIstioAmbient).To(BeTrue())
		})

		It("should not modify other endpoint fields", func() {
			originalName := wep.Name
			originalState := wep.State
			cie.ApplyTo(wep)
			Expect(wep.Name).To(Equal(originalName))
			Expect(wep.State).To(Equal(originalState))
		})
	})

	Describe("ComputedEgressEP.ApplyTo", func() {
		var wep *proto.WorkloadEndpoint

		BeforeEach(func() {
			wep = &proto.WorkloadEndpoint{
				State:                   "up",
				Name:                    "test-endpoint",
				IsEgressGateway:         false,
				EgressGatewayHealthPort: 0,
				EgressGatewayRules:      nil,
			}
		})

		Context("when endpoint is an egress gateway", func() {
			It("should set IsEgressGateway to true and health port", func() {
				computed := &calc.ComputedEgressEP{
					IsEgressGateway: true,
					HealthPort:      8080,
					Rules:           []calc.EpEgressData{},
				}
				computed.ApplyTo(wep)
				Expect(wep.IsEgressGateway).To(BeTrue())
				Expect(wep.EgressGatewayHealthPort).To(Equal(int32(8080)))
				Expect(wep.EgressGatewayRules).To(BeNil())
			})

			It("should not set egress gateway rules when IsEgressGateway is true", func() {
				computed := &calc.ComputedEgressEP{
					IsEgressGateway: true,
					HealthPort:      9090,
					Rules: []calc.EpEgressData{
						{
							IpSetID:     "test-ipset",
							MaxNextHops: 2,
							CIDR:        "10.0.0.0/8",
						},
					},
				}
				computed.ApplyTo(wep)
				Expect(wep.IsEgressGateway).To(BeTrue())
				Expect(wep.EgressGatewayHealthPort).To(Equal(int32(9090)))
				Expect(wep.EgressGatewayRules).To(BeNil())
			})
		})

		Context("when endpoint is not an egress gateway", func() {
			It("should set egress gateway rules", func() {
				computed := &calc.ComputedEgressEP{
					IsEgressGateway: false,
					HealthPort:      0,
					Rules: []calc.EpEgressData{
						{
							IpSetID:     "test-ipset-1",
							MaxNextHops: 2,
							CIDR:        "10.0.0.0/8",
						},
					},
				}
				computed.ApplyTo(wep)
				Expect(wep.IsEgressGateway).To(BeFalse())
				Expect(wep.EgressGatewayHealthPort).To(Equal(int32(0)))
				Expect(wep.EgressGatewayRules).To(HaveLen(1))
				Expect(wep.EgressGatewayRules[0].IpSetId).To(Equal("test-ipset-1"))
				Expect(wep.EgressGatewayRules[0].MaxNextHops).To(Equal(int32(2)))
				Expect(wep.EgressGatewayRules[0].Destination).To(Equal("10.0.0.0/8"))
				Expect(wep.EgressGatewayRules[0].PreferLocalEgressGateway).To(BeFalse())
			})

			It("should set multiple egress gateway rules", func() {
				computed := &calc.ComputedEgressEP{
					IsEgressGateway: false,
					HealthPort:      0,
					Rules: []calc.EpEgressData{
						{
							IpSetID:     "test-ipset-1",
							MaxNextHops: 2,
							CIDR:        "10.0.0.0/8",
						},
						{
							IpSetID:       "test-ipset-2",
							MaxNextHops:   3,
							CIDR:          "192.168.0.0/16",
							PreferLocalGW: true,
						},
					},
				}
				computed.ApplyTo(wep)
				Expect(wep.IsEgressGateway).To(BeFalse())
				Expect(wep.EgressGatewayRules).To(HaveLen(2))
				Expect(wep.EgressGatewayRules[0].IpSetId).To(Equal("test-ipset-1"))
				Expect(wep.EgressGatewayRules[0].MaxNextHops).To(Equal(int32(2)))
				Expect(wep.EgressGatewayRules[0].Destination).To(Equal("10.0.0.0/8"))
				Expect(wep.EgressGatewayRules[0].PreferLocalEgressGateway).To(BeFalse())
				Expect(wep.EgressGatewayRules[1].IpSetId).To(Equal("test-ipset-2"))
				Expect(wep.EgressGatewayRules[1].MaxNextHops).To(Equal(int32(3)))
				Expect(wep.EgressGatewayRules[1].Destination).To(Equal("192.168.0.0/16"))
				Expect(wep.EgressGatewayRules[1].PreferLocalEgressGateway).To(BeTrue())
			})

			It("should handle empty rules list", func() {
				computed := &calc.ComputedEgressEP{
					IsEgressGateway: false,
					HealthPort:      0,
					Rules:           []calc.EpEgressData{},
				}
				computed.ApplyTo(wep)
				Expect(wep.IsEgressGateway).To(BeFalse())
				Expect(wep.EgressGatewayHealthPort).To(Equal(int32(0)))
				Expect(wep.EgressGatewayRules).To(BeNil())
			})

			It("should handle PreferLocalGW flag correctly", func() {
				computed := &calc.ComputedEgressEP{
					IsEgressGateway: false,
					HealthPort:      0,
					Rules: []calc.EpEgressData{
						{
							IpSetID:       "test-ipset",
							MaxNextHops:   1,
							CIDR:          "172.16.0.0/12",
							PreferLocalGW: true,
						},
					},
				}
				computed.ApplyTo(wep)
				Expect(wep.EgressGatewayRules).To(HaveLen(1))
				Expect(wep.EgressGatewayRules[0].PreferLocalEgressGateway).To(BeTrue())
			})
		})

		It("should not modify other endpoint fields", func() {
			originalName := wep.Name
			originalState := wep.State
			computed := &calc.ComputedEgressEP{
				IsEgressGateway: false,
				HealthPort:      0,
				Rules:           []calc.EpEgressData{},
			}
			computed.ApplyTo(wep)
			Expect(wep.Name).To(Equal(originalName))
			Expect(wep.State).To(Equal(originalState))
		})
	})

	Describe("Multiple ApplyTo calls", func() {
		It("should apply both Istio and Egress computed data correctly", func() {
			wep := &proto.WorkloadEndpoint{
				State:                   "up",
				Name:                    "test-endpoint",
				IsIstioAmbient:          false,
				IsEgressGateway:         false,
				EgressGatewayHealthPort: 0,
			}

			// Apply Istio computed data
			compIstioEp := &calc.ComputedIstioEndpoint{}
			compIstioEp.ApplyTo(wep)
			Expect(wep.IsIstioAmbient).To(BeTrue())

			// Apply Egress computed data
			egressComputed := &calc.ComputedEgressEP{
				IsEgressGateway: false,
				HealthPort:      0,
				Rules: []calc.EpEgressData{
					{
						IpSetID:     "test-ipset",
						MaxNextHops: 1,
						CIDR:        "10.0.0.0/8",
					},
				},
			}
			egressComputed.ApplyTo(wep)
			Expect(wep.EgressGatewayRules).To(HaveLen(1))

			// Verify both computed data are applied
			Expect(wep.IsIstioAmbient).To(BeTrue())
			Expect(wep.EgressGatewayRules[0].IpSetId).To(Equal("test-ipset"))
		})
	})
})
