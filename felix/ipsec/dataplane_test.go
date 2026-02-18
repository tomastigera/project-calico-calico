// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package ipsec_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/ip"
	. "github.com/projectcalico/calico/felix/ipsec"
	"github.com/projectcalico/calico/felix/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	localHostIP     = "10.0.0.1"
	localHostV4Addr = ip.FromString(localHostIP).(ip.V4Addr)
	localHostNetIP  = localHostV4Addr.AsNetIP()
	localHostCIDR   = ip.MustParseCIDROrIP(localHostIP).(ip.V4CIDR)

	localWorkloadIP   = "10.0.0.2"
	localWorkloadCIDR = ip.MustParseCIDROrIP(localWorkloadIP).(ip.V4CIDR)

	remoteHostIP     = "10.0.1.1"
	remoteHostV4Addr = ip.FromString(remoteHostIP).(ip.V4Addr)
	remoteHostCIDR   = ip.MustParseCIDROrIP(remoteHostIP).(ip.V4CIDR)

	remoteWorkloadIP   = "10.0.1.2"
	remoteWorkloadCIDR = ip.MustParseCIDROrIP(remoteWorkloadIP).(ip.V4CIDR)

	remoteWorkload2IP   = "10.0.1.3"
	remoteWorkload2CIDR = ip.MustParseCIDROrIP(remoteWorkload2IP).(ip.V4CIDR)

	// Policy selectors...

	trafficFromRemoteHostToLocalWorkload = PolicySelector{
		TrafficSrc: remoteHostCIDR,
		Dir:        netlink.XFRM_DIR_FWD,
	}
	trafficFromLocalWorkloadToRemoteHost = PolicySelector{
		TrafficDst: remoteHostCIDR,
		Mark:       0x8,
		MarkMask:   0x8,
		Dir:        netlink.XFRM_DIR_OUT,
	}

	trafficFromRemoteWorkloadToLocalWorkload = PolicySelector{
		TrafficSrc: remoteWorkloadCIDR,
		Dir:        netlink.XFRM_DIR_FWD,
	}
	trafficFromRemoteWorkloadToLocalHost = PolicySelector{
		TrafficSrc: remoteWorkloadCIDR,
		TrafficDst: localHostCIDR,
		Dir:        netlink.XFRM_DIR_IN,
	}
	trafficToRemoteWorkload = PolicySelector{
		TrafficDst: remoteWorkloadCIDR,
		Dir:        netlink.XFRM_DIR_OUT,
	}

	trafficFromRemoteWorkload2ToLocalWorkload = PolicySelector{
		TrafficSrc: remoteWorkload2CIDR,
		Dir:        netlink.XFRM_DIR_FWD,
	}
	trafficFromRemoteWorkload2ToLocalHost = PolicySelector{
		TrafficSrc: remoteWorkload2CIDR,
		TrafficDst: localHostCIDR,
		Dir:        netlink.XFRM_DIR_IN,
	}
	trafficToRemoteWorkload2 = PolicySelector{
		TrafficDst: remoteWorkload2CIDR,
		Dir:        netlink.XFRM_DIR_OUT,
	}

	// Policy rules...

	tunnelToRemote = PolicyRule{
		TunnelSrc: localHostV4Addr,
		TunnelDst: remoteHostV4Addr,
	}
	tunnelFromRemote = PolicyRule{
		TunnelSrc: remoteHostV4Addr,
		TunnelDst: localHostV4Addr,
	}
	block = PolicyRule{
		Action: netlink.XFRM_POLICY_BLOCK,
	}
)

var _ = Describe("IPsec dataplane tests with IPSecAllowUnsecuredTraffic=true", func() {
	describeIPSecDataplaneTests(true)
})

var _ = Describe("IPsec dataplane tests with IPSecAllowUnsecuredTraffic=false", func() {
	describeIPSecDataplaneTests(false)
})

func describeIPSecDataplaneTests(allowUnsecured bool) {
	var dataplane *Dataplane
	var mPolTable *mockPolicyTable
	var mIKEDaemon *mockIKEDaemon

	var totalSleep time.Duration
	var mSleep = func(d time.Duration) {
		logrus.WithField("duration", d).Info("Mock sleeping")
		totalSleep += d
	}

	newDataplane := func() *Dataplane {
		return NewDataplaneWithShims(
			localHostNetIP,
			"my-key",
			0x8,
			mPolTable,
			mIKEDaemon,
			allowUnsecured,
			mSleep,
		)
	}

	BeforeEach(func() {
		totalSleep = 0
		mPolTable = &mockPolicyTable{
			ExpectOptionalRules: allowUnsecured,
			Rules:               map[PolicySelector]*PolicyRule{},
		}
		mIKEDaemon = &mockIKEDaemon{
			Keys:       map[string]string{},
			Conns:      set.New[Conn](),
			ErrorQueue: testutils.NewErrorProducer(),
		}
		dataplane = newDataplane()
	})

	It("should load our local key at start of day", func() {
		Expect(mIKEDaemon.Keys).To(Equal(map[string]string{localHostIP: "my-key"}))
	})

	Context("with a start-of-day error", func() {
		BeforeEach(func() {
			mIKEDaemon.ErrorQueue.QueueError("LoadSharedKey")
		})

		It("should retry", func() {
			newDataplane()
			Expect(mIKEDaemon.Keys).To(Equal(map[string]string{
				localHostIP: "my-key",
			}))
			mIKEDaemon.ErrorQueue.ExpectAllErrorsConsumed()
			Expect(totalSleep).To(BeNumerically("==", 1*time.Second))
		})
	})

	Context("with a persistent start-of-day error", func() {
		BeforeEach(func() {
			mIKEDaemon.ErrorQueue.QueueNErrors("LoadSharedKey", 10)
		})

		It("should retry then panic", func() {
			Expect(func() { newDataplane() }).To(Panic())
			mIKEDaemon.ErrorQueue.ExpectAllErrorsConsumed()
			Expect(totalSleep).To(BeNumerically("==", 9*time.Second))
		})
	})

	Context("with a tunnel", func() {
		BeforeEach(func() {
			dataplane.AddTunnel(remoteHostIP)
		})

		It("should load the key for the host", func() {
			Expect(mIKEDaemon.Keys).To(Equal(map[string]string{
				localHostIP:  "my-key",
				remoteHostIP: "my-key",
			}))
		})

		expectedRulesForRemoteHost := map[PolicySelector]*PolicyRule{
			trafficFromRemoteHostToLocalWorkload: &tunnelFromRemote,
			trafficFromLocalWorkloadToRemoteHost: &tunnelToRemote,
		}

		It("should add the right rules", func() {
			Expect(mPolTable.Rules).To(Equal(expectedRulesForRemoteHost))
		})

		Context("with a binding", func() {
			BeforeEach(func() {
				dataplane.AddBinding(remoteHostIP, "10.0.1.2")
			})

			var (
				expectedRulesForRemoteWorkload = map[PolicySelector]*PolicyRule{
					trafficFromRemoteHostToLocalWorkload: &tunnelFromRemote,
					trafficFromLocalWorkloadToRemoteHost: &tunnelToRemote,

					trafficFromRemoteWorkloadToLocalWorkload: &tunnelFromRemote,
					trafficFromRemoteWorkloadToLocalHost:     &tunnelFromRemote,
					trafficToRemoteWorkload:                  &tunnelToRemote,
				}

				expectedRulesForRemoteWorkload2 = map[PolicySelector]*PolicyRule{
					trafficFromRemoteHostToLocalWorkload: &tunnelFromRemote,
					trafficFromLocalWorkloadToRemoteHost: &tunnelToRemote,

					trafficFromRemoteWorkloadToLocalWorkload: &tunnelFromRemote,
					trafficFromRemoteWorkloadToLocalHost:     &tunnelFromRemote,
					trafficToRemoteWorkload:                  &tunnelToRemote,

					trafficFromRemoteWorkload2ToLocalWorkload: &tunnelFromRemote,
					trafficFromRemoteWorkload2ToLocalHost:     &tunnelFromRemote,
					trafficToRemoteWorkload2:                  &tunnelToRemote,
				}
			)

			It("should add the right rules", func() {
				Expect(mPolTable.Rules).To(Equal(expectedRulesForRemoteWorkload))
			})

			Context("after adding a local tunnel and  binding", func() {
				BeforeEach(func() {
					dataplane.AddTunnel(localHostIP)
					dataplane.AddBinding(localHostIP, localWorkloadIP)
				})

				It("shouldn't add any new rules", func() {
					Expect(mPolTable.Rules).To(Equal(expectedRulesForRemoteWorkload))
				})

				Context("after removing the local binding", func() {
					BeforeEach(func() {
						dataplane.RemoveBinding(localHostIP, localWorkloadIP)
					})

					It("shouldn't make any changes", func() {
						Expect(mPolTable.Rules).To(Equal(expectedRulesForRemoteWorkload))
					})
				})
				Context("after removing the remote workload", func() {
					BeforeEach(func() {
						dataplane.RemoveBinding(remoteHostIP, remoteWorkloadIP)
					})

					It("should clean up", func() {
						Expect(mPolTable.Rules).To(Equal(expectedRulesForRemoteHost))
					})

					Context("after removing the remote tunnel", func() {
						BeforeEach(func() {
							dataplane.RemoveTunnel(remoteHostIP)
						})

						It("should clean up", func() {
							Expect(mPolTable.Rules).To(BeEmpty())
						})
					})
				})
			})

			Context("after adding a second remote workload", func() {
				BeforeEach(func() {
					dataplane.AddBinding(remoteHostIP, remoteWorkload2IP)
				})

				It("should add the right rules", func() {
					Expect(mPolTable.Rules).To(Equal(expectedRulesForRemoteWorkload2))
				})

				It("should not unload the key for the host", func() {
					Expect(mIKEDaemon.Keys).To(Equal(map[string]string{
						localHostIP:  "my-key",
						remoteHostIP: "my-key",
					}))
				})

				Context("after removing the second workload", func() {
					BeforeEach(func() {
						dataplane.RemoveBinding(remoteHostIP, remoteWorkload2IP)
					})

					It("should add go back to the single-workload state", func() {
						Expect(mPolTable.Rules).To(Equal(expectedRulesForRemoteWorkload))
					})

					Context("after removing the first workload and tunnel", func() {
						BeforeEach(func() {
							dataplane.RemoveBinding(remoteHostIP, "10.0.1.2")
							dataplane.RemoveTunnel(remoteHostIP)
						})

						It("should unload the key for the host", func() {
							Expect(mIKEDaemon.Keys).To(Equal(map[string]string{
								localHostIP: "my-key",
							}))
						})

						It("should remove its rules", func() {
							Expect(mPolTable.Rules).To(Equal(map[PolicySelector]*PolicyRule{}))
						})
					})
				})
			})

			Context("after removing the binding and tunnel again", func() {
				BeforeEach(func() {
					dataplane.RemoveBinding(remoteHostIP, "10.0.1.2")
					dataplane.RemoveTunnel(remoteHostIP)
				})

				It("should unload the key for the host", func() {
					Expect(mIKEDaemon.Keys).To(Equal(map[string]string{
						localHostIP: "my-key",
					}))
				})

				It("should remove its rules", func() {
					Expect(mPolTable.Rules).To(Equal(map[PolicySelector]*PolicyRule{}))
				})
			})
		})
	})

	Context("with a blacklist entry", func() {
		BeforeEach(func() {
			dataplane.AddBlacklist(remoteWorkloadIP)
		})

		if allowUnsecured {
			It("should be ignored", func() {
				Expect(mPolTable.Rules).To(BeEmpty())
			})
		} else {
			It("should add the right rules", func() {
				Expect(mPolTable.Rules).To(Equal(map[PolicySelector]*PolicyRule{
					PolicySelector{
						TrafficSrc: remoteWorkloadCIDR,
						Dir:        netlink.XFRM_DIR_IN,
					}: &block,
					PolicySelector{
						TrafficSrc: remoteWorkloadCIDR,
						Dir:        netlink.XFRM_DIR_FWD,
					}: &block,
					PolicySelector{
						TrafficDst: remoteWorkloadCIDR,
						Dir:        netlink.XFRM_DIR_OUT,
					}: &block,
					PolicySelector{
						TrafficDst: remoteWorkloadCIDR,
						Dir:        netlink.XFRM_DIR_FWD,
					}: &block,
				}))
			})
		}

		Context("with a blacklist entry removed", func() {
			BeforeEach(func() {
				dataplane.RemoveBlacklist(remoteWorkloadIP)
			})

			It("should clean up", func() {
				Expect(mPolTable.Rules).To(BeEmpty())
			})
		})
	})
}

type mockPolicyTable struct {
	ExpectOptionalRules bool
	Rules               map[PolicySelector]*PolicyRule
}

func (p *mockPolicyTable) SetRule(sel PolicySelector, rule *PolicyRule) {
	Expect(rule).NotTo(BeNil())

	// If the dataplane is in allow-unsecured mode then we expect all policies to be marked
	// optional.
	if p.ExpectOptionalRules {
		Expect(rule.Optional).To(BeTrue(),
			"dataplane programmed a non-optional rule in allow-unsecured mode")
	} else {
		Expect(rule.Optional).To(BeFalse(),
			"dataplane programmed an optional rule but allow-unsecured is false")
	}
	// However, for ease of re-using tests, we store a copy of the rules with Optional forced to false.
	ruleCopy := *rule
	ruleCopy.Optional = false

	p.Rules[sel] = &ruleCopy
}

func (p *mockPolicyTable) DeleteRule(sel PolicySelector) {
	Expect(p.Rules).To(HaveKey(sel))
	delete(p.Rules, sel)
}

type mockIKEDaemon struct {
	Keys  map[string]string
	Conns set.Set[Conn]

	ErrorQueue testutils.ErrorProducer
}

func (d *mockIKEDaemon) LoadSharedKey(remoteIP, password string) error {
	err := d.ErrorQueue.NextError("LoadSharedKey")
	if err != nil {
		return err
	}

	d.Keys[remoteIP] = password

	return nil
}

func (d *mockIKEDaemon) UnloadSharedKey(remoteIP string) error {
	err := d.ErrorQueue.NextError("UnloadSharedKey")
	if err != nil {
		return err
	}

	Expect(d.Keys).To(HaveKey(remoteIP))
	delete(d.Keys, remoteIP)

	return nil
}

func (d *mockIKEDaemon) LoadConnection(localIP, remoteIP string) error {
	err := d.ErrorQueue.NextError("LoadConnection")
	if err != nil {
		return err
	}

	d.Conns.Add(Conn{localIP, remoteIP})
	return nil
}

func (d *mockIKEDaemon) UnloadCharonConnection(localIP, remoteIP string) error {
	err := d.ErrorQueue.NextError("LoadConnection")
	if err != nil {
		return err
	}

	c := Conn{localIP, remoteIP}
	Expect(d.Conns.Contains(c)).To(BeTrue())
	d.Conns.Discard(c)
	return nil
}

type Conn struct {
	LocalIP, RemoteIP string
}
