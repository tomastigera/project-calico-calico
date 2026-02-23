// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package dnslog

import (
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

var _ = Describe("DNS log aggregator", func() {
	var l *Aggregator
	var clientEP, serverEP calc.EndpointData
	var clientIP, serverIP net.IP
	BeforeEach(func() {
		l = NewAggregator()
		clientEP = &calc.RemoteEndpointData{CommonEndpointData: calc.CalculateCommonEndpointData(model.HostEndpointKey{}, &model.HostEndpoint{})}
		serverEP = &calc.RemoteEndpointData{CommonEndpointData: calc.CalculateCommonEndpointData(model.HostEndpointKey{}, &model.HostEndpoint{})}
		clientIP = net.ParseIP("1.2.3.4")
		serverIP = net.ParseIP("8.8.8.8")
	})

	Describe("constructor", func() {
		It("initializes the dns store", func() {
			Expect(l.dnsStore).ShouldNot(BeNil())
		})
		It("sets the start time", func() {
			Expect(l.aggregationStartTime).Should(BeTemporally(">", time.Time{}))
		})
	})

	Describe("settings", func() {
		It("include labels", func() {
			Expect(l.includeLabels).Should(BeFalse())
			Expect(l.IncludeLabels(true)).Should(Equal(l))
			Expect(l.includeLabels).Should(BeTrue())
			Expect(l.IncludeLabels(false)).Should(Equal(l))
			Expect(l.includeLabels).Should(BeFalse())
		})

		It("aggregate over", func() {
			Expect(l.kind).Should(Equal(DNSDefault))
			Expect(l.AggregateOver(DNSPrefixNameAndIP)).Should(Equal(l))
			Expect(l.kind).Should(Equal(DNSPrefixNameAndIP))
			Expect(l.AggregateOver(DNSDefault)).Should(Equal(l))
			Expect(l.kind).Should(Equal(DNSDefault))
		})

		It("per-node limit", func() {
			Expect(l.perNodeLimit).Should(BeNumerically("==", 0))
			Expect(l.PerNodeLimit(579)).Should(Equal(l))
			Expect(l.perNodeLimit).Should(BeNumerically("==", 579))
		})
	})

	Describe("feed update", func() {
		BeforeEach(func() {
			err := l.FeedUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
				ResponseCode: layers.DNSResponseCodeNoErr,
				Questions: []layers.DNSQuestion{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
				},
				Answers: []layers.DNSResourceRecord{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP("127.0.0.1")},
				},
			}})

			Expect(err).ShouldNot(HaveOccurred())
			Expect(l.dnsStore).Should(HaveLen(1))
		})

		It("new entry", func() {
			err := l.FeedUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
				ResponseCode: layers.DNSResponseCodeNoErr,
				Questions: []layers.DNSQuestion{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
				},
				Answers: []layers.DNSResourceRecord{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN, IP: net.ParseIP("::1")},
				},
			}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(l.dnsStore).Should(HaveLen(2))
			for _, v := range l.dnsStore {
				Expect(v.Count).Should(BeNumerically("==", 1))
			}
		})

		It("update with same rdata", func() {
			err := l.FeedUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
				ResponseCode: layers.DNSResponseCodeNoErr,
				Questions: []layers.DNSQuestion{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
				},
				Answers: []layers.DNSResourceRecord{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP("127.0.0.1")},
				},
			}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(l.dnsStore).Should(HaveLen(1))
			for _, v := range l.dnsStore {
				Expect(v.Count).Should(BeNumerically("==", 2))
			}
		})

		It("update with different rdata", func() {
			err := l.FeedUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
				ResponseCode: layers.DNSResponseCodeNoErr,
				Questions: []layers.DNSQuestion{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
				},
				Answers: []layers.DNSResourceRecord{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP("127.0.0.2")},
				},
			}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(l.dnsStore).Should(HaveLen(2))
			for _, v := range l.dnsStore {
				Expect(v.Count).Should(BeNumerically("==", 1))
			}
		})
	})

	Describe("get", func() {
		It("empty", func() {
			Expect(l.Get()).Should(HaveLen(0))
		})

		It("updates aggregationStartTime", func() {
			startTime := l.aggregationStartTime
			l.Get()
			Expect(l.aggregationStartTime).Should(BeTemporally(">", startTime))
		})

		It("resets dnsStore", func() {
			err := l.FeedUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
				ResponseCode: layers.DNSResponseCodeNoErr,
				Questions: []layers.DNSQuestion{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
				},
				Answers: []layers.DNSResourceRecord{
					{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP("127.0.0.1")},
				},
			}})
			Expect(err).ShouldNot(HaveOccurred())
			Expect(l.dnsStore).Should(HaveLen(1))

			l.Get()
			Expect(l.dnsStore).Should(HaveLen(0))
		})

		Describe("populated", func() {
			BeforeEach(func() {
				err := l.FeedUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
					ResponseCode: layers.DNSResponseCodeNoErr,
					Questions: []layers.DNSQuestion{
						{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
					},
					Answers: []layers.DNSResourceRecord{
						{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP("127.0.0.1")},
					},
				}})
				Expect(err).ShouldNot(HaveOccurred())

				err = l.FeedUpdate(Update{ClientIP: clientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
					ResponseCode: layers.DNSResponseCodeNoErr,
					Questions: []layers.DNSQuestion{
						{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
					},
					Answers: []layers.DNSResourceRecord{
						{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP("127.0.0.2")},
					},
				}})
				Expect(err).ShouldNot(HaveOccurred())
			})

			for _, b := range []bool{false, true} {
				withLabels := b
				var logs []*v1.DNSLog

				Describe(fmt.Sprintf("withLabels: %t", withLabels), func() {
					It("sets startTime correctly", func() {
						l.IncludeLabels(withLabels)
						startTime := l.aggregationStartTime
						logs = l.Get()
						Expect(logs).Should(HaveLen(2))

						for _, log := range logs {
							Expect(log.StartTime).Should(BeTemporally("==", startTime))
						}
					})

					It("sets endTime correctly", func() {
						l.IncludeLabels(withLabels)
						logs = l.Get()
						Expect(logs).Should(HaveLen(2))

						for _, log := range logs {
							Expect(log.EndTime).Should(BeTemporally("==", l.aggregationStartTime))
						}
					})

					switch withLabels {
					case true:
						It("includes labels", func() {
							// TODO
						})
					case false:
						It("excludes labels", func() {
							l.IncludeLabels(withLabels)
							logs = l.Get()
							Expect(logs).Should(HaveLen(2))

							for _, log := range logs {
								Expect(log.ClientLabels.RecomputeOriginalMap()).Should(HaveLen(0))
								for _, server := range log.Servers {
									Expect(server.Labels.RecomputeOriginalMap()).Should(HaveLen(0))
								}
							}
						})
					}
				})
			}
		})
	})

	Describe("with per-node limit of 5", func() {
		BeforeEach(func() {
			l.PerNodeLimit(5)
		})

		It("should only buffer 5 logs", func() {
			for i := range 10 {
				uniqueClientIP := net.ParseIP(fmt.Sprintf("10.9.8.%v", i))
				err := l.FeedUpdate(Update{ClientIP: uniqueClientIP, ServerIP: serverIP, ClientEP: clientEP, ServerEP: serverEP, DNS: &layers.DNS{
					ResponseCode: layers.DNSResponseCodeNoErr,
					Questions: []layers.DNSQuestion{
						{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
					},
					Answers: []layers.DNSResourceRecord{
						{Name: []byte("tigera.io."), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP("127.0.0.1")},
					},
				}})
				Expect(err).ShouldNot(HaveOccurred())
			}
			Expect(l.dnsStore).Should(HaveLen(5))

			// l.Get() will return the 5 stored logs, plus an extra one to say
			// that there were 5 more updates that could not be fully logged.
			emitted := l.Get()
			Expect(emitted).To(HaveLen(6))
			found := false
			for _, lg := range emitted {
				if (lg.Count == 5) && (lg.Servers == nil) && (lg.RRSets == nil) {
					Expect(lg.Type).To(Equal(v1.DNSLogTypeUnlogged))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})
	})
})
