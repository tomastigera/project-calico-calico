// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package dns

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector"
	config "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/testutils"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

type dnsLog struct {
	server  net.IP
	client  net.IP
	dns     *layers.DNS
	latency *time.Duration
}

type mockCollector struct {
	collector.Collector

	dnsLogs []dnsLog
}

func (m *mockCollector) LogDNS(server, client net.IP, dns *layers.DNS, latency *time.Duration) {
	m.dnsLogs = append(m.dnsLogs, dnsLog{server, client, dns, latency})
}

func (m *mockCollector) SetDomainLookup(_ collector.EgressDomainCache) {
	// no-op
}

type mockDomainInfoChangeHandler struct {
	dataplaneSyncNeeded bool
	domainsChanged      []string
}

func (m *mockDomainInfoChangeHandler) OnDomainChange(name string) (dataplaneSyncNeeded bool) {
	m.domainsChanged = append(m.domainsChanged, name)
	return m.dataplaneSyncNeeded
}

var _ = Describe("Domain Info Store", func() {
	var (
		handler             *mockDomainInfoChangeHandler
		domainStore         *DomainInfoStore
		clientIP            = cnet.MustParseIP("192.168.1.1").IP
		client1IP           = cnet.MustParseIP("192.168.1.2").IP
		client2IP           = cnet.MustParseIP("1.2.3.4").IP
		client3IP           = cnet.MustParseIP("10.10.10.99").IP
		mockDNSRecA1        = testutils.MakeA("a.com", "10.0.0.10")
		mockDNSRecA2        = testutils.MakeA("b.com", "10.0.0.20")
		mockDNSRecA2Caps    = testutils.MakeA("B.cOm", "10.0.0.20")
		mockDNSRecAAAA1     = testutils.MakeAAAA("aaaa.com", "fe80:fe11::1")
		mockDNSRecAAAA2     = testutils.MakeAAAA("bbbb.com", "fe80:fe11::2")
		mockDNSRecAAAA3Caps = testutils.MakeAAAA("mIxEdCaSe.CoM", "fe80:fe11::3")
		invalidDNSRec       = layers.DNSResourceRecord{
			Name:       []byte("invalid#rec.com"),
			Type:       layers.DNSTypeMX,
			Class:      layers.DNSClassAny,
			TTL:        2147483648,
			DataLength: 0,
			Data:       []byte("999.000.999.000"),
			IP:         net.ParseIP("999.000.999.000"),
		}
		mockDNSRecCNAME = []layers.DNSResourceRecord{
			testutils.MakeCNAME("cname1.com", "cname2.com"),
			testutils.MakeCNAME("cNAME2.com", "cname3.com"),
			testutils.MakeCNAME("cname3.com", "a.com"),
		}
		mockDNSRecCNAMEUnderscore = []layers.DNSResourceRecord{
			testutils.MakeCNAME("cname_1.com", "cname2.com"),
			testutils.MakeCNAME("cNAME2.com", "cname_3.com"),
			testutils.MakeCNAME("cname_3.com", "a.com"),
		}
		lastTTL time.Duration

		// Callback indication. Tests using callbacks must emulate the dataplane by calling back into the
		// DomainInfoStore to notify when the dataplane is programmed.
		callbackIdsMutex sync.Mutex
		callbackIds      []string

		current time.Time
		expire  time.Time
	)

	BeforeEach(func() {
		// Reset the callback IDs.
		callbackIdsMutex.Lock()
		defer callbackIdsMutex.Unlock()
		callbackIds = nil

		current = time.Now()
		expire = current.Add(time.Minute)
	})

	// Program a DNS record as an "answer" type response.
	programDNSAnswer := func(clientIP string, domainStore *DomainInfoStore, dnsPacket layers.DNSResourceRecord, callbackId ...string) {
		var layerDNS layers.DNS
		layerDNS.Answers = append(layerDNS.Answers, dnsPacket)
		var cb func()
		if len(callbackId) == 1 {
			cb = func() {
				callbackIdsMutex.Lock()
				defer callbackIdsMutex.Unlock()
				callbackIds = append(callbackIds, callbackId[0])
			}
		}
		domainStore.processDNSResponsePacket(clientIP, &layerDNS, cb)
	}

	// Program a DNS record as an "additionals" type response.
	programDNSAdditionals := func(clientIP net.IP, domainStore *DomainInfoStore, dnsPacket layers.DNSResourceRecord, callbackId ...string) {
		var layerDNS layers.DNS
		layerDNS.Additionals = append(layerDNS.Additionals, dnsPacket)
		var cb func()
		if len(callbackId) == 1 {
			cb = func() {
				callbackIdsMutex.Lock()
				defer callbackIdsMutex.Unlock()
				callbackIds = append(callbackIds, callbackId[0])
			}
		}
		client := clientIP.String()
		domainStore.processDNSResponsePacket(client, &layerDNS, cb)
	}

	// Assert that the domain store accepted and signaled the given record (and reason).
	AssertDomainChanged := func(domainStore *DomainInfoStore, d string, r string) {
		Expect(domainStore.UpdatesReadyChannel()).Should(Receive())
		log.Info("Domain updates ready to handle")
		domainStore.HandleUpdates()
		// DomainInfoStore stores domains in lowercase.
		Expect(handler.domainsChanged).To(ConsistOf(strings.ToLower(d)))

		// Reset the domains changed ready for the next test.
		handler.domainsChanged = nil
	}

	// Assert that the domain store registered the given record and then process its expiration.
	AssertValidRecord := func(clientIP net.IP, dnsRec layers.DNSResourceRecord) {
		It("should result in a domain entry", func() {
			Expect(domainStore.GetDomainIPs(string(dnsRec.Name))).To(Equal([]string{dnsRec.IP.String()}))
		})
		It("should expire and signal a domain change", func() {
			client := clientIP.String()
			domainStore.processMappingExpiry(client, strings.ToLower(string(dnsRec.Name)), dnsRec.IP.String(), expire)
			AssertDomainChanged(domainStore, string(dnsRec.Name), "mapping expired")
			Expect(domainStore.collectGarbage()).To(Equal(1))
		})
	}

	defaultConfig := &DnsConfig{
		DNSCacheFile:         "/dnsinfo",
		DNSCacheSaveInterval: time.Minute,
		MaxTopLevelDomains:   5,
	}

	// Create a new datastore.
	domainStoreCreateEx := func(capacity int, config *DnsConfig) {
		// For UT purposes, don't actually run any expiry timers. We arrange that mappings
		// always appear to have expired when UT code calls processMappingExpiry by using
		// current time for all time.Now() calls and use expire time (after current) when
		// calling in to processMappingExpiry.
		domainStore = newDomainInfoStoreWithShims(
			config,
			func(ttl time.Duration, _ func()) *time.Timer {
				lastTTL = ttl
				return nil
			},
			func() time.Time { return current },
		)

		handler = &mockDomainInfoChangeHandler{
			// For most tests assume the dataplane does need to be sync'd.
			dataplaneSyncNeeded: true,
		}
		domainStore.RegisterHandler(handler)
	}
	domainStoreCreate := func() {
		// Create domain info store with 100 capacity for changes channel.
		domainStoreCreateEx(100, defaultConfig)
	}

	// Basic validation tests that add/expire one or two DNS records of A and AAAA type to the data store.
	domainStoreTestValidRec := func(dnsRec1, dnsRec2 layers.DNSResourceRecord) {
		Describe("receiving a DNS packet", func() {
			BeforeEach(func() {
				domainStoreCreate()
			})

			Context("with a valid type A DNS answer record", func() {
				BeforeEach(func() {
					programDNSAnswer(clientIP.String(), domainStore, dnsRec1)
					AssertDomainChanged(domainStore, string(dnsRec1.Name), "mapping added")
				})
				AssertValidRecord(clientIP, dnsRec1)
			})

			Context("with a valid type A DNS additional record", func() {
				BeforeEach(func() {
					programDNSAdditionals(clientIP, domainStore, dnsRec1)
					AssertDomainChanged(domainStore, string(dnsRec1.Name), "mapping added")
				})
				AssertValidRecord(clientIP, dnsRec1)
			})

			Context("with two valid type A DNS answer records", func() {
				BeforeEach(func() {
					programDNSAnswer(clientIP.String(), domainStore, dnsRec1)
					AssertDomainChanged(domainStore, string(dnsRec1.Name), "mapping added")
					programDNSAnswer(clientIP.String(), domainStore, dnsRec2)
					AssertDomainChanged(domainStore, string(dnsRec2.Name), "mapping added")
				})
				AssertValidRecord(clientIP, dnsRec1)
				AssertValidRecord(clientIP, dnsRec2)
			})

			Context("with two valid type A DNS additional records", func() {
				BeforeEach(func() {
					programDNSAdditionals(clientIP, domainStore, dnsRec1)
					AssertDomainChanged(domainStore, string(dnsRec1.Name), "mapping added")
					programDNSAdditionals(clientIP, domainStore, dnsRec2)
					AssertDomainChanged(domainStore, string(dnsRec2.Name), "mapping added")
				})
				AssertValidRecord(clientIP, dnsRec1)
				AssertValidRecord(clientIP, dnsRec2)
			})
		})
	}

	// Check that a malformed DNS record will not be accepted.
	domainStoreTestInvalidRec := func(dnsRec layers.DNSResourceRecord) {
		Context("with an invalid DNS record", func() {
			BeforeEach(func() {
				domainStoreCreate()
				programDNSAnswer(clientIP.String(), domainStore, dnsRec)
			})
			It("should return nil", func() {
				Expect(domainStore.GetDomainIPs(string(dnsRec.Name))).To(BeNil())
			})
		})
	}

	// Check that a chain of CNAME records with one A record results in a domain change only for the latter.
	domainStoreTestCNAME := func(CNAMErecs []layers.DNSResourceRecord, client string, aRec layers.DNSResourceRecord) {
		Context("with a chain of CNAME records", func() {
			BeforeEach(func() {
				// Check that we receive signals when there are updates ready.
				domainStoreCreate()
				for _, r := range CNAMErecs {
					programDNSAnswer(client, domainStore, r)
					Expect(domainStore.UpdatesReadyChannel()).Should(Receive())
					domainStore.HandleUpdates()
				}
				programDNSAnswer(client, domainStore, aRec)
				Expect(domainStore.UpdatesReadyChannel()).Should(Receive())
				domainStore.HandleUpdates()
			})
			It("should result in a CNAME->A mapping", func() {
				Expect(domainStore.GetDomainIPs(string(CNAMErecs[0].Name))).To(Equal([]string{aRec.IP.String()}))
			})
			It("should reverse lookup to the first CNAME record in the chain", func() {
				ipb, _ := ip.ParseIPAs16Byte(aRec.IP.String())
				name := strings.ToLower(string(CNAMErecs[0].Name))
				client := net.IP(clientIP[:]).String()
				Expect(domainStore.GetTopLevelDomainsForIP(client, ipb)).To(Equal([]string{name}))
			})
		})

		// CNAME records could arrive in reverse order if each of the CNAME records were requested individually and
		// in that order (not very realistic, but a good test scenario).
		Context("with a chain of CNAME records in reverse order", func() {
			var orderedNames []string
			BeforeEach(func() {
				// Check that we receive signals when there are updates ready.
				domainStoreCreate()
				orderedNames = nil
				for i := range CNAMErecs {
					programDNSAnswer(clientIP.String(), domainStore, CNAMErecs[len(CNAMErecs)-i-1])
					Expect(domainStore.UpdatesReadyChannel()).Should(Receive())
					domainStore.HandleUpdates()
					name := strings.ToLower(string(CNAMErecs[len(CNAMErecs)-i-1].Name))
					orderedNames = append([]string{name}, orderedNames...)
				}
				if len(orderedNames) > 5 {
					orderedNames = orderedNames[:5]
				}
				programDNSAnswer(clientIP.String(), domainStore, aRec)
				Expect(domainStore.UpdatesReadyChannel()).Should(Receive())
				domainStore.HandleUpdates()
			})
			It("should result in a CNAME->A mapping", func() {
				Expect(domainStore.GetDomainIPs(string(CNAMErecs[0].Name))).To(Equal([]string{aRec.IP.String()}))
			})
			It("should reverse lookup to the all CNAME records in the chain", func() {
				ipb, _ := ip.ParseIPAs16Byte(aRec.IP.String())
				Expect(domainStore.GetTopLevelDomainsForIP(clientIP.String(), ipb)).To(Equal(orderedNames))
			})
		})
	}

	domainStoreTestValidRec(mockDNSRecA1, mockDNSRecA2)
	domainStoreTestValidRec(mockDNSRecA1, mockDNSRecA2Caps)
	domainStoreTestValidRec(mockDNSRecAAAA1, mockDNSRecAAAA2)
	domainStoreTestValidRec(mockDNSRecAAAA1, mockDNSRecAAAA3Caps)
	domainStoreTestInvalidRec(invalidDNSRec)
	domainStoreTestCNAME(mockDNSRecCNAME, clientIP.String(), mockDNSRecA1)
	domainStoreTestCNAME(mockDNSRecCNAMEUnderscore, clientIP.String(), mockDNSRecA1)

	handleUpdatesAndExpectChangesFor := func(domains ...string) {
		// For a set of changes we should get a single update ready notification.
		ExpectWithOffset(1, domainStore.UpdatesReadyChannel()).To(Receive())
		ExpectWithOffset(1, domainStore.UpdatesReadyChannel()).NotTo(Receive())
		log.Debug("Updates ready to handle")

		// Handle the updates - this synchronously invokes the OnDomainChange callbacks.
		domainStore.HandleUpdates()

		// We shouldn't care if _more_ domains are signaled than we expect.  Just check that
		// the expected ones _are_ signaled.
		for _, domain := range domains {
			ExpectWithOffset(1, handler.domainsChanged).To(ContainElement(domain),
				fmt.Sprintf("Expected domain %v to be signalled but it wasn't", domain))
		}
		handler.domainsChanged = nil
	}

	// Assert that the expected callbacks have been received. This resets the callback Ids.
	expectCallbacks := func(expectedCallbackIds ...string) {
		getCallbackIds := func() []string {
			callbackIdsMutex.Lock()
			defer callbackIdsMutex.Unlock()
			if len(callbackIds) == 0 {
				return nil
			}
			callbackIdsCopy := make([]string, len(callbackIds))
			copy(callbackIdsCopy, callbackIds)
			return callbackIdsCopy
		}
		if len(expectedCallbackIds) == 0 {
			ConsistentlyWithOffset(1, getCallbackIds).Should(HaveLen(0))
		} else {
			EventuallyWithOffset(1, getCallbackIds).Should(ConsistOf(expectedCallbackIds))
			ConsistentlyWithOffset(1, getCallbackIds).Should(ConsistOf(expectedCallbackIds))
		}

		callbackIdsMutex.Lock()
		defer callbackIdsMutex.Unlock()
		ExpectWithOffset(1, callbackIds).To(ConsistOf(expectedCallbackIds))
		callbackIds = nil
	}

	Context("with two CNAME chains ending in the same A record", func() {
		var orderedNames []string
		BeforeEach(func() {
			// Check that we receive signals when there are updates ready.
			domainStoreCreate()
			orderedNames = nil
			for _, recs := range [][]layers.DNSResourceRecord{mockDNSRecCNAME, mockDNSRecCNAMEUnderscore} {
				for _, rec := range recs {
					programDNSAnswer(clientIP.String(), domainStore, rec)
				}
				name := strings.ToLower(string(recs[0].Name))
				orderedNames = append([]string{name}, orderedNames...)
				programDNSAnswer(clientIP.String(), domainStore, mockDNSRecA1)
			}
			if len(orderedNames) > 5 {
				orderedNames = orderedNames[:5]
			}
		})
		It("should reverse lookup to top of the two chains", func() {
			ipb, _ := ip.ParseIPAs16Byte(mockDNSRecA1.IP.String())
			Expect(domainStore.GetTopLevelDomainsForIP(clientIP.String(), ipb)).To(Equal(orderedNames))
		})
	})

	Context("with monitor thread", func() {
		var (
			expectedSeen      bool
			expectedDomainIPs []string
			monitorMutex      sync.Mutex
			killMonitor       chan struct{}
			monitorRunning    sync.WaitGroup
		)

		monitor := func(domain string) {
			defer monitorRunning.Done()
			for {
			loop:
				for {
					select {
					case <-killMonitor:
						return
					case <-domainStore.UpdatesReadyChannel():
						log.Debug("Updates ready to handle")
						domainStore.HandleUpdates()
						monitorMutex.Lock()
						for _, signalDomain := range handler.domainsChanged {
							if signalDomain == domain {
								expectedSeen = true
								expectedDomainIPs = domainStore.GetDomainIPs(domain)
								break
							}
						}
						monitorMutex.Unlock()
					default:
						break loop
					}
				}
			}
		}

		checkMonitor := func(expectedIPs []string) {
			Eventually(func() bool {
				monitorMutex.Lock()
				defer monitorMutex.Unlock()
				result := expectedSeen && reflect.DeepEqual(expectedDomainIPs, expectedIPs)
				if result {
					expectedSeen = false
				}
				return result
			}).Should(BeTrue())
		}

		BeforeEach(func() {
			expectedSeen = false
			killMonitor = make(chan struct{})
			domainStoreCreateEx(0, defaultConfig)
			monitorRunning.Add(1)
			go monitor("*.microsoft.com")
		})

		AfterEach(func() {
			close(killMonitor)
			monitorRunning.Wait()
		})

		It("microsoft case", func() {
			Expect(domainStore.GetDomainIPs("*.microsoft.com")).To(Equal([]string(nil)))
			programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("www.microsoft.com", "www.microsoft.com-c-3.edgekey.net"))
			checkMonitor(nil)
			programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("www.microsoft.com-c-3.edgekey.net", "www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net"))
			programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("www.microsoft.com-c-3.edgekey.net.globalredir.akadns.net", "e13678.dspb.akamaiedge.net"))
			programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("e13678.dspb.akamaiedge.net", "104.75.174.50"))
			checkMonitor([]string{"104.75.174.50"})
		})
	})

	// Test where:
	// - a1.com and a2.com are both CNAMEs for b.com
	// - b.com is a CNAME for c.com
	// - c.com resolves to an IP address
	// The ipsets manager is interested in both a1.com and a2.com.
	//
	// The key point is that when the IP address for c.com changes, the ipsets manager
	// should be notified that domain info has changed for both a1.com and a2.com.
	It("should handle a branched DNS graph", func() {
		domainStoreCreate()
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("a1.com", "b.com"))
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("a2.com", "b.com"))
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("b.com", "c.com"))
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("c.com", "3.4.5.6"))
		handleUpdatesAndExpectChangesFor("a1.com", "a2.com", "b.com", "c.com")
		Expect(domainStore.GetDomainIPs("a1.com")).To(Equal([]string{"3.4.5.6"}))
		Expect(domainStore.GetDomainIPs("a2.com")).To(Equal([]string{"3.4.5.6"}))
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("c.com", "7.8.9.10"))
		handleUpdatesAndExpectChangesFor("a1.com", "a2.com", "c.com")
		Expect(domainStore.GetDomainIPs("a1.com")).To(ConsistOf("3.4.5.6", "7.8.9.10"))
		Expect(domainStore.GetDomainIPs("a2.com")).To(ConsistOf("3.4.5.6", "7.8.9.10"))
		client := clientIP.String()
		domainStore.processMappingExpiry(client, "c.com", "3.4.5.6", expire)
		handleUpdatesAndExpectChangesFor("a1.com", "a2.com", "c.com")
		Expect(domainStore.GetDomainIPs("a1.com")).To(Equal([]string{"7.8.9.10"}))
		Expect(domainStore.GetDomainIPs("a2.com")).To(Equal([]string{"7.8.9.10"}))
		// No garbage yet, because c.com still has a value and is the RHS of other mappings.
		Expect(domainStore.collectGarbage()).To(Equal(0))
	})

	It("is not vulnerable to CNAME loops", func() {
		domainStoreCreate()
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("a.com", "b.com"))
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("b.com", "c.com"))
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("c.com", "a.com"))
		Expect(domainStore.GetDomainIPs("a.com")).To(BeEmpty())
	})

	It("0.0.0.0 is ignored", func() {
		domainStoreCreate()
		// 0.0.0.0 should be ignored.
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("a.com", "0.0.0.0"))
		Expect(domainStore.GetDomainIPs("a.com")).To(BeEmpty())
		// But not any other IP.
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("a.com", "0.0.0.1"))
		Expect(domainStore.GetDomainIPs("a.com")).To(HaveLen(1))
	})

	DescribeTable("it should identify wildcards",
		func(domain string, expectedIsWildcard bool) {
			Expect(isWildcard(domain)).To(Equal(expectedIsWildcard))
		},
		Entry("*.com",
			"*.com", true),
		Entry(".com",
			".com", false),
		Entry("google.com",
			"google.com", false),
		Entry("*.google.com",
			"*.google.com", true),
		Entry("update.*.tigera.io",
			"update.*.tigera.io", true),
		Entry("cpanel.blog.org",
			"cpanel.blog.org", false),
	)

	DescribeTable("it should build correct wildcard regexps",
		func(wildcard, expectedRegexp string) {
			Expect(wildcardToRegexpString(wildcard)).To(Equal(expectedRegexp))
		},
		Entry("*.com",
			"*.com", "^.*\\.com$"),
		Entry("*.google.com",
			"*.google.com", "^.*\\.google\\.com$"),
		Entry("update.*.tigera.io",
			"update.*.tigera.io", "^update\\..*\\.tigera\\.io$"),
	)

	DescribeTable("wildcards match as expected",
		func(wildcard, name string, expectedMatch bool) {
			regex, err := regexp.Compile(wildcardToRegexpString(wildcard))
			Expect(err).NotTo(HaveOccurred())
			Expect(regex.MatchString(name)).To(Equal(expectedMatch))
		},
		Entry("*.com",
			"*.com", "google.com", true),
		Entry("*.com",
			"*.com", "www.google.com", true),
		Entry("*.com",
			"*.com", "com", false),
		Entry("*.com",
			"*.com", "tigera.io", false),
		Entry("*.google.com",
			"*.google.com", "www.google.com", true),
		Entry("*.google.com",
			"*.google.com", "ipv6.google.com", true),
		Entry("*.google.com",
			"*.google.com", "ipv6google.com", false),
		Entry("*.google.com",
			"*.google.com", "ipv6.experimental.google.com", true),
		Entry("update.*.tigera.io",
			"update.*.tigera.io", "update.calico.tigera.io", true),
		Entry("update.*.tigera.io",
			"update.*.tigera.io", "update.tsee.tigera.io", true),
		Entry("update.*.tigera.io",
			"update.*.tigera.io", "update.security.tsee.tigera.io", true),
		Entry("update.*.tigera.io",
			"update.*.tigera.io", "update.microsoft.com", false),
	)

	Context("collector tests", func() {
		var (
			collector         *mockCollector
			clientIP          = cnet.MustParseIP("1.2.3.4").IP
			serverIP          = cnet.MustParseIP("10.0.0.0").IP
			ipv4LayerRequest1 = &layers.IPv4{
				SrcIP: clientIP,
				DstIP: serverIP,
			}
			ipv4LayerResponse1 = &layers.IPv4{
				SrcIP: serverIP,
				DstIP: clientIP,
			}
			dnsLayerRequest1 = &layers.DNS{
				ID: 100,
				QR: false,
			}
			dnsLayerResponse1 = &layers.DNS{
				ID: 100,
				QR: true,
			}
			timeNow     = time.Now()
			time0       = uint64(timeNow.UnixNano())
			time1       = uint64(timeNow.Add(1 * time.Second).UnixNano())
			time2       = uint64(timeNow.Add(3 * time.Second).UnixNano())
			timeDelta12 = time.Duration(time2 - time1)
		)

		Context("with no collector", func() {
			BeforeEach(func() {
				config := &DnsConfig{
					DNSCacheFile:         "/dnsinfo",
					DNSCacheSaveInterval: time.Minute,
					DNSLogsLatency:       true,
				}
				domainStoreCreateEx(100, config)
			})

			It("handles request arriving before response and release tick", func() {
				// None of the collector specific methods should do anything if there is no collector.
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time1)
				Expect(domainStore.latencyData).To(HaveLen(0))

				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(0))

				domainStore.releaseUnpairedDataForLogging(timeNow.Add(1 * time.Hour))
			})
		})

		Context("with collector", func() {
			BeforeEach(func() {
				collector = &mockCollector{}
				config := &DnsConfig{
					DNSCacheFile:         "/dnsinfo",
					DNSCacheSaveInterval: time.Minute,
					Collector:            collector,
					DNSLogsLatency:       true,
				}
				domainStoreCreateEx(100, config)
			})

			It("handles no ipv4 layer on request", func() {
				domainStore.processDNSRequestPacketForLogging(nil, dnsLayerRequest1, time1)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(0))
			})

			It("handles no ipv4 layer on response", func() {
				domainStore.processDNSResponsePacketForLogging(nil, dnsLayerResponse1, time1)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(0))
			})

			It("handles no timestamp on request", func() {
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, 0)

				// We still store the request info even if the timestamp is unknown.
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				// Latency data will not be included when the response arrives.
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))
			})

			It("handles no timestamp on response", func() {
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, 0)

				// We should log immediately without any latency inforamtion
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0].latency).To(BeNil())

				// But we should still store the response for correlation with a late arriving request.
				Expect(domainStore.latencyData).To(HaveLen(1))

				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time1)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
			})

			It("handles request arriving before response", func() {
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time1)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: &timeDelta12,
				}))
			})

			It("handles response arriving before request", func() {
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time1)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: &timeDelta12,
				}))
			})

			It("handles response arriving before request, request has no timestemp", func() {
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, 0)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))
			})

			It("handles request, request, respose with the same ID", func() {
				// Request packet at time 0.
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				// Identical request packet at time 1. This should take precedence, the old one will be dropped, so
				// latency will be timeDelta12.
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time1)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: &timeDelta12,
				}))
			})

			It("handles request, request, respose with the same ID and no timestamp", func() {
				// Request packet at time 0.
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, 0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				// Identical request packet at time 1. This should take precedence, the old one will be dropped, so
				// latency will be timeDelta12.
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, 0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, 0)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))
			})

			It("handles response, response, request with the same ID", func() {
				// Request packet at time 0.
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				// Identical response packet at time 2. This should take precedence, the old one will be logged without
				// latency, and the new one will be logged with latency timeDelta12.
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))

				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time1)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(2))
				Expect(collector.dnsLogs[1]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: &timeDelta12,
				}))
			})

			It("handles response, response, request with the same ID and no timestamps", func() {
				// Request packet at time 0.
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, 0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))

				// Identical response packet at time 2. This should take precedence, the old one will be logged without
				// latency, and the new one will be logged with latency timeDelta12.
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, 0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(2))
				Expect(collector.dnsLogs[1]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))

				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, 0)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(2))
			})

			It("handles expiration of an unmatched request", func() {
				// Request packet at time 0.
				domainStore.nowFunc = func() time.Time {
					return timeNow
				}
				domainStore.processDNSRequestPacketForLogging(ipv4LayerRequest1, dnsLayerRequest1, time0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				// Ticker at time 0 + 1.1s. Should still be present.
				domainStore.releaseUnpairedDataForLogging(timeNow.Add(1100 * time.Millisecond))
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				// Ticker at time 0 + 10.1s. Should be removed.
				domainStore.releaseUnpairedDataForLogging(timeNow.Add(10100 * time.Millisecond))
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(0))
			})

			It("handles expiration of an unmatched response", func() {
				// Response packet at time 0.
				domainStore.nowFunc = func() time.Time {
					return timeNow
				}
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time0)
				Expect(domainStore.latencyData).To(HaveLen(1))
				Expect(collector.dnsLogs).To(HaveLen(0))

				// Ticker at time 0 + 1.1s. Should be removed and logged.
				domainStore.releaseUnpairedDataForLogging(timeNow.Add(1100 * time.Millisecond))
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))
			})
		})

		Context("with collector, no latency", func() {
			BeforeEach(func() {
				collector = &mockCollector{}
				config := &DnsConfig{
					DNSCacheFile:         "/dnsinfo",
					DNSCacheSaveInterval: time.Minute,
					Collector:            collector,
					DNSLogsLatency:       false,
				}
				domainStoreCreateEx(100, config)
			})

			It("immediately logs a response without latency", func() {
				domainStore.processDNSResponsePacketForLogging(ipv4LayerResponse1, dnsLayerResponse1, time2)
				Expect(domainStore.latencyData).To(HaveLen(0))
				Expect(collector.dnsLogs).To(HaveLen(1))
				Expect(collector.dnsLogs[0]).To(Equal(dnsLog{
					server:  serverIP,
					client:  clientIP,
					dns:     dnsLayerResponse1,
					latency: nil,
				}))
			})
		})
	})

	Context("wildcard handling", func() {
		BeforeEach(func() {
			domainStoreCreate()
		})

		// Test where wildcard is configured in the data model before we have any DNS
		// information that matches it.
		Context("with client interested in *.google.com", func() {
			BeforeEach(func() {
				Expect(domainStore.GetDomainIPs("*.google.com")).To(BeEmpty())
			})

			Context("with IP for update.google.com", func() {
				BeforeEach(func() {
					programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("update.google.com", "1.2.3.5"))
				})

				It("should update *.google.com", func() {
					handleUpdatesAndExpectChangesFor("*.google.com")
					Expect(domainStore.GetDomainIPs("*.google.com")).To(Equal([]string{"1.2.3.5"}))
				})

				It("should reverse lookup to update.google.com", func() {
					client := clientIP.String()
					ipb, _ := ip.ParseIPAs16Byte("1.2.3.5")
					Expect(domainStore.GetTopLevelDomainsForIP(client, ipb)).To(Equal([]string{"update.google.com"}))
				})
			})
		})

		// Test where wildcard is configured in the data model when we already have DNS
		// information that matches it.
		Context("with IP for update.google.com", func() {
			getWatchedDomains := func(ipb [16]byte) []string {
				var domains []string
				client := clientIP.String()
				domainStore.IterWatchedDomainsForIP(client, ipb, func(domain string) (stop bool) {
					domains = append(domains, domain)
					return false
				})
				return domains
			}

			BeforeEach(func() {
				programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("update.google.com", "1.2.3.5"))
			})

			It("should get that IP for *.google.com", func() {
				Expect(domainStore.GetDomainIPs("*.google.com")).To(Equal([]string{"1.2.3.5"}))
			})

			It("should handle reverse lookup when no IP was requested", func() {
				ipb, _ := ip.ParseIPAs16Byte("1.2.3.5")
				Expect(getWatchedDomains(ipb)).To(BeNil())
			})

			It("should handle reverse lookup when IP was requested as update.google.com", func() {
				ipb, _ := ip.ParseIPAs16Byte("1.2.3.5")
				Expect(domainStore.GetDomainIPs("update.google.com")).To(Equal([]string{"1.2.3.5"}))
				Expect(getWatchedDomains(ipb)).To(ConsistOf("update.google.com"))
			})

			It("should handle reverse lookup when IP was requested as *.google.com", func() {
				ipb, _ := ip.ParseIPAs16Byte("1.2.3.5")
				Expect(domainStore.GetDomainIPs("*.google.com")).To(Equal([]string{"1.2.3.5"}))
				Expect(getWatchedDomains(ipb)).To(ConsistOf("*.google.com"))
			})

			It("should handle reverse lookup when IP was requested as update.google.com and *.google.com", func() {
				ipb, _ := ip.ParseIPAs16Byte("1.2.3.5")
				Expect(domainStore.GetDomainIPs("*.google.com")).To(Equal([]string{"1.2.3.5"}))
				Expect(domainStore.GetDomainIPs("update.google.com")).To(Equal([]string{"1.2.3.5"}))
				Expect(getWatchedDomains(ipb)).To(ConsistOf("update.google.com", "*.google.com"))
			})
		})
	})

	Context("with 10s extra TTL", func() {
		BeforeEach(func() {
			domainStoreCreateEx(100, &DnsConfig{
				DNSExtraTTL:   10 * time.Second,
				DNSCacheEpoch: 1,
			})
			programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("update.google.com", "1.2.3.5"))
		})

		It("delivers the IP when queried", func() {
			Expect(domainStore.GetDomainIPs("update.google.com")).To(Equal([]string{"1.2.3.5"}))
		})

		It("created the mapping with 10s expiry", func() {
			Expect(lastTTL).To(Equal(10 * time.Second))
		})

		Context("with an epoch change", func() {
			BeforeEach(func() {
				conf := config.New()
				_, err := conf.UpdateFrom(map[string]string{"DNSCacheEpoch": "2"}, config.DatastoreGlobal)
				Expect(err).NotTo(HaveOccurred())
				domainStore.OnUpdate(conf.ToConfigUpdate())
				log.Info("Injected epoch change")
			})

			It("quickly removes the mapping", func() {
				// Note, Eventually by default allows up to 1 second.
				Eventually(func() []string {
					domainStore.loopIteration(nil, nil, nil)
					return domainStore.GetDomainIPs("update.google.com")
				}).Should(BeEmpty())
			})
		})
	})

	Context("with dynamic config update for 1h extra TTL", func() {
		BeforeEach(func() {
			domainStoreCreate()
			conf := config.New()
			_, err := conf.UpdateFrom(map[string]string{"DNSExtraTTL": "3600"}, config.DatastoreGlobal)
			Expect(err).NotTo(HaveOccurred())
			domainStore.OnUpdate(conf.ToConfigUpdate())
			log.Info("Updated extra TTL to 1h")
			programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("update.google.com", "1.2.3.5"))
		})

		It("delivers the IP when queried", func() {
			Expect(domainStore.GetDomainIPs("update.google.com")).To(Equal([]string{"1.2.3.5"}))
		})

		It("created the mapping with 1h expiry", func() {
			Expect(lastTTL).To(Equal(1 * time.Hour))
		})
	})

	// Test callbacks are invoked after dataplane programming is completed.
	It("should handle DNS updates with callbacks", func() {
		domainStoreCreate()

		// Program answer.  Handle updates and expect domain updates. No callbacks should be invoked until updates
		// are applied.
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("a1.com", "b.com"), "cb1")
		handleUpdatesAndExpectChangesFor("a1.com")
		expectCallbacks()
		domainStore.UpdatesApplied()
		expectCallbacks("cb1")

		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("a2.com", "b.com"), "cb2")
		handleUpdatesAndExpectChangesFor("a2.com")

		// We are already waiting for the dataplane updates for the previous two messages to be applied. In the meantime
		// send in more updates, the last is a repeat of the previous message.
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("b.com", "c.com"), "cb3")
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("c.com", "3.4.5.6"), "cb4")
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("a2.com", "b.com"), "cb5")

		// Apply the dataplane changes. We should get the callbacks for cb2 and cb5 once the changes are applied.
		expectCallbacks()
		domainStore.UpdatesApplied()
		expectCallbacks("cb2", "cb5")

		// Handle the remaining changes and apply the updates, we should get remaining callbacks invoked.
		handleUpdatesAndExpectChangesFor("b.com", "c.com")
		domainStore.UpdatesApplied()
		expectCallbacks("cb3", "cb4")
		handler.dataplaneSyncNeeded = true

		// Get IPs for domains a1.com and a2.com and then update c.com.
		Expect(domainStore.GetDomainIPs("a1.com")).To(Equal([]string{"3.4.5.6"}))
		Expect(domainStore.GetDomainIPs("a2.com")).To(Equal([]string{"3.4.5.6"}))

		// Have the handler indicate that no dataplane updates are required.  In this case the callbacks should happen
		// immediately without waiting for UpdatesApplied().
		handler.dataplaneSyncNeeded = false
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeA("c.com", "7.8.9.10"), "cb6")
		handleUpdatesAndExpectChangesFor("a1.com", "a2.com", "c.com")
		expectCallbacks("cb6")
		domainStore.UpdatesApplied()
		expectCallbacks()
		handler.dataplaneSyncNeeded = true

		// Repeat a message that is already programmed. We should get no further changes and the callback should happen
		// without any further dataplane involvement.
		programDNSAnswer(clientIP.String(), domainStore, testutils.MakeCNAME("a2.com", "b.com"), "cb7")
		Expect(domainStore.UpdatesReadyChannel()).ShouldNot(Receive())
		expectCallbacks("cb7")
	})

	It("should not panic because of an IPv4 packet with no transport header", func() {
		domainStoreCreate()

		pkt := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(
			pkt,
			gopacket.SerializeOptions{ComputeChecksums: true},
			&layers.IPv4{
				Version:  4,
				IHL:      5,
				TTL:      64,
				Flags:    layers.IPv4DontFragment,
				SrcIP:    net.IPv4(172, 31, 11, 2),
				DstIP:    net.IPv4(172, 31, 21, 5),
				Protocol: layers.IPProtocolTCP,
				Length:   5 * 4,
			},
		)
		Expect(err).NotTo(HaveOccurred())

		domainStore.MsgChannel() <- DataWithTimestamp{
			Data: pkt.Bytes(),
		}
		saveTimerC := make(chan time.Time)
		gcTimerC := make(chan time.Time)
		latencyTimerC := make(chan time.Time)
		Expect(func() {
			domainStore.loopIteration(saveTimerC, gcTimerC, latencyTimerC)
		}).NotTo(Panic())
	})

	It("should not panic because of an IPv6 packet", func() {
		domainStoreCreate()

		pkt := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(
			pkt,
			gopacket.SerializeOptions{FixLengths: true},
			&layers.IPv6{
				Version:    6,
				HopLimit:   64,
				NextHeader: layers.IPProtocolTCP,
				SrcIP:      net.IP([]byte{254, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 31, 11, 2}),
				DstIP:      net.IP([]byte{254, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 172, 31, 21, 5}),
			},
			&layers.TCP{
				SrcPort: 31024,
				DstPort: 5060,
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		)
		Expect(err).NotTo(HaveOccurred())

		domainStore.MsgChannel() <- DataWithTimestamp{
			Data: pkt.Bytes(),
		}
		saveTimerC := make(chan time.Time)
		gcTimerC := make(chan time.Time)
		latencyTimerC := make(chan time.Time)
		Expect(func() {
			domainStore.loopIteration(saveTimerC, gcTimerC, latencyTimerC)
		}).NotTo(Panic())
	})

	It("should not panic because of randomly generated packets", func() {
		domainStoreCreate()

		saveTimerC := make(chan time.Time)
		gcTimerC := make(chan time.Time)
		latencyTimerC := make(chan time.Time)
		for i := 0; i < 10; i++ {
			pkt := make([]byte, 78)
			n, err := rand.Read(pkt)
			Expect(err).NotTo(HaveOccurred())
			Expect(n).To(Equal(len(pkt)))
			domainStore.MsgChannel() <- DataWithTimestamp{
				Data: pkt,
			}
			Expect(func() {
				domainStore.loopIteration(saveTimerC, gcTimerC, latencyTimerC)
			}).NotTo(Panic())
		}
	})

	Context("handles domains that resolve to the same IP, for calls made by different clients", func() {
		BeforeEach(func() {
			programDNSAnswer(client1IP.String(), domainStore, testutils.MakeCNAME("cname1.example.com", "update.example.com"))
			programDNSAnswer(client1IP.String(), domainStore, testutils.MakeA("update.example.com", "1.2.3.5"))
			programDNSAnswer(client2IP.String(), domainStore, testutils.MakeCNAME("cname2.example.com", "update.example.com"))
			programDNSAnswer(client2IP.String(), domainStore, testutils.MakeA("update.example.com", "1.2.3.5"))
			programDNSAnswer(client3IP.String(), domainStore, testutils.MakeCNAME("cname3.example.com", "cname4.example.com"))
			programDNSAnswer(client3IP.String(), domainStore, testutils.MakeCNAME("cname4.example.com", "update.example.com"))
			programDNSAnswer(client3IP.String(), domainStore, testutils.MakeCNAME("cname5.example.com", "update.example.com"))
			programDNSAnswer(client3IP.String(), domainStore, testutils.MakeA("update.example.com", "1.2.3.5"))
			programDNSAnswer(client3IP.String(), domainStore, testutils.MakeA("other.example.com", "1.2.3.5"))
		})

		It("should get top level domains associated with the right client", func() {
			client1 := client1IP.String()
			client2 := client2IP.String()
			client3 := client3IP.String()
			ipb, _ := ip.ParseIPAs16Byte("1.2.3.5")

			// The right top level domains should be returned for the corresponding client.
			Expect(domainStore.GetTopLevelDomainsForIP(client1, ipb)).To(Equal([]string{"cname1.example.com"}))
			Expect(domainStore.GetTopLevelDomainsForIP(client2, ipb)).To(Equal([]string{"cname2.example.com"}))
			Expect(domainStore.GetTopLevelDomainsForIP(client3, ipb)).To(Equal([]string{"other.example.com", "cname5.example.com", "cname3.example.com"}))
		})
	})

	Context("handles domains that resolve to the same IP, for calls made by the zero client", func() {
		// This doesn't test different functionality, however, it is a special case that we want to make
		// sure we handle correctly. When the FlowLogsDestDomainByClient is false, programming of each
		// DNS answer is done by the zero client. The GetTopLevelDomains is requested with the zero
		// client.
		BeforeEach(func() {
			zeroIP := "0.0.0.0"
			programDNSAnswer(zeroIP, domainStore, testutils.MakeCNAME("cname1.example.com", "update.example.com"))
			programDNSAnswer(zeroIP, domainStore, testutils.MakeA("update.example.com", "1.2.3.5"))
			programDNSAnswer(zeroIP, domainStore, testutils.MakeCNAME("cname2.example.com", "update.example.com"))
			programDNSAnswer(zeroIP, domainStore, testutils.MakeA("update.example.com", "1.2.3.5"))
			programDNSAnswer(zeroIP, domainStore, testutils.MakeCNAME("cname3.example.com", "cname4.example.com"))
			programDNSAnswer(zeroIP, domainStore, testutils.MakeCNAME("cname4.example.com", "update.example.com"))
			programDNSAnswer(zeroIP, domainStore, testutils.MakeCNAME("cname5.example.com", "update.example.com"))
			programDNSAnswer(zeroIP, domainStore, testutils.MakeA("update.example.com", "1.2.3.5"))
		})

		It("should get top level domains associated with the right client", func() {
			zeroIP := "0.0.0.0"
			ipb, _ := ip.ParseIPAs16Byte("1.2.3.5")

			// The right top level domains should be returned for the corresponding client.
			Expect(domainStore.GetTopLevelDomainsForIP(zeroIP, ipb)).To(Equal([]string{"cname5.example.com", "cname3.example.com", "cname2.example.com", "cname1.example.com"}))
		})
	})

	Describe("SaveMappingsV1", func() {
		const (
			expectedFileContentOrder1 = `2
{"RequiredFeatures":["Epoch","PerClient"],"Epoch":0}
{"Client":"1.1.1.1","LHS":"lhsName1","RHS":"rhsName1","Expiry":"2022-01-01T00:00:00Z","Type":"ip"}
{"Client":"2.2.2.2","LHS":"lhsName2","RHS":"rhsName2","Expiry":"2022-01-01T00:00:01Z","Type":"ip"}
`

			expectedFileContentOrder2 = `2
{"RequiredFeatures":["PerClient","Epoch"],"Epoch":0}
{"Client":"1.1.1.1","LHS":"lhsName1","RHS":"rhsName1","Expiry":"2022-01-01T00:00:00Z","Type":"ip"}
{"Client":"2.2.2.2","LHS":"lhsName2","RHS":"rhsName2","Expiry":"2022-01-01T00:00:01Z","Type":"ip"}
`

			expectedFileContentOrder3 = `2
{"RequiredFeatures":["Epoch","PerClient"],"Epoch":0}
{"Client":"2.2.2.2","LHS":"lhsName2","RHS":"rhsName2","Expiry":"2022-01-01T00:00:01Z","Type":"ip"}
{"Client":"1.1.1.1","LHS":"lhsName1","RHS":"rhsName1","Expiry":"2022-01-01T00:00:00Z","Type":"ip"}
`

			expectedFileContentOrder4 = `2
{"RequiredFeatures":["PerClient","Epoch"],"Epoch":0}
{"Client":"2.2.2.2","LHS":"lhsName2","RHS":"rhsName2","Expiry":"2022-01-01T00:00:01Z","Type":"ip"}
{"Client":"1.1.1.1","LHS":"lhsName1","RHS":"rhsName1","Expiry":"2022-01-01T00:00:00Z","Type":"ip"}
`
		)

		var tempDir string

		BeforeEach(func() {
			var err error
			tempDir, err = os.MkdirTemp(".", "tmp")
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Create(tempDir + "/dnsinfo")
			Expect(err).NotTo(HaveOccurred())

			domainStoreCreate()
			domainStore.saveFile = tempDir + "/dnsinfo"
			domainStore.dnsLookup = map[string]*dnsLookupInfoByClient{
				"1.1.1.1": {
					mappings: map[string]*nameData{
						"lhsName1": {
							values: map[string]*valueData{
								"rhsName1": {
									isName:     false,
									expiryTime: time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
								},
							},
						},
					},
				},
				"2.2.2.2": {
					mappings: map[string]*nameData{
						"lhsName2": {
							values: map[string]*valueData{
								"rhsName2": {
									isName:     false,
									expiryTime: time.Date(2022, time.January, 1, 0, 0, 1, 0, time.UTC),
								},
							},
						},
					},
				},
			}
		})

		AfterEach(func() {
			_ = os.RemoveAll(tempDir)
		})

		It("should save mappings to file", func() {
			err := domainStore.SaveMappingsV1()
			Expect(err).NotTo(HaveOccurred())
			dir, err := os.ReadDir(tempDir)
			Expect(err).NotTo(HaveOccurred())
			f, err := os.ReadFile(tempDir + "/" + dir[0].Name())
			Expect(err).NotTo(HaveOccurred())
			// The order of the RequiredFeature and client entries in the file is not deterministic, so we
			// need to check for all possible orders.
			Expect(string(f)).Should(SatisfyAny(
				Equal(expectedFileContentOrder1),
				Equal(expectedFileContentOrder2),
				Equal(expectedFileContentOrder3),
				Equal(expectedFileContentOrder4),
			))
		})
	})

	Describe("readMappings", func() {
		var (
			expectedMappings = map[string]*dnsLookupInfoByClient{
				"1.1.1.1": {
					mappings: map[string]*nameData{
						"lhsName1": {
							values: map[string]*valueData{
								"rhsName1": {
									isName:     false,
									expiryTime: time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
								},
							},
							topLevelDomains: []string{"lhsName1"},
						},
					},
				},
				"2.2.2.2": {
					mappings: map[string]*nameData{
						"lhsName2": {
							values: map[string]*valueData{
								"rhsName2": {
									isName:     false,
									expiryTime: time.Date(2022, time.January, 1, 0, 0, 1, 0, time.UTC),
								},
							},
							topLevelDomains: []string{"lhsName2"},
						},
					},
				},
			}
			tempDir string
		)

		BeforeEach(func() {
			var err error
			tempDir, err = os.MkdirTemp(".", "tmp")
			Expect(err).NotTo(HaveOccurred())
			_, err = os.Create(tempDir + "/dnsinfo")
			Expect(err).NotTo(HaveOccurred())

			domainStoreCreate()
			domainStore.saveFile = tempDir + "/dnsinfo"
			domainStore.dnsLookup = map[string]*dnsLookupInfoByClient{
				"1.1.1.1": {
					mappings: map[string]*nameData{
						"lhsName1": {
							values: map[string]*valueData{
								"rhsName1": {
									isName:     false,
									expiryTime: time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
								},
							},
						},
					},
				},
				"2.2.2.2": {
					mappings: map[string]*nameData{
						"lhsName2": {
							values: map[string]*valueData{
								"rhsName2": {
									isName:     false,
									expiryTime: time.Date(2022, time.January, 1, 0, 0, 1, 0, time.UTC),
								},
							},
						},
					},
				},
			}

			err = domainStore.SaveMappingsV1()
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			_ = os.RemoveAll(tempDir)
		})

		It("should save mappings to file", func() {
			err := domainStore.readMappings()
			Expect(err).NotTo(HaveOccurred())
			for i, clk := range domainStore.dnsLookup {
				Expect(clk).To(Equal(expectedMappings[i]))
			}
		})
	})
})
