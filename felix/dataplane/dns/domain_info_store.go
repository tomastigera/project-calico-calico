// Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.
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

package dns

// Component interactions with the DomainInfoStore.
//
//  ┌─────────────────────────────────────────┐
//  │                                         │
//  │         DNS packet snooping             │
//  │                               callbacks │
//  └─┬┬──────────────────────────────────▲▲──┘
// (1)││                               (9)││
//    ││                                  ││
//    ││                                  ││
//    ││                                  ││
//  ┌─▼▼──────────────────────────────────┴┴──┐  (5)    ┌───────────────┐      ┌──────────────┐
//  │ MsgChan                     GetDomainIps│◄────────┤               │      │              │
//  │                                         │◄────────┤               │ (6)  │              │
//  │            DomainInfoStore              │         │ IPSetsManager ├─────►│    IPSets    │
//  │                                         ├────────►│               │      │              │
//  │            HandleUpdates UpdatesApplied ├────────►│OnDomainChange │      │ Apply        │
//  └───────┬───────────▲─────────────▲───────┘  (4)    └───────────────┘      └──▲───────────┘
//       (2)│        (3)│          (8)│                                        (7)│
//          │           │             │                                           │
//          │           │             └───────────────────────────────────────────┼────────┐
//          │           │                                                         │        │
//  ┌───────▼───────────┴─────────────────────────────────────────────────────────┴────────┴──┐
//  │UpdatesReadyChan                                                                         │
//  │                                   Dataplane loop                                        │
//  │                                                                                         │
//  └─────────────────────────────────────────────────────────────────────────────────────────┘
//
//  (1) Snooped packets are sent to the DomainInfoStore on the MsgChannel.
//      DomainInfoStore parses message, updates cache, stores set of changed names
//  (2) DomainInfoStore sends "update ready" tick to the dataplane.
//  (3) Dataplane loop calls back into DomainInfoStore to handle the current set of updates.
//  (4) During HandleUpdates(), the DomainInfoStore calls into the registered handlers (all IPSetsManagers) about each
//      domain that has been impacted (via OnDomainChange).
//  (5) and (6) During OnDomainChange(), the handler calls back into the DomainInfoStore for updated domain IPs and then
//      programs IP set dataplanes.
//  (7) Dataplane loop calls through to the IP set dataplanes to apply changes.
//  (8) Dataplane loop calls UpdatesApplied on DomainInfoStore to notify that the last set of handled updates have now
//      been applied to the IP set dataplanes.
//  (9) DomainInfoStore invokes callbacks associated with the DNS messages that were just applied to the Ip set
//      dataplanes.
//
// Notes:
// - (1) and (2) are channel based communications. The UpdatesReadyChan has capacity 1, so potentially multiple
//   DNS packets may be handled for only a single UpdatesReady tick.
// - Steps (3)-(9) are all callback based
// - In steps (3) - (6), if there are no changes required for the dataplane, the callbacks will be invoked immediately
// - Callbacks (3) and (8) can occur from the main (long-lived) dataplane loop, or from the ephemeral loops that the
//   dataplane starts up specifically for ipset updates while other updates (iptables) are happening. It is not
//   possible for both sets of updates to be happening at the same time, and these two callbacks will never be invoked
//   at the same time.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/collector"
	fc "github.com/projectcalico/calico/felix/config"
	"github.com/projectcalico/calico/felix/dataplane/common"
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

var (
	prometheusInvalidPacketsInCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_invalid_packets_in",
		Help: "Count of the number of invalid DNS request packets seen",
	})

	prometheusNonQueryPacketsInCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_non_query_packets_in",
		Help: "Count of the number of non-query DNS packets seen",
	})

	prometheusReqPacketsInCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_req_packets_in",
		Help: "Count of the number of DNS request packets seen",
	})

	prometheusRespPacketsInCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "felix_dns_resp_packets_in",
		Help: "Count of the number of DNS response packets seen",
	})
)

func init() {
	prometheus.MustRegister(prometheusInvalidPacketsInCount)
	prometheus.MustRegister(prometheusNonQueryPacketsInCount)
	prometheus.MustRegister(prometheusRespPacketsInCount)
	prometheus.MustRegister(prometheusReqPacketsInCount)
}

const (
	maxHoldDurationRequest  = 10 * time.Second
	maxHoldDurationResponse = 1 * time.Second
)

// dnsLookupInfoByClient holds the DNS lookup information per client.
type dnsLookupInfoByClient struct {
	// Stores for the information that we glean from DNS responses. Note: IPs are held here as
	// strings, and also passed to the ipsets manager as strings.
	mappings map[string]*nameData
	// Store for reverse DNS lookups.
	reverse map[[16]byte]*ipData
}

// The data that we hold for each value in a name -> value mapping.  A value can be an IP, or
// another name.  The values themselves are held as the keys of the nameData.values map.
type valueData struct {
	// When the validity of this value expires.
	expiryTime time.Time
	// Timer used to notify when the value expires.
	timer *time.Timer
	// Whether the value is another name, as opposed to being an IP.
	isName bool
}

// The data that we hold for each name.
type nameData struct {
	// Known values for this name. Map keys are the actual values (i.e. IPs or lowercase CNAME names),
	// and valueData is as above.
	values map[string]*valueData
	// Top-level domains associated with this name.
	topLevelDomains []string
	// Names that we should notify a "change of information" for, and whose cached IP list
	// should be invalidated, when the info for _this_ name changes.
	namesToNotify set.Set[string]
	// The revision sent to the dataplane associated with the creation or update of this nameData.
	revision uint64
}

type ipData struct {
	// The set of nameData entries that directly contain the IP.  We don't need to work our way backwards through the
	// chain because it is actually the namesToNotify that we are interested in which is propagated all the way
	// along the CNAME->A chain.
	nameDatas set.Set[*nameData]
	// The set of top level names associated with this IP. Note that the way this slice is updated, it is always
	// generated from scratch - this means it is safe to pass this slice without copying provided the consumer does not
	// alter the contents.
	topLevelDomains []string
}

// dnsExchangeKey is a key used to identify a DNS request and related response.
type dnsExchangeKey struct {
	clientIP string
	dnsID    uint16
}

// latencyData encapsulates one half of a DNS request or response. It is temporarily stored to determine latency
// information before the DNS response is logged. Generally the request arrives first, but there are scenarios where
// this may not always be true (e.g. DNSPolicyMode is DelayDNSResponse where requests and response come over different
// channels).
type latencyData struct {
	// The time (in milliseconds) that this data was queued. Used to determine when to expire this entry.
	queueTimestamp int64

	// The timestamp on the packet. Used to determine the request/response latency.
	packetTimestamp uint64

	// The serverIP, client IP and DNS packet for a DNS response.
	isResponse bool
	packet     *layers.DNS
	serverIP   net.IP
	clientIP   net.IP
}

type DataWithTimestamp struct {
	Data []byte
	// We use 0 here to mean "invalid" or "unknown", as a 0 value would mean 1970,
	// which will not occur in practice during Calico's active lifetime.
	Timestamp uint64
	// Optional callback for notification that the dataplane updates associated with this DNS data are programmed.
	Callback func()
}

type DomainInfoStore struct {
	// Rate limited logging when there are mismatched requests or responses. There is a known circumstance where
	// requests are not properly captured. If two requests are made with the same source port (which happens with some
	// regularity with certain DNS clients) and the first response comes in before the second request, then the second
	// request is marked as ctstate ESTABLISHED and is not captured.  Ideally we would capture ctstate RELATED, but
	// there is no conntrack module for dns and so it is not currently possible to hook into the RELATED state.
	rateLimitedNoRequestLogger  *logutils.RateLimitedLogger
	rateLimitedNoResponseLogger *logutils.RateLimitedLogger

	// Map from client IP to the DNS lookup data for that client.
	dnsLookup map[string]*dnsLookupInfoByClient

	// Handlers that we need update.
	handlers []common.DomainInfoChangeHandler

	// Channel on which we receive captured DNS responses (beginning with the IP header).
	msgChannel chan DataWithTimestamp

	// Channel used to send trigger notifications to the dataplane that there are updates that can be applied to the
	// DomainInfoChangeHandlers.
	updatesReady chan struct{}

	// Wildcard domain names that consumers are interested in (i.e. have called GetDomainIPs
	// for).
	wildcards map[string]*regexp.Regexp

	// Cache for "what are the IPs for <domain>?".  We have this to halve our processing,
	// because there are two copies of the IPSets Manager (one for v4 and one for v6) that will
	// call us to make identical queries.
	resultsCache map[string][]string

	// Channel for domain mapping expiry signals.
	mappingExpiryChannel chan *domainMappingExpired
	nowFunc              func() time.Time

	// Shim for starting and returning a timer that will call `onExpiry` after `ttl`.
	makeExpiryTimer func(ttl time.Duration, onExpiry func()) *time.Timer

	// Persistence.
	saveFile     string
	saveInterval time.Duration

	// Reclaiming memory for mappings that are now useless.
	gcTrigger  bool
	gcInterval time.Duration

	// Activity logging.
	collector collector.Collector

	// The max number of top level domains to associate with a domain or IP.
	maxTopLevelDomains int

	// Handling of DNS request/response timestamps, so that we can measure and report DNS latency. Because requests and
	// responses may be out-of-order (in some modes of operation they come through different channels) we may need to
	// store either the request or the response.  The requests are persisted for up to 10s to find the matching
	// response, but the responses are only persisted for up to 1s (since there is no network latency that we need to
	// consider for this scenario).
	measureLatency  bool
	latencyData     map[dnsExchangeKey]latencyData
	latencyInterval time.Duration

	// Handling additional DNS mapping lifetime.
	epoch    int
	extraTTL time.Duration
	resetC   chan struct{}

	dnsResponseDelay time.Duration

	// Whether the old mappings are in the process of being loaded in. During this phase we do not track top level DNS
	// requests because we cannot guarantee the order of loading.
	readingMappings bool

	// --- Data for the current set of updates ---
	// These are updates from new DNS packets that have not been handled by the dataplane.

	// Monotonically increasing revision number used to determine what changes have and have not been applied
	// to the dataplane. This number indicates the next revision to apply.
	// Revisions between appliedRevision and currentRevision have been "handled" but not applied.
	currentRevision uint64

	// Set of callbacks for the current (not handled) updates.
	callbacks []func()

	// The collated set of domain name changes for the current (not handled) set of updates. These are always stored
	// lowercase.
	changedNames set.Set[string]

	// --- Data for the handled set of updates ---\
	// These are updates that have been handled by the dataplane loop and programmed into the IP set dataplanes,
	// but have not yet been applied to the dataplane.

	// Set of callbacks for handled updates. These are callbacks for updates that have been handled but have not yet
	// been applied to the IP set dataplanes.
	handledCallbacks []func()

	// Whether the dataplane needs a sync from the domain name updates that have been handled. This is only accessed
	// from HandleUpdates() and UpdatesApplied() (which should not occur at the same time) - no lock is required for
	// accessing this field.
	needsDataplaneSync bool

	// --- Data for the applied set of updates ---
	// These are updates that are now programmed in the dataplane.

	// The revision number that has been applied to the dataplane.
	appliedRevision uint64

	// enableDestDomainsByClient enables the tracking of destination domains by client IP.
	enableDestDomainsByClient bool

	mutex sync.RWMutex
}

// Signal sent by timers' AfterFunc to the domain info store when a particular name -> IP or name ->
// cname mapping expires.
type domainMappingExpired struct {
	clientIP, name, value string
}

type DnsConfig struct {
	Collector                 collector.Collector
	DNSCacheEpoch             int
	DNSCacheFile              string
	DNSCacheSaveInterval      time.Duration
	DNSExtraTTL               time.Duration
	DNSLogsLatency            bool
	DebugDNSResponseDelay     time.Duration
	EnableDestDomainsByClient bool
	MaxTopLevelDomains        int
}

func NewDomainInfoStore(config *DnsConfig) *DomainInfoStore {
	return newDomainInfoStoreWithShims(
		config,
		time.AfterFunc,
		time.Now,
	)
}

func newDomainInfoStoreWithShims(
	config *DnsConfig,
	makeExpiryTimer func(time.Duration, func()) *time.Timer,
	nowFunc func() time.Time,
) *DomainInfoStore {
	log.WithField("config", config).Info("Creating domain info store")
	s := &DomainInfoStore{
		rateLimitedNoRequestLogger:  logutils.NewRateLimitedLogger(logutils.OptInterval(2 * time.Minute)),
		rateLimitedNoResponseLogger: logutils.NewRateLimitedLogger(logutils.OptInterval(2 * time.Minute)),

		// Updates ready channel has capacity 1 since only one notification is required at a time.
		updatesReady:         make(chan struct{}, 1),
		dnsLookup:            make(map[string]*dnsLookupInfoByClient),
		wildcards:            make(map[string]*regexp.Regexp),
		resultsCache:         make(map[string][]string),
		mappingExpiryChannel: make(chan *domainMappingExpired),
		nowFunc:              nowFunc,
		makeExpiryTimer:      makeExpiryTimer,
		saveFile:             config.DNSCacheFile,
		saveInterval:         config.DNSCacheSaveInterval,
		gcInterval:           13 * time.Second,
		collector:            config.Collector,
		maxTopLevelDomains:   config.MaxTopLevelDomains,
		// Only measure latency if we are collecting logs.
		measureLatency:   config.DNSLogsLatency && config.Collector != nil,
		latencyInterval:  100 * time.Millisecond,
		latencyData:      make(map[dnsExchangeKey]latencyData),
		epoch:            config.DNSCacheEpoch,
		extraTTL:         config.DNSExtraTTL,
		dnsResponseDelay: config.DebugDNSResponseDelay,
		// Capacity 1 here is to allow UT to test the use of this channel without
		// needing goroutines.
		resetC: make(chan struct{}, 1),
		// Use a buffered channel here with reasonable capacity, so that the nfnetlink capture
		// thread can handle a burst of DNS response packets without becoming blocked by the reading
		// thread here.  Specifically we say 1000 because that what's we use for flow logs, so we
		// know that works; even though we probably won't need so much capacity for the DNS case.
		msgChannel: make(chan DataWithTimestamp, 1000),

		// Create an empty set of changed names.
		changedNames: set.New[string](),

		// Current update revision starts at 1.  0 is used to indicate no required updates.
		currentRevision: 1,

		// Destination domains by client.
		enableDestDomainsByClient: config.EnableDestDomainsByClient,
	}

	return s
}

func (s *DomainInfoStore) MsgChannel() chan<- DataWithTimestamp {
	return s.msgChannel
}

func (s *DomainInfoStore) UpdatesReadyChannel() <-chan struct{} {
	return s.updatesReady
}

func (s *DomainInfoStore) Start() {
	log.Info("Starting domain info store")

	// If there is a flow collector, register ourselves as a domain lookup cache.
	if s.collector != nil {
		s.collector.SetDomainLookup(s)
	}

	// Ensure that the directory for the persistent file exists.
	if err := os.MkdirAll(path.Dir(s.saveFile), 0o755); err != nil {
		log.WithError(err).Fatal("Failed to create persistent file dir")
	}

	// Read mappings from the persistent file (if it exists).
	if err := s.readMappings(); err != nil {
		log.WithError(err).Warning("Failed to read mappings from file")
	}

	// Start repeating timers for periodically saving DNS info to a persistent file, and for
	// garbage collection.
	saveTimerC := time.NewTicker(s.saveInterval).C
	gcTimerC := time.NewTicker(s.gcInterval).C
	latencyTimerC := time.NewTicker(s.latencyInterval).C

	go s.loop(saveTimerC, gcTimerC, latencyTimerC)
}

// Dynamically handle changes to DNSCacheEpoch and DNSExtraTTL.
func (s *DomainInfoStore) OnUpdate(msg any) {
	switch msg := msg.(type) {
	case *proto.ConfigUpdate:
		felixConfig := fc.FromConfigUpdate(msg)
		s.mutex.Lock()
		defer s.mutex.Unlock()
		newEpoch := felixConfig.DNSCacheEpoch
		if newEpoch != s.epoch {
			log.Infof("Update epoch (%v->%v) and send trigger to clear cache", s.epoch, newEpoch)
			s.epoch = newEpoch
			s.resetC <- struct{}{}
		}
		newExtraTTL := felixConfig.GetDNSExtraTTL()
		if newExtraTTL != s.extraTTL {
			log.Infof("Extra TTL is now %v", newExtraTTL)
			s.extraTTL = newExtraTTL
		}
	}
}

// HandleUpdates is called after the dataplane is notified via the UpdatesReadyChannel that updates are ready to apply.
// This calls through to the handlers to notify them of configuration changes. It is up to the dataplane, however,
// to subsequently apply these changes and then call through to UpdatesApplied() to notify the DomainInfoStore that
// changes associated with the pending domain updates are now applied to the dataplane.
//
// Note that during initial sync, HandleUpdates may be called multiple times before UpdatesApplied.
func (s *DomainInfoStore) HandleUpdates() (needsDataplaneSync bool) {
	log.Debug("HandleUpdates called from dataplane")

	// Move current data into the pending data.
	s.mutex.Lock()
	s.handledCallbacks = append(s.handledCallbacks, s.callbacks...)
	s.callbacks = nil

	// Increment the current revision, new entries will be added with this revision.
	s.currentRevision++

	changedNames := s.changedNames
	s.changedNames = set.New[string]()
	s.mutex.Unlock()

	// Call into the handlers while we are not holding the lock.  This is important because the handlers will call back
	// into the DomainInfoStore to obtain domain->IP mapping info.
	for name := range changedNames.All() {
		for ii := range s.handlers {
			if s.handlers[ii].OnDomainChange(name) {
				// Track in member data that the dataplane needs a sync. It is not sufficient to just use a local
				// variable here since HandleUpdates may be called multiple times in a row before UpdatesApplied and
				// changes pending from a previous HandleUpdates invocation may make a later invocation a no-op even
				// though the dataplane changes still needs to be applied.
				s.needsDataplaneSync = true
			}
		}
	}

	if !s.needsDataplaneSync {
		// Dataplane does not need any updates, so just call through immediately to UpdatesApplied so that we don't wait
		// unneccessarily for other updates to be applied before we invoke any callbacks.
		log.Debug("No dataplane syncs are required")
		s.UpdatesApplied()
		return false
	}

	log.Debug("Dataplane syncs are required")
	return true
}

// UpdatesApplied is called by the dataplane when the updates associated after the last invocation of HandleUpdates have
// been applied to the dataplane.
func (s *DomainInfoStore) UpdatesApplied() {
	// Dataplane updates have been applied. Invoke the pending callbacks and update the last applied revision number.
	log.Debug("Dataplane updates have been applied")
	s.mutex.Lock()
	defer s.mutex.Unlock()

	callbacks := s.handledCallbacks
	s.handledCallbacks = nil
	s.needsDataplaneSync = false

	// We have applied everything that was handled, so the applied revision is up to but not including the current
	// revision.
	s.appliedRevision = s.currentRevision - 1

	// Invoke the callbacks on another goroutine to unblock the main dataplane.
	if len(callbacks) > 0 {
		log.Debug("Invoking callbacks for DNS packets")
		go func() {
			for i := range callbacks {
				callbacks[i]()
			}
		}()
	}
}

func (s *DomainInfoStore) RegisterHandler(handler common.DomainInfoChangeHandler) {
	s.handlers = append(s.handlers, handler)
}

func (s *DomainInfoStore) CompleteDeferredWork() error {
	// Nothing to do, we don't defer any work.
	return nil
}

func (s *DomainInfoStore) loop(saveTimerC, gcTimerC, latencyTimerC <-chan time.Time) {
	for {
		s.loopIteration(saveTimerC, gcTimerC, latencyTimerC)
	}
}

func (s *DomainInfoStore) loopIteration(saveTimerC, gcTimerC, latencyTimerC <-chan time.Time) {
	select {
	case msg := <-s.msgChannel:
		releaseImmediately := true
		defer func() {
			if releaseImmediately && msg.Callback != nil {
				log.Debug("Releasing packet immediately")
				msg.Callback()
			}
		}()

		// TODO: Test and fix handling of DNS over IPv6.  The `layers.LayerTypeIPv4`
		// in the next line is clearly a v4 assumption, and some of the code inside
		// `nfnetlink.SubscribeDNS` also looks v4-specific.
		packet := gopacket.NewPacket(msg.Data, layers.LayerTypeIPv4, gopacket.Lazy)
		ipv4, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ipv4 != nil {
			log.Debugf("src %v dst %v", ipv4.SrcIP, ipv4.DstIP)
		} else {
			log.Debug("No IPv4 layer")
		}

		// Decode the packet as DNS.  Don't just use LayerTypeDNS here, because that
		// requires port 53.  Here we want to parse as DNS regardless of the port
		// number.
		dns := &layers.DNS{}
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			log.Debug("Ignoring packet with no transport layer")
			return
		}
		dnsBytes := transportLayer.LayerPayload()

		// We've seen customers using tools that generate "ping" packets over UDP to test connectivity to
		// their DNS servers. One such tool uses "UDP PING ..." as the UDP payload.  Ignore such packets
		// rather than logging errors downstream.
		const udpPingPrefix = "UDP PING"
		if len(dnsBytes) >= len(udpPingPrefix) && string(dnsBytes[:len(udpPingPrefix)]) == udpPingPrefix {
			log.Debug("Ignoring UDP ping packet")
			prometheusInvalidPacketsInCount.Inc()
			return
		}

		err := dns.DecodeFromBytes(dnsBytes, gopacket.NilDecodeFeedback)
		if err != nil {
			log.WithError(err).Debug("Failed to decode DNS packet")
			prometheusInvalidPacketsInCount.Inc()
			return
		}

		if log.GetLevel() >= log.DebugLevel {
			log.WithField("dns", dns).Debug("DNS payload")
		}

		if dns.OpCode != layers.DNSOpCodeQuery {
			log.Debug("Ignoring non-Query DNS packet.")
			prometheusNonQueryPacketsInCount.Inc()
			return
		}

		if !dns.QR {
			// It's a DNS request. Process the packet for logging purposes.
			s.processDNSRequestPacketForLogging(ipv4, dns, msg.Timestamp)
			prometheusReqPacketsInCount.Inc()
		} else {
			// It's a DNS response.
			if dns.QDCount == 0 || len(dns.Questions) == 0 {
				// No questions; malformed packet?
				log.Debug("Ignoring DNS packet with no questions; malformed packet?")
				prometheusInvalidPacketsInCount.Inc()
				return
			}

			// Processing a DNS response, the client IP we will gather information for is represented by
			// the destination IP for this packet.
			clientIP := ipv4.DstIP.String()
			if !s.enableDestDomainsByClient {
				// When disabled, we store the DNS lookup info on a single clientIP key address. "0.0.0.0"
				// IP is used as the sentinel value to do so.
				clientIP = collector.DefaultGroupIP
			}

			// Process the packet for our DNS cache first and then process the packet for logging purposes.
			s.processDNSResponsePacket(clientIP, dns, msg.Callback)
			s.processDNSResponsePacketForLogging(ipv4, dns, msg.Timestamp)
			prometheusRespPacketsInCount.Inc()

			// Do not release the response packet immediately (only relevant if there is a release callback). If there
			// is a response callback the callback will be invoked once any associated IPSet updates have been applied.
			releaseImmediately = false
		}
	case expiry := <-s.mappingExpiryChannel:
		s.processMappingExpiry(expiry.clientIP, expiry.name, expiry.value, s.nowFunc())
	case <-saveTimerC:
		if err := s.SaveMappingsV1(); err != nil {
			log.WithError(err).Warning("Failed to save mappings to file")
		}
	case <-gcTimerC:
		_ = s.collectGarbage()
	case t := <-latencyTimerC:
		s.releaseUnpairedDataForLogging(t)
	case <-s.resetC:
		s.expireAllMappings()
	}
}

// maybeSignalUpdatesReady sends an update ready notification if required.
func (s *DomainInfoStore) maybeSignalUpdatesReady(reason string) {
	// Nothing to do if there are no changed names.
	if s.changedNames.Len() == 0 {
		log.Debug("No changed names")
		return
	}

	// If we need to delay the response, do that now. This is just for testing purposes. Release the lock so we don't
	// lock up the dataplane processing, but make sure we grab it again before sending the signal so that calling code
	// can ensure the signal has been sent but not yet handled (because handling requires access to the lock).
	if s.dnsResponseDelay != 0 {
		log.Debugf("Delaying DNS response for domains %v name for %d millis", s.changedNames, s.dnsResponseDelay)
		s.mutex.Unlock()
		time.Sleep(s.dnsResponseDelay)
		s.mutex.Lock()
	}

	// Signal updates are ready to process.
	select {
	case s.updatesReady <- struct{}{}:
		log.WithField("reason", reason).Debug("Sent update ready notification")
	default:
		log.WithField("reason", reason).Debug("Update ready notification already pending, updates will be handled together")
	}
}

type jsonMappingV1 struct {
	Client string
	LHS    string
	RHS    string
	Expiry string
	Type   string
}

// In v2 there is a mandatory initial header that specifies features required to correctly
// interpret the following mappings, with any settings related to those features.
//
// So far there is only one feature - encoding the epoch when the file was written, with the
// implication that the following mappings should be ignored if the epoch is now different from that
// - but this approach will allow us to add further features without having to evolve the overall
// format of the mappings file.
//
// Currently the v2 per-mapping content is the same as for v1.
//
// Upgrade/downgrade considerations are as follows.
//
// 1. Normal situation: the file was written as v2 with an epoch declaration, and is being read as
// v2 by (this) code that then check the epoch declaration.
//
// 2. Downgrade: the file was written as v2 with an epoch declaration, and is being read by
// downlevel code that only understands v1.  Reading will fail with `fmt.Errorf("Unrecognised format
// version: %v", version)`, which will then lead to a warning log and the mappings being ignored.
// Then the downlevel code will start building up DNS info again from scratch.  Worst case is
// failing to allow connections for which the DNS exchange happened before Felix restart and the
// connection setup happened after Felix restart.  This feels unlikely, and is acceptable given that
// the downgrade scenario is also unlikely.
//
// 3. Upgrade: the file was written as v1 without an epoch declaration, and is being read by this
// code.  Mappings will be read from the file, even though the epoch _might_ have changed - i.e. the
// same situation as before this fix.
type v2FileHeader struct {
	RequiredFeatures []v2FileFeature
	Epoch            int
}

type v2FileFeature string

const (
	v2FileFeatureEpoch     v2FileFeature = "Epoch"
	v2FileFeaturePerClient v2FileFeature = "PerClient"
)

var currentV2Features = set.From(
	v2FileFeatureEpoch,
	v2FileFeaturePerClient,
)

func (s *DomainInfoStore) readMappings() error {
	// Lock while we populate the cache.
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.readingMappings = true
	defer func() {
		s.readingMappings = false
	}()

	f, err := os.Open(s.saveFile)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)

	// Read the first line, which is the format version.
	if scanner.Scan() {
		version := strings.TrimSpace(scanner.Text())
		readerFunc := map[string]func(*bufio.Scanner) error{
			"1": s.readMappingsV1,
			"2": s.readMappingsV2,
		}[version]
		if readerFunc != nil {
			log.Infof("Read mappings in v%v format", version)
			if err = readerFunc(scanner); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("unrecognised format version: %v", version)
		}
	}
	// If we reach here, there was a problem scanning the version line.
	return scanner.Err()
}

const (
	v1TypeIP   = "ip"
	v1TypeName = "name"
)

func (s *DomainInfoStore) readMappingsV2(scanner *bufio.Scanner) error {
	// Read the first line, which must be the v2 file header.
	if !scanner.Scan() {
		return fmt.Errorf("failed to read v2 file header: %w", scanner.Err())
	}
	log.Infof("v2 file header line is: %v", scanner.Text())

	// Parse the header.
	var v2FileHeader v2FileHeader
	if err := json.Unmarshal(scanner.Bytes(), &v2FileHeader); err != nil {
		return fmt.Errorf("failed to parse v2 file header '%q': %w", scanner.Text(), err)
	}
	log.Infof("Decoded v2 file header as %#v", v2FileHeader)

	// Check that this code supports all the features that the file header requires.
	missingFeatures := []v2FileFeature{}
	for _, feature := range v2FileHeader.RequiredFeatures {
		if !currentV2Features.Contains(feature) {
			missingFeatures = append(missingFeatures, feature)
		}
	}
	if len(missingFeatures) > 0 {
		return fmt.Errorf("v2 file requires unsupported features %v", missingFeatures)
	}

	log.Debugf("Mappings file epoch is %v", v2FileHeader.Epoch)
	if v2FileHeader.Epoch != s.epoch {
		// Ignore the mappings in this file.
		log.Infof("Ignoring old DNS mappings because epoch changed from %v to %v", v2FileHeader.Epoch, s.epoch)
		return nil
	}

	// Epoch is good, so continue reading mappings as for v1.
	return s.readMappingsV1(scanner)
}

func (s *DomainInfoStore) readMappingsV1(scanner *bufio.Scanner) error {
	// Track which of the names is top-level (i.e. has no parent in the CNAME chain)
	hasParent := make(map[string]map[string]bool)

	for scanner.Scan() {
		var jsonMapping jsonMappingV1
		if err := json.Unmarshal(scanner.Bytes(), &jsonMapping); err != nil {
			return err
		}

		client := jsonMapping.Client
		if client == "" {
			// This is a mapping from the old format, where we didn't store the client IP.
			// Assume it's from the default client. The item will be expired shortly anyway.
			client = collector.DefaultGroupIP
		}

		if _, ok := hasParent[client]; !ok {
			hasParent[client] = make(map[string]bool)
		}
		hasParent[client][strings.ToLower(jsonMapping.RHS)] = true

		expiryTime, err := time.Parse(time.RFC3339, jsonMapping.Expiry)
		if err != nil {
			return err
		}
		ttlNow := time.Until(expiryTime)
		if ttlNow.Seconds() > 1 {
			log.Debugf("Recreate mapping %v", jsonMapping)

			// The mapping may have been saved by a previous version including uppercase letters,
			// so lowercase it now.
			s.storeInfo(
				client,
				strings.ToLower(jsonMapping.LHS),
				strings.ToLower(jsonMapping.RHS),
				ttlNow,
				jsonMapping.Type == v1TypeName,
			)
		} else {
			log.Debugf("Ignore expired mapping %v", jsonMapping)
		}
	}

	// Loop through every client that was stored in the previous step, and update the top-level
	// domains.
	for cip, clk := range s.dnsLookup {
		// Loop through the mappings and update any that don't have parents to be "top-level".
		for name, data := range clk.mappings {
			if !hasParent[cip][name] {
				s.propagateTopLevelDomains(cip, name, data, []string{name})
			}
		}
	}

	s.maybeSignalUpdatesReady("mapping loaded")
	return scanner.Err()
}

func (s *DomainInfoStore) SaveMappingsV1() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	log.WithField("file", s.saveFile).Debug("Saving DNS mappings...")

	// Write first to a temporary save file, so that we can atomically rename it to the intended
	// file once it contains new data.  Thus we avoid overwriting a previous version of the file
	// (which may still be useful) until we're sure we have a complete new file prepared.
	tmpSaveFile := s.saveFile + ".tmp"
	f, err := os.Create(tmpSaveFile)
	if err != nil {
		return err
	}
	fileAlreadyClosed := false
	defer func() {
		if !fileAlreadyClosed {
			if err := f.Close(); err != nil {
				log.WithError(err).Warning("Error closing mappings file")
			}
		}
	}()

	// File format 2.
	if _, err = f.WriteString("2\n"); err != nil {
		return err
	}
	jsonEncoder := json.NewEncoder(f)
	if err = jsonEncoder.Encode(v2FileHeader{
		RequiredFeatures: currentV2Features.Slice(),
		Epoch:            s.epoch,
	}); err != nil {
		return err
	}
	// Loop through every client and write out the mappings.
	for cip, clk := range s.dnsLookup {
		for lhsName, nameData := range clk.mappings {
			for rhsName, valueData := range nameData.values {
				jsonMapping := jsonMappingV1{Client: cip, LHS: lhsName, RHS: rhsName, Type: v1TypeIP}
				if valueData.isName {
					jsonMapping.Type = v1TypeName
				}
				jsonMapping.Expiry = valueData.expiryTime.Format(time.RFC3339)
				if err = jsonEncoder.Encode(jsonMapping); err != nil {
					return err
				}
				log.Debugf("Saved mapping: %v", jsonMapping)
			}
		}
	}

	// Close the temporary save file.
	if err = f.Close(); err != nil {
		return err
	}
	fileAlreadyClosed = true

	// Move that file to the non-temporary name.
	if err = os.Rename(tmpSaveFile, s.saveFile); err != nil {
		return err
	}

	log.WithField("file", s.saveFile).Debug("Finished saving DNS mappings")

	return nil
}

// processDNSRequestPacketForLogging processes a DNS request for logging.
//
// Requests are only used to determine request/response latency, so if not measuring latency this is a no-op. Under
// certain conditions requests and responses may arrive out of order. This method handles both:
// - If a response has not been received then the request is stored for a maximum of 10s while we wait for a response
// - If a response has been received then the latency is calculated and the response packet is logged with latency.
//
// Response packets are processed in processDNSResponsePacketForLogging.
// Requests that have been held for >10s are removed in releaseUnpairedDataForLogging.
func (s *DomainInfoStore) processDNSRequestPacketForLogging(ipv4 *layers.IPv4, dns *layers.DNS, timestamp uint64) {
	// We only use the request packet if we are measuring latency.
	if !s.measureLatency {
		return
	}
	if ipv4 == nil {
		// DNS request IDs are not globally unique; we need the IP of the client to scope
		// them.  So, when the packet in hand does not have an IPv4 header, we can't process
		// it for latency.
		return
	}

	if timestamp == 0 {
		// No packetTimestamp on this packet.
		log.Debugf("DNS-LATENCY: Missing packetTimestamp on DNS request with ID %v", dns.ID)
	}

	key := dnsExchangeKey{ipv4.SrcIP.String(), dns.ID}
	if data, exists := s.latencyData[key]; !exists {
		// There is no stored entry, so store the request.
		log.Debugf("DNS-LATENCY: Received DNS request with ID %v", key)
		s.latencyData[key] = latencyData{
			queueTimestamp:  s.nowFunc().UnixMilli(),
			packetTimestamp: timestamp,
		}
	} else if !data.isResponse {
		// We already have a request stored for this key. Update it. This is not expected, but we should protect
		// as best we can against duplicate IDs.
		log.Warnf("DNS-LATENCY: Received DNS request but already have DNS request with ID %v", key)
		s.latencyData[key] = latencyData{
			queueTimestamp:  s.nowFunc().UnixMilli(),
			packetTimestamp: timestamp,
		}
	} else if data.packet == nil {
		// Stored response packet is nil which means we've already logged it, so nothing more to do other than remove
		// the cached entry.
		log.Debugf("DNS-LATENCY: Received DNS request and already have logged response for ID %v", key)
		delete(s.latencyData, key)
	} else if timestamp == 0 {
		log.Debugf("DNS-LATENCY: Received DNS request with no timestamp and already have response for ID %v", key)
		s.collector.LogDNS(ipv4.DstIP, ipv4.SrcIP, data.packet, nil)
		delete(s.latencyData, key)
	} else {
		// We have received a request, and have a stored response (so they were out of order). Remove the record,
		// calculate latency and log.
		latency := time.Duration(data.packetTimestamp - timestamp)
		log.Debugf("DNS-LATENCY: Received DNS request and already have response: Latency %v for ID %v", latency, key)
		s.collector.LogDNS(ipv4.DstIP, ipv4.SrcIP, data.packet, &latency)
		delete(s.latencyData, key)
	}
}

// processDNSResponsePacketForLogging processes a DNS response for logging.
//
// If not measuring latency the packet is logged immediately. Otherwise, the response is correlated with a request to
// determine latency.
//
// Under certain conditions requests and responses may arrive out of order. This method handles both:
//   - If a request has not been received then the response is stored for a maximum of 1s while we wait for a request.
//     Since request and response are processed by different queues then it is theoretically possible for them to arrive
//     out of order (and infact NFQueued responses seem to regularly arrive before NFLog'd requests.
//   - If a request has been received then the latency is calculated and the response packet is logged with latency.
//
// Request packets are processed in processDNSRequestPacketForLogging.
// Responses that have been held for >1s are removed in releaseUnpairedDataForLogging.
func (s *DomainInfoStore) processDNSResponsePacketForLogging(ipv4 *layers.IPv4, dns *layers.DNS, timestamp uint64) {
	// We only need to do anything if we are logging.
	if s.collector == nil {
		return
	}
	if ipv4 == nil {
		// DNS request IDs are not globally unique; we need the IP of the client to scope
		// them.  So, when the packet in hand does not have an IPv4 header, we can't process
		// it for latency.
		return
	}
	if !s.measureLatency {
		// Not measuring latency, , just log immediately since we are not gathering latency info.
		s.collector.LogDNS(ipv4.SrcIP, ipv4.DstIP, dns, nil)
		return
	}

	// Calculate the key.
	key := dnsExchangeKey{ipv4.DstIP.String(), dns.ID}

	if timestamp == 0 {
		// No packetTimestamp on this packet, just log immediately since we cannot gather latency info.
		log.Debugf("DNS-LATENCY: Missing timestamp on DNS response with ID %v", dns.ID)
		s.collector.LogDNS(ipv4.SrcIP, ipv4.DstIP, dns, nil)

		// We may still want to temporarily process the response to match it up with a request so that we don't
		// write out warning logs, but we no longer need the actual DNS packet.
		dns = nil
	}

	// From here on we know we have a packetTimestamp for the packet in hand.  It's a number of
	// nanoseconds, measured from some arbitrary point in the past.  (Possibly not from the same
	// base point as time.Time, so don't assume that.)
	if data, exists := s.latencyData[key]; !exists {
		// There is no stored entry, so store the response. We can marry this up to a request that might be arriving
		// shortly.
		log.Debugf("DNS-LATENCY: Received DNS response with no request for ID %v", key)
		s.latencyData[key] = latencyData{
			queueTimestamp:  s.nowFunc().UnixMilli(),
			packetTimestamp: timestamp,
			isResponse:      true,
			serverIP:        ipv4.SrcIP,
			clientIP:        ipv4.DstIP,
			packet:          dns,
		}
	} else if data.isResponse {
		// We have received a response and already have a stored response. Send a log for the previous response
		// (if we hadn't already sent it) and update the entry.  This is not expected, but we should protect as best we
		// can against identical IDs.
		log.Warnf("DNS-LATENCY: Received DNS response but already have DNS reponse with ID %v", key)
		if data.packet != nil {
			s.collector.LogDNS(data.serverIP, data.clientIP, data.packet, nil)
		}
		s.latencyData[key] = latencyData{
			queueTimestamp:  s.nowFunc().UnixMilli(),
			packetTimestamp: timestamp,
			isResponse:      true,
			serverIP:        ipv4.SrcIP,
			clientIP:        ipv4.DstIP,
			packet:          dns,
		}
	} else if dns == nil {
		// We logged above and have received a request. Just delete the request.
		log.Debugf("DNS-LATENCY: Received DNS response and have request (no latency) for ID %v", key)
		delete(s.latencyData, key)
	} else if data.packetTimestamp == 0 {
		// Packet request had no timestamp, so log without latency and remove cached data.
		log.Debugf("DNS-LATENCY: Received DNS response and have request with no timestamp for ID %v", key)
		s.collector.LogDNS(ipv4.SrcIP, ipv4.DstIP, dns, nil)
		delete(s.latencyData, key)
	} else {
		// Packet request and response had timestamp so calculate the latency, log and remove the cached data.
		latency := time.Duration(timestamp - data.packetTimestamp)
		log.Debugf("DNS-LATENCY: Received DNS response and have request: latency %v for ID %v", latency, key)
		s.collector.LogDNS(ipv4.SrcIP, ipv4.DstIP, dns, &latency)
		delete(s.latencyData, key)
	}
}

func (s *DomainInfoStore) processDNSResponsePacket(clientIP string, dns *layers.DNS, callback func()) {
	log.Debugf("DNS packet with %v answers %v additionals", len(dns.Answers), len(dns.Additionals))
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Update our cache and collect any name updates that we need to signal. We also determine the max revision
	// associated with these changes so that we can determine when to invoke the callbacks (if supplied).
	var maxRevision uint64
	for _, rec := range dns.Answers {
		if revision := s.storeDNSRecordInfo(&rec, clientIP, "answer"); revision > maxRevision {
			maxRevision = revision
		}
	}
	for _, rec := range dns.Additionals {
		if msgNum := s.storeDNSRecordInfo(&rec, clientIP, "additional"); msgNum > maxRevision {
			maxRevision = msgNum
		}
	}

	// Maybe signal an update is ready. Since we are holding the lock this is safe to do before the callback handling.
	s.maybeSignalUpdatesReady("mapping added")

	// If there is no callback supplied, just exit now.
	if callback == nil {
		return
	}

	// The DNS packet may have provided new information that is not yet programmed.  If so, add the callback to
	// the set of callbacks associated with the message number. These callbacks will be invoked once the dataplane
	// indicates the messages have been programmed. Otherwise, invoke the callback immediately.
	//
	// Since the message numbers are monotonic and the dataplane handles the messages in order, we use thresholds to
	// determine which messages have been processed. Invoke the callback on a goroutine so that we are not
	// holding the lock.
	switch {
	case maxRevision >= s.currentRevision:
		// The packet contains changes that have not yet been handled, so add the callback to the active set.
		log.Debugf("Changes have not yet been handled: %d > %d", maxRevision, s.currentRevision)
		s.callbacks = append(s.callbacks, callback)
	case maxRevision <= s.appliedRevision:
		// The packet only contains changes that are already programmed in the dataplane. Invoke the callback
		// immediately.
		log.Debugf("Changes have been applied or are not required: %d <= %d", maxRevision, s.currentRevision)
		go callback()
	default:
		// The packet has been handled, but not yet programmed, so add to the handled callbacks. This will be invoked
		// on the next call to UpdatesApplied().
		log.Debugf("Changes have been handled but not applied: %d <= %d", maxRevision, s.currentRevision)
		s.handledCallbacks = append(s.handledCallbacks, callback)
	}
}

func (s *DomainInfoStore) processMappingExpiry(clientIP, name, value string, now time.Time) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	clk := s.dnsLookup[clientIP]
	if clk != nil {
		if nameData := clk.mappings[name]; nameData != nil {
			if valueData := nameData.values[value]; (valueData != nil) && valueData.expiryTime.Before(now) {
				log.Debugf("Mapping expiry for %v/%v -> %v", clientIP, name, value)
				delete(nameData.values, value)
				if !valueData.isName {
					s.removeIPMapping(nameData, clientIP, value)
				}
				s.gcTrigger = true
				s.compileChangedNames(clientIP, name)
			} else if valueData != nil {
				log.Debugf("Too early mapping expiry for %v -> %v", name, value)
			} else {
				log.Debugf("Mapping already gone for %v -> %v", name, value)
			}
		} else {
			log.Debugf("No mappings for clientIP %s", clientIP)
		}
	} else {
		log.Debugf("DNS lookup info for clientIP %s doesn't exist", clientIP)
	}
	s.maybeSignalUpdatesReady("mapping expired")
}

func (s *DomainInfoStore) expireAllMappings() {
	log.Info("Expire all mappings")
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// For each mapping...
	for clientIP, cl := range s.dnsLookup {
		for name, nameData := range cl.mappings {
			// ...discard all of its values, being careful to release any reverse IP mappings.
			for value, valueData := range nameData.values {
				if !valueData.isName {
					s.removeIPMapping(nameData, clientIP, value)
				}
			}
			nameData.values = make(map[string]*valueData)
			s.compileChangedNames(clientIP, name)
		}
	}

	// Trigger a GC to reclaim the memory that we can.
	s.gcTrigger = true

	s.maybeSignalUpdatesReady("epoch changed")
}

// Add a mapping between an IP and the nameData that directly contains the IP for a given clientIP.
func (s *DomainInfoStore) addIPMapping(nd *nameData, clientIP, ipStr string) {
	ipBytes, ok := ip.ParseIPAs16Byte(ipStr)
	if !ok {
		return
	}

	clk := s.dnsLookup[clientIP]
	if clk != nil {
		ipd := clk.reverse[ipBytes]
		if ipd == nil {
			ipd = &ipData{
				nameDatas:       set.New[*nameData](),
				topLevelDomains: nd.topLevelDomains,
			}
			clk.reverse[ipBytes] = ipd
		} else {
			ipd.topLevelDomains = s.combineTopLevelDomains(nd.topLevelDomains, ipd.topLevelDomains)
		}
		log.Debugf("Client's %s queries to IP %s has the top level names %v", clientIP, ipStr, ipd.topLevelDomains)
		ipd.nameDatas.Add(nd)
	} else {
		log.Debugf("DNS lookup info for clientIP %s doesn't exist", clientIP)
	}
}

// Remove a mapping between an IP and the nameData that directly contained the IP.
func (s *DomainInfoStore) removeIPMapping(nameData *nameData, clientIP, ipStr string) {
	ipBytes, ok := ip.ParseIPAs16Byte(ipStr)
	if !ok {
		return
	}

	clk := s.dnsLookup[clientIP]
	if clk != nil {
		if ipd := clk.reverse[ipBytes]; ipd != nil {
			ipd.nameDatas.Discard(nameData)
			if ipd.nameDatas.Len() == 0 {
				delete(clk.reverse, ipBytes)
			}
		} else {
			log.Warningf("IP mapping is not cached %v", ipBytes)
		}
	} else {
		log.Debugf("DNS lookup info for clientIP %s doesn't exist", clientIP)
	}
}

func (s *DomainInfoStore) storeDNSRecordInfo(rec *layers.DNSResourceRecord, clientIP, section string) (revision uint64) {
	if rec.Class != layers.DNSClassIN {
		log.Debugf("Ignore DNS response with class %v", rec.Class)
		return
	}

	// Only CNAME type records can have the IP field set to nil
	if rec.IP == nil && rec.Type != layers.DNSTypeCNAME {
		log.Debugf("Ignore %s DNS response with empty or invalid IP", rec.Type.String())
		return
	}

	// All names are stored and looked up as lowercase.
	name := strings.ToLower(string(rec.Name))

	switch rec.Type {
	case layers.DNSTypeA:
		log.Debugf("A: %v -> %v with TTL %v (%v)",
			name,
			rec.IP,
			rec.TTL,
			section,
		)
		revision = s.storeInfo(clientIP, name, rec.IP.String(), time.Duration(rec.TTL)*time.Second, false)
	case layers.DNSTypeAAAA:
		log.Debugf("AAAA: %v -> %v with TTL %v (%v)",
			name,
			rec.IP,
			rec.TTL,
			section,
		)
		revision = s.storeInfo(clientIP, name, rec.IP.String(), time.Duration(rec.TTL)*time.Second, false)
	case layers.DNSTypeCNAME:
		cname := strings.ToLower(string(rec.CNAME))
		log.Debugf("CNAME: %v -> %v with TTL %v (%v)",
			name,
			cname,
			rec.TTL,
			section,
		)
		revision = s.storeInfo(clientIP, name, cname, time.Duration(rec.TTL)*time.Second, true)
	default:
		log.Debugf("Ignore DNS response with type %v", rec.Type)
	}

	return
}

func (s *DomainInfoStore) storeInfo(clientIP, name, value string, ttl time.Duration, isName bool) (revision uint64) {
	if value == "0.0.0.0" {
		// DNS records sometimes contain 0.0.0.0, but it's not a real routable IP and we
		// must avoid passing it on to ipsets, because ipsets complains with "ipset v6.38:
		// Error in line 1: Null-valued element, cannot be stored in a hash type of set".
		// We don't need to record 0.0.0.0 mappings for any other purpose, so just log and
		// bail out early here.
		log.Debugf("Ignoring zero IP (%v -> %v TTL %v)", name, value, ttl)
		return
	}

	// Add on extra TTL, if configured.
	ttl = time.Duration(int64(ttl) + int64(s.extraTTL))

	// Impose a minimum TTL of 2 seconds - i.e. ensure that the mapping that we store here will
	// not expire for at least 2 seconds.  Otherwise TCP connections that should succeed will
	// fail if they involve a DNS response with TTL 1.  In detail:
	//
	// a. A client does a DNS lookup for an allowed domain.
	// b. DNS response comes back, and is copied here for processing.
	// c. Client sees DNS response and immediately connects to the IP.
	// d. Felix's ipset programming isn't in place yet, so the first connection packet is
	//    dropped.
	// e. TCP sends a retry connection packet after 1 second.
	// f. 1 second should be plenty long enough for Felix's ipset programming, so the retry
	//    connection packet should go through.
	//
	// However, if the mapping learnt from (c) expires after 1 second, the retry connection
	// packet may be dropped as well.  Imposing a minimum expiry of 2 seconds avoids that.
	if int64(ttl) < int64(2*time.Second) {
		ttl = 2 * time.Second
	}

	makeTimer := func() *time.Timer {
		return s.makeExpiryTimer(ttl, func() {
			s.mappingExpiryChannel <- &domainMappingExpired{clientIP: clientIP, name: name, value: value}
		})
	}

	// Get the dnsLookupInfo for this clientIP. If it does not exist, create it.
	clientDNSLookup, ok := s.dnsLookup[clientIP]
	if !ok {
		clientDNSLookup = &dnsLookupInfoByClient{
			mappings: make(map[string]*nameData),
			reverse:  make(map[[16]byte]*ipData),
		}
		s.dnsLookup[clientIP] = clientDNSLookup
	}
	// Get the stored nameData for this name. If it does not exist, and we are not in the data loading
	// stage of start up then this must be a top-of-chain request.
	thisNameData := clientDNSLookup.mappings[name]
	if thisNameData == nil {
		thisNameData = &nameData{
			values:        make(map[string]*valueData),
			namesToNotify: set.New[string](),
		}
		if !s.readingMappings {
			log.Debugf("Top level CNAME query for %s", name)
			thisNameData.topLevelDomains = []string{name}
		}
		clientDNSLookup.mappings[name] = thisNameData
	}
	existingValue := thisNameData.values[value]
	if existingValue == nil {
		// If this is the first value for this name, check whether the name matches any
		// existing wildcards.
		if len(thisNameData.values) == 0 {
			for wildcard, regex := range s.wildcards {
				if regex.MatchString(name) {
					thisNameData.namesToNotify.Add(wildcard)
				}
			}
		}
		thisNameData.values[value] = &valueData{
			expiryTime: s.nowFunc().Add(ttl),
			timer:      makeTimer(),
			isName:     isName,
		}

		if isName {
			// Value is another name. If we don't yet have any information, create a
			// mapping entry for it so we can record that it is a descendant of the name in
			// hand.  Then, when we get information for the descendant name, we can correctly
			// signal changes for the name in hand and any of its ancestors.
			if valueNameData := clientDNSLookup.mappings[value]; valueNameData == nil {
				log.Debugf("Storing value %s for name %s with top level names %v", value, name, thisNameData.topLevelDomains)
				clientDNSLookup.mappings[value] = &nameData{
					values:          make(map[string]*valueData),
					namesToNotify:   set.New[string](),
					topLevelDomains: thisNameData.topLevelDomains,
				}
			} else {
				// Propagate the top level names down the chain.
				log.Debugf("Propagating to %s the top level names %v", value, thisNameData.topLevelDomains)
				s.propagateTopLevelDomains(clientIP, value, valueNameData, thisNameData.topLevelDomains)
			}
		} else {
			// Value is an IP. Add to our IP mapping.
			s.addIPMapping(thisNameData, clientIP, value)
		}

		// Compile the set of changed names. The calling code will signal that the info has changed for
		// the compiled set of names.
		s.compileChangedNames(clientIP, name)

		// Set the revision for this entry.
		clientDNSLookup.mappings[name].revision = s.currentRevision
		revision = s.currentRevision
	} else {
		newExpiryTime := s.nowFunc().Add(ttl)
		if newExpiryTime.After(existingValue.expiryTime) {
			// Update the expiry time of the existing mapping.
			existingValue.timer.Stop()
			existingValue.timer = makeTimer()
			existingValue.expiryTime = newExpiryTime
		}

		// Return the revision for this existing mapping.
		revision = thisNameData.revision
	}

	return
}

// propagateTopLevelDomains propagates the top level domains down the chain of names, for a given client.
func (s *DomainInfoStore) propagateTopLevelDomains(clientIP, name string, data *nameData, topLevelDomains []string) {
	var prop func(currentName string, currentNameData *nameData)
	handled := set.New[string]()

	clk := s.dnsLookup[clientIP]
	if clk == nil {
		log.Debugf("DNS lookup info for clientIP %s doesn't exist", clientIP)
		return
	}

	prop = func(currentName string, currentNameData *nameData) {
		if handled.Contains(currentName) {
			return
		}
		handled.Add(currentName)
		currentNameData.topLevelDomains = s.combineTopLevelDomains(topLevelDomains, currentNameData.topLevelDomains)
		for value, data := range currentNameData.values {
			if data.isName {
				if valueNameData := clk.mappings[value]; valueNameData != nil {
					// Propagate the top level names down the chain.
					log.Debugf("Propagating to %s the top level names %v", value, topLevelDomains)
					prop(value, valueNameData)
				}
			} else {
				ipBytes, ok := ip.ParseIPAs16Byte(value)
				if !ok {
					return
				}

				ipd := clk.reverse[ipBytes]
				if ipd != nil {
					ipd.topLevelDomains = s.combineTopLevelDomains(topLevelDomains, ipd.topLevelDomains)
				}
			}
		}
	}

	// Recursively propagate the domains.
	prop(name, data)
}

// GetDomainIPs returns the list of IPs associated with a domain name. The domains are extracted
// from the DNS mappings from every client.
func (s *DomainInfoStore) GetDomainIPs(domain string) []string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	// All names are stored and looked up as lowercase.
	domain = strings.ToLower(domain)
	ips := s.resultsCache[domain]
	if ips == nil {
		var collectIPsForName func(string, string, set.Set[string])
		collectIPsForName = func(clientIP, name string, collectedNames set.Set[string]) {
			clk := s.dnsLookup[clientIP]
			if clk == nil {
				log.Debugf("DNS lookup info for clientIP %s doesn't exist", clientIP)
				return
			}
			if collectedNames.Contains(name) {
				log.Warningf("%v has a CNAME loop back to itself", name)
				return
			}
			collectedNames.Add(name)
			nameData := clk.mappings[name]
			log.WithFields(log.Fields{
				"name":     name,
				"nameData": nameData,
			}).Debug("Collect IPs for name")
			if nameData != nil {
				nameData.namesToNotify.Add(domain)
				for value, valueData := range nameData.values {
					if valueData.isName {
						// The RHS of the mapping is another name, so we recurse to pick up
						// its IPs.
						collectIPsForName(clientIP, value, collectedNames)
					} else {
						// The RHS of the mapping is an IP, so add it to the list that we
						// will return.
						ips = append(ips, value)
					}
				}
			}
		}
		if isWildcard(domain) {
			regex := s.wildcards[domain]
			if regex == nil {
				// Need to build corresponding regexp.
				regexpString := wildcardToRegexpString(domain)
				var err error
				regex, err = regexp.Compile(regexpString)
				if err != nil {
					log.WithError(err).Panicf("Couldn't compile regexp %v for wildcard %v", regexpString, domain)
				}
				s.wildcards[domain] = regex
			}
			for clientIP, cl := range s.dnsLookup {
				for name := range cl.mappings {
					if regex.MatchString(name) {
						collectIPsForName(clientIP, name, set.New[string]())
					}
				}
			}
		} else {
			for clientIP := range s.dnsLookup {
				collectIPsForName(clientIP, domain, set.New[string]())
			}
		}
		s.resultsCache[domain] = ips
	}
	log.Debugf("GetDomainIPs(%v) -> %v", domain, ips)
	return ips
}

// IterWatchedDomainsForIP iterates over the watched domain associated with an IP. The "watch" refers to an explicit
// request to GetDomainIPs.
//
// The signature of this method is somewhat specific to how the collector stores connection data and is used to
// minimize allocations during connection processing.
func (s *DomainInfoStore) IterWatchedDomainsForIP(clientIP string, ip [16]byte, cb func(domain string) (stop bool)) {
	// We only need the read lock to access this data.
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var stop bool
	clk := s.dnsLookup[clientIP]
	if clk != nil {
		if ipData := s.dnsLookup[clientIP].reverse[ip]; ipData != nil {
			for nd := range ipData.nameDatas.All() {
				// Just return the first domain name we find. This should cover the most general case where the user adds
				// a single entry for a particular domain. Return the first "name to notify" that we find.
				for itemWatchedName := range nd.namesToNotify.All() {
					stop = cb(itemWatchedName)
					if stop {
						break
					}
				}
				if stop {
					break
				}
			}
		}
	}
}

// GetTopLevelDomainsForIP returns the set of top level domains associated with an IP and
// client IP.
//
// The signature of this method is somewhat specific to how the collector stores connection data and is used to
// minimize allocations during connection processing.
func (s *DomainInfoStore) GetTopLevelDomainsForIP(clientIP string, ip [16]byte) []string {
	// We only need the read lock to access this data.
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	clk := s.dnsLookup[clientIP]
	if clk != nil {
		if ipData := clk.reverse[ip]; ipData != nil {
			return ipData.topLevelDomains
		}
	}
	return nil
}

func isWildcard(domain string) bool {
	return strings.Contains(domain, "*")
}

func wildcardToRegexpString(wildcard string) string {
	nonWildParts := strings.Split(wildcard, "*")
	for i := range nonWildParts {
		nonWildParts[i] = regexp.QuoteMeta(nonWildParts[i])
	}
	return "^" + strings.Join(nonWildParts, ".*") + "$"
}

func (s *DomainInfoStore) compileChangedNames(clientIP, name string) {
	s.changedNames.Add(name)
	delete(s.resultsCache, name)

	clk := s.dnsLookup[clientIP]
	if clk != nil {
		if nameData := s.dnsLookup[clientIP].mappings[name]; nameData != nil {
			for ancestor := range nameData.namesToNotify.All() {
				s.changedNames.Add(ancestor)
				delete(s.resultsCache, ancestor)
			}
		}
	}
}

func (s *DomainInfoStore) collectGarbage() (numDeleted int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.gcTrigger {
		// Accumulate the mappings that are still useful.
		for _, clk := range s.dnsLookup {
			namesToKeep := set.New[string]()
			for name, nameData := range clk.mappings {
				// A mapping is still useful if it has any unexpired values, because policy
				// might be configured at any moment for that mapping's name, and then we'd
				// want to be able to return the corresponding IPs.
				if len(nameData.values) > 0 {
					namesToKeep.Add(name)
				}
				// A mapping X is also still useful if its name is the RHS of another
				// mapping Y, even if we don't currently have any values for X, because
				// there could be a GetDomainIPs(Y) call, and later a new value for X, and
				// in that case we need to be able to signal that the information for Y has
				// changed.
				for rhs, valueData := range nameData.values {
					if valueData.isName {
						namesToKeep.Add(rhs)
						// There must be a mapping for the RHS name.
						if clk.mappings[rhs] == nil {
							log.Panicf("Missing mapping for %v, which is a RHS value for %v", rhs, name)
						}
					}
				}
			}
			// Delete the mappings that are now useless.  Since this mapping contains no values, there can be no
			// corresponding reverse mappings to tidy up.
			for name := range clk.mappings {
				if !namesToKeep.Contains(name) {
					log.WithField("name", name).Debug("Delete useless mapping")
					delete(clk.mappings, name)
					numDeleted += 1
				}
			}
			// Reset the flag that will trigger the next GC.
			s.gcTrigger = false
		}
	}

	return
}

// releaseUnpairedDataForLogging releases request/response data that has had no corresponding response/request. This
// data is only cached for latency calculation for logging, and so if latency is not being measured then this is a
// no-op.
func (s *DomainInfoStore) releaseUnpairedDataForLogging(t time.Time) {
	if !s.measureLatency {
		// Only relevant if measuring latency.
		return
	}

	// Calculate the timestamps for expiring requests and responses.
	nowMillis := t.UnixMilli()
	requestCutoff := nowMillis - int64(maxHoldDurationRequest/time.Millisecond)
	responseCutoff := nowMillis - int64(maxHoldDurationResponse/time.Millisecond)

	// Check for any request timestamps that are now more than 10 seconds old, and discard those.
	// Check for any response timestamps that are now more than 1s old, and log and discard those.
	for key, data := range s.latencyData {
		if data.packet == nil {
			// Request.
			if data.queueTimestamp < requestCutoff {
				s.rateLimitedNoResponseLogger.Warnf("DNS-LATENCY: Missed DNS response for request with ID %v", key)
				delete(s.latencyData, key)
			}
		} else {
			// Response. We still need to log this response, but have not latency data associated with it.
			//
			// We only log this at debug level because it can be hit quite easily depending on the DNS client. In some
			// cases the client issues multiple requests in quick succession, each request from the same source port.
			// Because the same source port is used the second request will have conntrack state ESTABLISHED and will
			// not match the request snooping rule which matches state NEW. Ideally, these second and third packets
			// would be marked as RELATED (same 5-tuple but a different DNS request ID) - but there is no kernel module
			// for processing DNS requests and so the kernel is unable to correlate multiple DNS requests from the same
			// source. The related packets will therefore have no snooped request and therefore no latency info. Since
			// collector aggregates DNs logs there will still be latency info but it'll be based off of the first
			// request/response of the related packet pairs.
			if data.queueTimestamp < responseCutoff {
				s.rateLimitedNoRequestLogger.Debugf("DNS-LATENCY: Missed DNS request for response with ID %v", key)
				delete(s.latencyData, key)
				s.collector.LogDNS(data.serverIP, data.clientIP, data.packet, nil)
			}
		}
	}
}

// combineTopLevelDomains combines two sets of top level domains, putting the primary elements at the front (these are
// the most recently stored), and limiting the length.
func (s *DomainInfoStore) combineTopLevelDomains(primary, secondary []string) (combined []string) {
	if len(primary) == 0 {
		return secondary
	} else if len(secondary) == 0 {
		return primary
	} else if len(primary) >= s.maxTopLevelDomains {
		return primary[:s.maxTopLevelDomains]
	}
	primarySet := set.FromArray(primary)

	var missing []string
	for _, se := range secondary {
		if !primarySet.Contains(se) {
			missing = append(missing, se)
			if len(missing)+len(primary) >= s.maxTopLevelDomains {
				break
			}
		}
	}

	if missing == nil {
		return primary
	}

	return append(primary, missing...)
}
