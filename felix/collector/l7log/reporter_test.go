// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

package l7log

import (
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	net2 "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var (
	srcPort = 54123
	dstPort = 80

	proto_tcp    = 6
	localIp1Str  = "10.0.0.1"
	localIp1     = utils.IpStrTo16Byte(localIp1Str)
	localIp2Str  = "10.0.0.2"
	localIp2     = utils.IpStrTo16Byte(localIp2Str)
	remoteIp1Str = "20.0.0.1"
	remoteIp1    = utils.IpStrTo16Byte(remoteIp1Str)
	remoteIp2Str = "20.0.0.2"
	remoteIp2    = utils.IpStrTo16Byte(remoteIp2Str)

	localWlEp1 = &model.WorkloadEndpoint{
		State:    "active",
		Name:     "cali1",
		Mac:      utils.MustParseMac("01:02:03:04:05:06"),
		IPv4Nets: []net2.IPNet{utils.MustParseNet("10.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "local-ep-1",
		}),
	}
	remoteWlEp1 = &model.WorkloadEndpoint{
		State:    "active",
		Name:     "cali3",
		Mac:      utils.MustParseMac("02:02:03:04:05:06"),
		IPv4Nets: []net2.IPNet{utils.MustParseNet("20.0.0.1/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "remote-ep-1",
		}),
	}
	remoteWlEp2 = &model.WorkloadEndpoint{
		State:    "active",
		Name:     "cali4",
		Mac:      utils.MustParseMac("02:03:03:04:05:06"),
		IPv4Nets: []net2.IPNet{utils.MustParseNet("20.0.0.2/32")},
		Labels: uniquelabels.Make(map[string]string{
			"id": "remote-ep-2",
		}),
	}
)

type testL7Reporter struct {
	mutex sync.Mutex
	logs  []*L7Log
}

func (d *testL7Reporter) Start() error {
	return nil
}

func (d *testL7Reporter) Report(logSlice any) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.Info("In dispatch")
	fl := logSlice.([]*L7Log)
	d.logs = append(d.logs, fl...)
	return nil
}

func (d *testL7Reporter) getLogs() []*L7Log {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.logs
}

var _ = Describe("L7 Log Reporter", func() {
	var (
		ed1, ed2, ed3 calc.EndpointData
		dispatcher    *testL7Reporter
		flushTrigger  chan time.Time
		r             *L7Reporter
	)

	JustBeforeEach(func() {
		dispatcherMap := map[string]types.Reporter{}
		dispatcher = &testL7Reporter{}
		dispatcherMap["testL7"] = dispatcher
		flushTrigger = make(chan time.Time)
		// Set all the aggregation fields off
		agg := AggregationKind{
			HTTPHeader:      HTTPHeaderInfo,
			HTTPMethod:      HTTPMethod,
			Service:         ServiceInfo,
			Destination:     DestinationInfo,
			Source:          SourceInfo,
			TrimURL:         FullURL,
			ResponseCode:    ResponseCode,
			NumURLPathParts: -1,
			URLCharLimit:    100,
		}
		r = NewReporterWithShims(dispatcherMap, flushTrigger, nil)
		r.AddAggregator(NewAggregator().AggregateOver(agg), []string{"testL7"})
		Expect(r.Start()).NotTo(HaveOccurred())
		remoteWlEpKey1 := model.WorkloadEndpointKey{
			OrchestratorID: "orchestrator",
			WorkloadID:     "default/remoteworkloadid1",
			EndpointID:     "remoteepid1",
		}
		ed1 = calc.CalculateRemoteEndpoint(remoteWlEpKey1, remoteWlEp1)
		remoteWlEpKey2 := model.WorkloadEndpointKey{
			OrchestratorID: "orchestrator",
			WorkloadID:     "default/remoteworkloadid2",
			EndpointID:     "remoteepid2",
		}
		ed2 = calc.CalculateRemoteEndpoint(remoteWlEpKey2, remoteWlEp2)
		localWlEPKey1 := model.WorkloadEndpointKey{
			Hostname:       "localhost",
			OrchestratorID: "orchestrator",
			WorkloadID:     "default/localworkloadid1",
			EndpointID:     "localepid1",
		}
		ed3 = &calc.LocalEndpointData{
			CommonEndpointData: calc.CalculateCommonEndpointData(localWlEPKey1, localWlEp1),
			Ingress: &calc.MatchData{
				PolicyMatches: map[calc.PolicyID]int{
					{Name: "policy1"}: 0,
					{Name: "policy2"}: 0,
				},
				TierData: map[string]*calc.TierData{
					"default": {
						TierDefaultActionRuleID: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy2", "", calc.RuleIndexTierDefaultAction,
							rules.RuleDirIngress, rules.RuleActionDeny),
						EndOfTierMatchIndex: 0,
					},
				},
				ProfileMatchIndex: 0,
			},
			Egress: &calc.MatchData{
				PolicyMatches: map[calc.PolicyID]int{
					{Name: "policy1"}: 0,
					{Name: "policy2"}: 0,
				},
				TierData: map[string]*calc.TierData{
					"default": {
						TierDefaultActionRuleID: calc.NewRuleID(v3.KindGlobalNetworkPolicy, "default", "policy2", "", calc.RuleIndexTierDefaultAction,
							rules.RuleDirIngress, rules.RuleActionDeny),
						EndOfTierMatchIndex: 0,
					},
				},
				ProfileMatchIndex: 0,
			},
		}
	})

	It("should generate correct logs", func() {
		err := r.Report(Update{
			Tuple:         tuple.Make(remoteIp1, remoteIp2, proto_tcp, srcPort, dstPort),
			SrcEp:         ed1,
			DstEp:         ed2,
			Duration:      10,
			DurationMax:   12,
			BytesReceived: 500,
			BytesSent:     30,
			ResponseCode:  "200",
			Method:        "GET",
			Domain:        "www.test.com",
			Path:          "/test/path",
			UserAgent:     "firefox",
			Type:          "html/1.1",
			Count:         1,
		})
		Expect(err).NotTo(HaveOccurred())
		err = r.Report(Update{
			Tuple:         tuple.Make(remoteIp1, localIp1, proto_tcp, srcPort, dstPort),
			SrcEp:         ed1,
			DstEp:         ed3,
			Duration:      20,
			DurationMax:   22,
			BytesReceived: 30,
			BytesSent:     50,
			ResponseCode:  "200",
			Method:        "GET",
			Domain:        "www.testanother.com",
			Path:          "/test/different",
			UserAgent:     "firefox",
			Type:          "html/1.1",
			Count:         1,
		})
		Expect(err).NotTo(HaveOccurred())
		flushTrigger <- time.Now()
		time.Sleep(1 * time.Second)

		commonChecks := func(l *L7Log) {
			Expect(l.SourceNameAggr).To(Equal("remoteworkloadid1"))
			Expect(l.SourceNamespace).To(Equal("default"))
			Expect(l.SourceType).To(Equal(endpoint.Wep))

			Expect(l.Method).To(Equal("GET"))
			Expect(l.UserAgent).To(Equal("firefox"))
			Expect(l.ResponseCode).To(Equal("200"))
			Expect(l.Type).To(Equal("html/1.1"))
			Expect(l.Count).To(Equal(1))
		}

		Eventually(dispatcher.getLogs()).Should(HaveLen(2))
		logs := dispatcher.getLogs()

		for _, l := range logs {
			commonChecks(l)

			if l.DestNameAggr == "remoteworkloadid2" {
				// TODO: Add service name checks
				Expect(l.DurationMean).To(Equal(10 * time.Millisecond))
				Expect(l.DurationMax).To(Equal(12 * time.Millisecond))
				Expect(l.BytesIn).To(Equal(500))
				Expect(l.BytesOut).To(Equal(30))

				Expect(l.DestNameAggr).To(Equal("remoteworkloadid2"))
				Expect(l.DestNamespace).To(Equal("default"))
				Expect(l.DestType).To(Equal(endpoint.Wep))

				Expect(l.URL).To(Equal("www.test.com/test/path"))
			} else {
				Expect(l.DurationMean).To(Equal(20 * time.Millisecond))
				Expect(l.DurationMax).To(Equal(22 * time.Millisecond))
				Expect(l.BytesIn).To(Equal(30))
				Expect(l.BytesOut).To(Equal(50))

				Expect(l.DestNameAggr).To(Equal("localworkloadid1"))
				Expect(l.DestNamespace).To(Equal("default"))
				Expect(l.DestType).To(Equal(endpoint.Wep))

				Expect(l.URL).To(Equal("www.testanother.com/test/different"))
			}
		}
	})
})
