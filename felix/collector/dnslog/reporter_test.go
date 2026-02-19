// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package dnslog

import (
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket/layers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/utils"
	"github.com/projectcalico/calico/felix/testutils"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

type testReporter struct {
	mutex sync.Mutex
	logs  []*v1.DNSLog
}

func (d *testReporter) Start() error {
	return nil
}

func (d *testReporter) Report(logSlice interface{}) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	log.Info("In dispatch")
	fl := logSlice.([]*v1.DNSLog)
	d.logs = append(d.logs, fl...)
	return nil
}

func (d *testReporter) getLogs() []*v1.DNSLog {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return d.logs
}

type testSink struct {
	name          string
	includeLabels bool
	aggregation   AggregationKind
	aggregator    *Aggregator
	dispatcher    *testReporter
}

var _ = Describe("DNS Log Reporter", func() {
	var (
		sinks        []*testSink
		flushTrigger chan time.Time
		r            *DNSReporter
	)

	JustBeforeEach(func() {
		sinks = nil
		sinks = append(sinks, &testSink{name: "noLabelsOrAgg", includeLabels: false, aggregation: DNSDefault})
		sinks = append(sinks, &testSink{name: "LabelsAndAgg", includeLabels: true, aggregation: DNSPrefixNameAndIP})
		sinks = append(sinks, &testSink{name: "LabelsNoAgg", includeLabels: true, aggregation: DNSDefault})
		dispatcherMap := map[string]types.Reporter{}
		for _, sink := range sinks {
			sink.aggregator = NewAggregator().IncludeLabels(sink.includeLabels).AggregateOver(sink.aggregation)
			sink.dispatcher = &testReporter{}
			dispatcherMap[sink.name] = sink.dispatcher
		}
		flushTrigger = make(chan time.Time)
		r = NewReporterWithShims(dispatcherMap, flushTrigger, nil)
		for _, sink := range sinks {
			r.AddAggregator(sink.aggregator, []string{sink.name})
		}
		Expect(r.Start()).NotTo(HaveOccurred())
	})

	It("should generate correct logs", func() {
		dns := &layers.DNS{}
		dns.Questions = append(dns.Questions, testutils.MakeQ("google.com"))
		dns.Answers = append(dns.Answers, testutils.MakeA("google.com", "1.1.1.1"))

		client1 := calc.CalculateRemoteEndpoint(
			model.WorkloadEndpointKey{
				Hostname:       "host1",
				OrchestratorID: "k8s",
				WorkloadID:     "alice/test1-a345cf",
				EndpointID:     "ep1",
			},
			&model.WorkloadEndpoint{
				Name:         "test1-a345cf",
				GenerateName: "test1",
				Labels: uniquelabels.Make(map[string]string{
					"group":    "test1",
					"name":     "test1-a345cf",
					"common":   "red",
					"specific": "socks",
				}),
			},
		)
		client2 := calc.CalculateRemoteEndpoint(
			model.WorkloadEndpointKey{
				Hostname:       "host1",
				OrchestratorID: "k8s",
				WorkloadID:     "alice/test1-56dca3",
				EndpointID:     "ep2",
			},
			&model.WorkloadEndpoint{
				Name:         "test1-56dca3",
				GenerateName: "test1",
				Labels: uniquelabels.Make(map[string]string{
					"group":    "test1",
					"name":     "test1-56dca3",
					"common":   "red",
					"specific": "shoes",
				}),
			},
		)
		err := r.Report(Update{
			ClientEP: client1,
			ClientIP: net.ParseIP("1.2.3.4"),
			ServerIP: net.ParseIP("8.8.8.8"),
			DNS:      dns,
		})
		Expect(err).NotTo(HaveOccurred())
		err = r.Report(Update{
			ClientEP: client2,
			ClientIP: net.ParseIP("1.2.3.5"),
			ServerIP: net.ParseIP("8.8.8.8"),
			DNS:      dns,
		})
		Expect(err).NotTo(HaveOccurred())
		flushTrigger <- time.Now()

		commonChecks := func(l *v1.DNSLog) {
			Expect(l.ClientNameAggr).To(Equal("test1*"))
			Expect(l.ClientNamespace).To(Equal("alice"))
		}

		// Logs with no aggregation and no labels.
		Eventually(sinks[0].dispatcher.getLogs).Should(HaveLen(2))
		for _, l := range sinks[0].dispatcher.getLogs() {
			commonChecks(l)
			Expect(l.Count).To(BeNumerically("==", 1))
			Expect(l.ClientName).To(ContainSubstring("test1-"))
			Expect(l.ClientIP).NotTo(BeNil())
			Expect(*l.ClientIP).To(ContainSubstring("1.2.3."))
			Expect(l.ClientLabels.IsNil()).To(BeTrue())
		}

		// Logs with aggregation and labels.
		Eventually(sinks[1].dispatcher.getLogs).Should(HaveLen(1))
		for _, l := range sinks[1].dispatcher.getLogs() {
			commonChecks(l)
			Expect(l.Count).To(BeNumerically("==", 2))
			Expect(l.ClientName).To(Equal(utils.FieldNotIncluded))
			Expect(l.ClientIP).To(BeNil())
			Expect(l.ClientLabels.RecomputeOriginalMap()).To(Equal(map[string]string{
				"group":  "test1",
				"common": "red",
			}))
		}

		// Logs with labels but no aggregation.
		Eventually(sinks[2].dispatcher.getLogs).Should(HaveLen(2))
		for _, l := range sinks[2].dispatcher.getLogs() {
			commonChecks(l)
			Expect(l.Count).To(BeNumerically("==", 1))
			Expect(l.ClientName).To(ContainSubstring("test1-"))
			Expect(l.ClientIP).NotTo(BeNil())
			Expect(*l.ClientIP).To(ContainSubstring("1.2.3."))
			Expect(l.ClientLabels.RecomputeOriginalMap()).To(Or(
				Equal(map[string]string{
					"group":    "test1",
					"name":     "test1-a345cf",
					"common":   "red",
					"specific": "socks",
				}),
				Equal(map[string]string{
					"group":    "test1",
					"name":     "test1-56dca3",
					"common":   "red",
					"specific": "shoes",
				})))
		}
	})
})
