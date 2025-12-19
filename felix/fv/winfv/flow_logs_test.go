// Copyright (c) 2022-2025 Tigera, Inc. All rights reserved.

package winfv_test

import (
	"errors"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	log "github.com/sirupsen/logrus"
	"github.com/tigera/windows-networking/pkg/testutils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/felix/fv/flowlogs"
	. "github.com/projectcalico/calico/felix/fv/winfv"
	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

func init() {
	// Stop Gomega from chopping off diffs in logs.
	format.MaxLength = 0
}

// Generate traffic flows to test flow logs on Windows nodes.
// Common features which are not specific on Windows (e.g. cloudwatch)
// are tested with Linux FVs.
//
// Infra setup
//
//             Windows node                         Linx node
//
//              porter                          client (allowed to porter)
//                                              client-b (denied to porter)
//                                              nginx
//

type aggregation int

const (
	AggrNone         aggregation = 0
	AggrBySourcePort aggregation = 1
	AggrByPodPrefix  aggregation = 2
)

type expectation struct {
	labels                bool
	policies              bool
	aggregationForAllowed aggregation
	aggregationForDenied  aggregation
}

var _ = Describe("Windows flow logs test", func() {
	var (
		expectation                    expectation
		flowLogsReaders                []flowlogs.FlowLogReader
		porter, client, clientB, nginx string
		fv                             *WinFV
		err                            error
	)

	BeforeEach(func() {
		Skip("Temporarily skip failing flow log tests on HPC") //TODO
		fv, err = NewWinFV(winutils.GetHostPath("c:\\CalicoWindows"),
			winutils.GetHostPath("c:\\TigeraCalico\\flowlogs"),
			winutils.GetHostPath("c:\\TigeraCalico\\felix-dns-cache.txt"))
		Expect(err).NotTo(HaveOccurred())

		flowLogsReaders = []flowlogs.FlowLogReader{fv}

		// Get Pod IPs.
		client = testutils.InfraPodIP("client", "demo")
		clientB = testutils.InfraPodIP("client-b", "demo")
		porter = testutils.InfraPodIP("porter", "demo")
		nginx = testutils.InfraPodIP("nginx", "demo")
		log.Infof("Pod IP client %s, client-b %s, porter %s, nginx %s",
			client, clientB, porter, nginx)

		Expect(client).NotTo(BeEmpty())
		Expect(clientB).NotTo(BeEmpty())
		Expect(porter).NotTo(BeEmpty())
		Expect(nginx).NotTo(BeEmpty())
	})

	AfterEach(func() {
		err := fv.RestoreConfig()
		Expect(err).NotTo(HaveOccurred())
	})

	checkFlowLogs := func() {
		// Within 60s we should see the complete set of expected allow and deny
		// flow logs.
		Eventually(func() error {
			flowTester := flowlogs.NewFlowTesterDeprecated(flowLogsReaders, expectation.labels, expectation.policies, 80)
			err := flowTester.PopulateFromFlowLogs()
			if err != nil {
				return err
			}

			// Only report errors at the end.
			var errs []string

			// Now we tick off each FlowMeta that we expect, and check that
			// the log(s) for each one are present and as expected.
			switch expectation.aggregationForAllowed {
			case AggrNone:
				err = flowTester.CheckFlow(
					"wep demo client client", client,
					"wep demo porter porter", porter,
					flowlogs.NoService, 1, 1,
					[]flowlogs.ExpectedPolicy{
						{
							Reporter:         "dst",
							Action:           "allow",
							EnforcedPolicies: []string{"0|default|demo/knp.default.allow-client|allow|0"},
						},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; flow 1: %v", err))
				}
				err = flowTester.CheckFlow(
					"wep demo porter porter", porter,
					"wep demo nginx nginx", nginx,
					"demo nginx - 80", 1, 1,
					[]flowlogs.ExpectedPolicy{
						{
							Reporter:         "src",
							Action:           "allow",
							EnforcedPolicies: []string{"0|default|demo/knp.default.allow-nginx|allow|0"},
						},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; flow 2: %v", err))
				}
			case AggrByPodPrefix:
				err = flowTester.CheckFlow(
					"wep demo - client", "",
					"wep demo - porter", "",
					flowlogs.NoService, 1, 1,
					[]flowlogs.ExpectedPolicy{
						{
							Reporter:         "dst",
							Action:           "allow",
							EnforcedPolicies: []string{"0|default|demo/knp.default.allow-client|allow|0"},
						},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; flow 1: %v", err))
				}
				err = flowTester.CheckFlow(
					"wep demo - porter", "",
					"wep demo - nginx", "",
					"demo nginx - 80", 1, 1,
					[]flowlogs.ExpectedPolicy{
						{
							Reporter:         "src",
							Action:           "allow",
							EnforcedPolicies: []string{"0|default|demo/knp.default.allow-nginx|allow|0"},
						},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for allowed; agg pod prefix; flow 2: %v", err))
				}
			}
			switch expectation.aggregationForDenied {
			case AggrNone:
				err = flowTester.CheckFlow(
					"wep demo client-b client-b", clientB,
					"wep demo porter porter", porter,
					flowlogs.NoService, 1, 1,
					[]flowlogs.ExpectedPolicy{
						{
							Reporter:         "dst",
							Action:           "deny",
							EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.__NO_MATCH__|deny|0"},
						},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for denied; agg pod prefix: %v", err))
				}
			case AggrBySourcePort:
				err = flowTester.CheckFlow(
					"wep demo client-b client-b", clientB,
					"wep demo porter porter", porter,
					flowlogs.NoService, 1, 1,
					[]flowlogs.ExpectedPolicy{
						{
							Reporter:         "dst",
							Action:           "deny",
							EnforcedPolicies: []string{"0|__PROFILE__|__PROFILE__.__NO_MATCH__|deny|0"},
						},
					})
				if err != nil {
					errs = append(errs, fmt.Sprintf("Error agg for denied; agg pod prefix: %v", err))
				}
			}

			// Finally check that there are no remaining flow logs that we did not expect.
			err = flowTester.CheckAllFlowsAccountedFor()
			if err != nil {
				errs = append(errs, err.Error())
			}

			if len(errs) == 0 {
				return nil
			}

			return errors.New(strings.Join(errs, "\n==============\n"))

		}, "60s", "10s").ShouldNot(HaveOccurred())
	}

	Context("File flow logs only", func() {
		setupAndRunFelix := func(config map[string]any) {
			err := fv.AddConfigItems(config)
			Expect(err).NotTo(HaveOccurred())

			fv.RestartFelix()

			// Initiate traffic.
			testutils.InfraInitiateTraffic()
		}

		It("should get expected flow logs with no aggregation", func() {
			expectation.labels = true
			expectation.policies = true
			expectation.aggregationForAllowed = AggrNone
			expectation.aggregationForDenied = AggrNone

			zero := 0
			var tenSeconds metav1.Duration
			tenSeconds.Duration = 10 * time.Second
			config := map[string]any{
				"FlowLogsFileAggregationKindForAllowed": &zero,
				"FlowLogsFileAggregationKindForDenied":  &zero,
				"FlowLogsFlushInterval":                 &tenSeconds,
			}
			setupAndRunFelix(config)

			checkFlowLogs()
		})

		It("should get expected flow logs with default aggregation", func() {
			expectation.labels = true
			expectation.policies = true
			expectation.aggregationForAllowed = AggrByPodPrefix
			expectation.aggregationForDenied = AggrBySourcePort

			one := 1
			two := 2
			var tenSeconds metav1.Duration
			tenSeconds.Duration = 10 * time.Second
			config := map[string]any{
				"FlowLogsFileAggregationKindForAllowed": &two,
				"FlowLogsFileAggregationKindForDenied":  &one,
				"FlowLogsFlushInterval":                 &tenSeconds,
			}
			setupAndRunFelix(config)

			checkFlowLogs()
		})
	})
})
