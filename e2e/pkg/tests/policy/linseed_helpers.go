// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	//nolint:staticcheck // Ignore ST1001: should not use dot imports
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	lsutil "github.com/projectcalico/calico/e2e/pkg/utils/linseed"
	lmaapi "github.com/projectcalico/calico/lma/pkg/api"
)

// expectFlowLogWithPolicy asserts that at least one flow log (matching the given source
// namespace and reporter) contains the expected policy hit in any of the policy trace
// fields (AllPolicies, EnforcedPolicies, PendingPolicies, or TransitPolicies).
// The PolicyHit is serialized via its canonical ToFlowLogPolicyString() method for comparison.
func expectFlowLogWithPolicy(c *lsutil.Client, srcNamespace, reporter string, expected lmaapi.PolicyHit) {
	expectedPolicy := lmaapi.ToFlowLogPolicyString(expected)
	selector := fmt.Sprintf("source_namespace = '%s' AND reporter = '%s'", srcNamespace, reporter)

	logrus.WithFields(logrus.Fields{
		"selector": selector,
		"policy":   expectedPolicy,
	}).Info("Asserting policy in Linseed flow logs")

	EventuallyWithOffset(1, func(g Gomega) {
		logs, err := lsutil.QueryFlowLogs(c, selector)
		g.Expect(err).NotTo(HaveOccurred(), "failed to query Linseed")
		g.Expect(logs).NotTo(BeEmpty(), "no flow logs found for selector %q", selector)

		// Strip the rule index (last "|<ruleID>") for comparison since the rule
		// index depends on the order of rules in the policy which is non-deterministic.
		expectedPrefix := expectedPolicy[:strings.LastIndex(expectedPolicy, "|")]

		// Collect all unique policies seen across all flow logs for the diagnostic error message.
		seen := make(map[string]struct{})
		found := false
		for _, fl := range logs {
			if fl.Policies == nil {
				continue
			}
			for _, plist := range [][]string{
				fl.Policies.AllPolicies,
				fl.Policies.EnforcedPolicies,
				fl.Policies.PendingPolicies,
				fl.Policies.TransitPolicies,
			} {
				for _, p := range plist {
					seen[p] = struct{}{}
					if strings.HasPrefix(p, expectedPrefix+"|") {
						found = true
					}
				}
			}
		}

		seenList := make([]string, 0, len(seen))
		for p := range seen {
			seenList = append(seenList, p)
		}
		sort.Strings(seenList)

		var seenDesc string
		if len(seenList) == 0 {
			seenDesc = "  (no policies in any flow log)"
		} else {
			seenDesc = "  " + strings.Join(seenList, "\n  ")
		}

		g.Expect(found).To(BeTrue(),
			"policy matching %q not found in %d flow logs (selector %q)\nActual policies seen:\n%s",
			expectedPrefix+"|*", len(logs), selector, seenDesc)
	}, 90*time.Second, 5*time.Second).Should(Succeed())
}

// waitForFlowLogWithPort polls until a WEP-type flow log with the given destination port
// appears in Linseed. An optional generateTraffic function is called each iteration to
// ensure traffic keeps flowing while waiting for the flow log.
func waitForFlowLogWithPort(lsclient *lsutil.Client, srcNamespace, destNamespace string, port int, generateTraffic ...func()) {
	EventuallyWithOffset(1, func() bool {
		if len(generateTraffic) > 0 {
			generateTraffic[0]()
		}
		selector := fmt.Sprintf(
			"source_namespace = '%s' AND dest_namespace = '%s' AND reporter = 'src'",
			srcNamespace, destNamespace,
		)
		logs, err := lsutil.QueryFlowLogs(lsclient, selector)
		if err != nil {
			return false
		}
		for _, fl := range logs {
			if fl.DestPort != nil && int(*fl.DestPort) == port {
				return true
			}
			if fl.DestServicePortNum != nil && int(*fl.DestServicePortNum) == port {
				return true
			}
		}
		return false
	}, 2*time.Minute, 15*time.Second).Should(BeTrue(),
		"timed out waiting for WEP-type flow log with dest_port=%d from %s to %s",
		port, srcNamespace, destNamespace)
}
