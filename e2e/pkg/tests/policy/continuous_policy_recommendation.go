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
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
	"github.com/projectcalico/calico/e2e/pkg/utils/conncheck"
	lsutil "github.com/projectcalico/calico/e2e/pkg/utils/linseed"
	mgrutil "github.com/projectcalico/calico/e2e/pkg/utils/manager"
	lmaapi "github.com/projectcalico/calico/lma/pkg/api"
	polrecres "github.com/projectcalico/calico/policy-recommendation/pkg/calico-resources"
	polrectypes "github.com/projectcalico/calico/policy-recommendation/pkg/types"
)

const (
	// recommendationInterval is how often the engine evaluates flow logs.
	// The engine enforces a minimum of > 30 seconds; values <= 30s are rejected
	// and the engine falls back to its 10-minute default.
	recommendationInterval = 32 * time.Second

	// recommendationStabilization is how long a recommendation must remain unchanged
	// before it is marked Stable. Must be greater than recommendationInterval.
	recommendationStabilization = 37 * time.Second

	// flowLogsFlushInterval controls how quickly Felix flushes flow logs.
	flowLogsFlushInterval = 10 * time.Second
)

// DESCRIPTION: This test verifies the policy recommendation engine lifecycle: generating
// recommendations for cross-namespace traffic, validating their structure and flow log presence,
// stabilization, enforcement via the manager API (stagedAction=Set), and that enforced policies
// are not modified by new traffic. It also verifies the disable/re-enable cycle.
//
// DOCS_URL: https://docs.tigera.io/calico-enterprise/latest/network-policy/recommendations
var _ = describe.EnterpriseDescribe(
	describe.WithTeam(describe.EV),
	describe.WithFeature("Continuous-Policy-Recommendations"),
	describe.WithCategory(describe.Policy),
	describe.WithSerial(),
	framework.WithConformance(),
	"continuous policy recommendation",
	func() {
		const serverNamespacePrefix = "server-namespace"

		var (
			f               = utils.NewDefaultFramework("client-namespace")
			cclient         ctrlclient.Client
			checker         conncheck.ConnectionTester
			client1         *conncheck.Client
			clientNamespace string
			lsclient        *lsutil.Client
			server          *conncheck.Server
			serverNamespace *v1.Namespace
			resetFlush      func()
			cancelPortFwd   func()
		)

		BeforeEach(func() {
			var err error

			// --- Linseed client ---
			cancelPortFwd = lsutil.PortForward()
			lsclient = lsutil.InitClient(f)
			lsutil.WaitForLinseed(lsclient)

			// --- Calico client ---
			cclient, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// --- Felix Configuration ---
			resetFlush, err = utils.SetFlowLogsFlushInterval(cclient, flowLogsFlushInterval)
			Expect(err).NotTo(HaveOccurred())

			// Clean up any leftover recommendation state from a previous interrupted run.
			resetPolicyRecommendationScope(cclient)
			deleteRecommendationTier(cclient, polrectypes.PolicyRecommendationTierName)

			// --- Namespaces ---
			clientNamespace = f.Namespace.Name
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			serverNamespace, err = f.CreateNamespace(ctx, serverNamespacePrefix, map[string]string{"ns-name": serverNamespacePrefix})
			Expect(err).NotTo(HaveOccurred())

			// --- Pods ---
			checker = conncheck.NewConnectionTester(f)
			server = conncheck.NewServer(utils.GenerateRandomName("server"), serverNamespace)
			checker.AddServer(server)
			client1 = conncheck.NewClient(utils.GenerateRandomName("client"), f.Namespace)
			checker.AddClient(client1)
			checker.Deploy()

			// --- Baseline traffic (no policies yet) ---
			By("Executing a connection test without any policy")
			checker.ExpectSuccess(client1, server.ClusterIPs()...)
			checker.Execute()

			By("Validating profile policies appear in flow logs")
			expectFlowLogWithPolicy(lsclient, clientNamespace, "src", profilePolicyHit(clientNamespace))
			expectFlowLogWithPolicy(lsclient, clientNamespace, "dst", profilePolicyHit(serverNamespace.Name))
		})

		AfterEach(func() {
			if checker != nil {
				checker.Stop()
			}
			if cancelPortFwd != nil {
				cancelPortFwd()
			}
			if resetFlush != nil {
				resetFlush()
			}

			// Best-effort cleanup: disable recommendations and reset scope to defaults.
			// Errors are logged but do not fail the teardown so that remaining cleanup still runs.
			if cclient != nil {
				resetPolicyRecommendationScope(cclient)
				deleteRecommendationTier(cclient, polrectypes.PolicyRecommendationTierName)
			}
		})

		// --- Test 1: full recommendation lifecycle ---

		It("should generate, stabilize, and enforce recommendations for cross-namespace traffic", func() {
			// --- Manager client (only needed for enforcement in this test) ---
			mgrPort, cancelMgrPortFwd := mgrutil.PortForward()
			defer cancelMgrPortFwd()
			mgrclient := mgrutil.NewClient(context.Background(), f, mgrPort)
			mgrutil.WaitForManager(mgrclient)

			recTier := polrectypes.PolicyRecommendationTierName
			_, err := enablePolicyRecommendation(cclient, recommendationInterval, recommendationStabilization, clientNamespace, serverNamespace.Name)
			Expect(err).NotTo(HaveOccurred())

			// Deploy a second server (port 8080) and an intra-namespace client to exercise
			// multiple traffic patterns: cross-ns to two ports + intra-ns.
			server2 := conncheck.NewServer(utils.GenerateRandomName("server2"), serverNamespace, conncheck.WithPorts(8080))
			checker.AddServer(server2)
			intraNSClient := conncheck.NewClient(utils.GenerateRandomName("intra-cli"), serverNamespace)
			checker.AddClient(intraNSClient)
			checker.Deploy()

			generateAllTraffic := func() {
				checker.ResetExpectations()
				checker.ExpectSuccess(client1, server.ClusterIPs()...)
				for _, t := range server2.ClusterIPs() {
					checker.ExpectSuccess(client1, t.Port(8080))
				}
				checker.ExpectSuccess(intraNSClient, server.ClusterIPs()...)
				checker.Execute()
			}

			// --- Phase 1: generate & validate recommendations ---

			By("Generating traffic until flow logs appear for all ports")
			waitForFlowLogWithPort(lsclient, clientNamespace, serverNamespace.Name, 8080, generateAllTraffic)

			By("Waiting for recommendations covering both ports in the custom tier")
			waitForRecommendationsInTierWithPorts(cclient, clientNamespace, recTier, 80, 8080)
			srcRec := waitForRecommendationInTier(cclient, clientNamespace, recTier)
			dstRec := waitForRecommendationInTier(cclient, serverNamespace.Name, recTier)

			By("Validating recommendation structure, tier, and rule actions")
			validateRecommendation(srcRec, "egress", numorstring.ProtocolFromString("TCP"), recTier, 80, 8080)
			validateRecommendation(dstRec, "ingress", numorstring.ProtocolFromString("TCP"), recTier, 80, 8080)

			By("Generating traffic so flow logs reflect the staged policies")
			generateAllTraffic()

			By("Validating staged policies appear in flow logs")
			expectFlowLogWithPolicy(lsclient, clientNamespace, "src", namespacedPolicyHit(v3.KindStagedNetworkPolicy, recTier, srcRec.Name, clientNamespace))
			expectFlowLogWithPolicy(lsclient, clientNamespace, "dst", namespacedPolicyHit(v3.KindStagedNetworkPolicy, recTier, dstRec.Name, serverNamespace.Name))

			// --- Phase 2: stabilize & enforce ---

			By("Waiting for stabilization")
			waitForRecommendationStatus(cclient, clientNamespace, polrecres.StableStatus)

			By("Enforcing recommendations via the manager API")
			srcRec = waitForRecommendationInTier(cclient, clientNamespace, recTier)
			dstRec = waitForRecommendationInTier(cclient, serverNamespace.Name, recTier)
			mgrclient.BatchEnforce([]mgrutil.StagedNetworkPolicyRef{
				{Name: srcRec.Name, Namespace: srcRec.Namespace, UID: string(srcRec.UID), ResourceVersion: srcRec.ResourceVersion},
				{Name: dstRec.Name, Namespace: dstRec.Namespace, UID: string(dstRec.UID), ResourceVersion: dstRec.ResourceVersion},
			})

			By("Verifying enforced StagedNetworkPolicies have stagedAction=Set and no owner references")
			Eventually(func(g Gomega) {
				evCtx, evCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer evCancel()
				list := v3.NewStagedNetworkPolicyList()
				g.Expect(cclient.List(evCtx, list, ctrlclient.InNamespace(clientNamespace))).NotTo(HaveOccurred())
				found := false
				for _, snp := range list.Items {
					if snp.Spec.Tier == recTier && snp.Spec.StagedAction == v3.StagedActionSet {
						found = true
						g.Expect(snp.OwnerReferences).To(BeEmpty(),
							"enforced StagedNetworkPolicy %s/%s should not have owner references", snp.Namespace, snp.Name)
					}
				}
				g.Expect(found).To(BeTrue(), "expected at least one StagedNetworkPolicy with stagedAction=Set in tier %s", recTier)
			}, 30*time.Second, 5*time.Second).Should(Succeed())

			// --- Phase 3: verify enforced policies are not modified by new traffic ---

			By("Snapshotting the enforced policy's egress rule count before new traffic")
			srcRec = waitForRecommendationInTier(cclient, clientNamespace, recTier)
			egressRulesBefore := len(srcRec.Spec.Egress)

			By("Deploying a new server on port 9090 and generating traffic that would require a new rule")
			server3 := conncheck.NewServer(utils.GenerateRandomName("server3"), serverNamespace, conncheck.WithPorts(9090))
			checker.AddServer(server3)
			checker.Deploy()

			generateNewTraffic := func() {
				checker.ResetExpectations()
				for _, t := range server3.ClusterIPs() {
					checker.ExpectSuccess(client1, t.Port(9090))
				}
				checker.Execute()
			}
			generateNewTraffic()
			waitForFlowLogWithPort(lsclient, clientNamespace, serverNamespace.Name, 9090, generateNewTraffic)

			By("Verifying the enforced policy is unchanged and no new Learn recommendations appear")
			Consistently(func(g Gomega) {
				cCtx, cCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cCancel()
				list := v3.NewStagedNetworkPolicyList()
				g.Expect(cclient.List(cCtx, list, ctrlclient.InNamespace(clientNamespace))).NotTo(HaveOccurred())
				for _, snp := range list.Items {
					if _, ok := snp.Annotations[polrecres.StatusKey]; !ok {
						continue
					}
					if snp.Spec.Tier == recTier && snp.Spec.StagedAction == v3.StagedActionSet {
						g.Expect(snp.Spec.Egress).To(HaveLen(egressRulesBefore),
							"enforced policy %s should not gain new egress rules", snp.Name)
					}
					g.Expect(snp.Spec.StagedAction).NotTo(Equal(v3.StagedActionLearn),
						"engine should not create new Learn recommendations when enforced policy exists: %s", snp.Name)
				}
			}, recommendationInterval*3/2, 5*time.Second).Should(Succeed())
		})

		// --- Test 2: disable / re-enable ---

		It("should stop generating recommendations when disabled and resume when re-enabled", func() {
			stopRec, err := enablePolicyRecommendation(cclient, recommendationInterval, recommendationStabilization, clientNamespace, serverNamespace.Name)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for initial recommendations")
			waitForRecommendation(cclient, clientNamespace)

			By("Disabling policy recommendation")
			Expect(stopRec()).NotTo(HaveOccurred())

			By("Creating a new namespace with traffic while recommendation is disabled")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			extraNS, err := f.CreateNamespace(ctx, "extra-ns", map[string]string{"ns-name": "extra-ns"})
			Expect(err).NotTo(HaveOccurred())

			extraServer := conncheck.NewServer(utils.GenerateRandomName("extra-srv"), extraNS)
			checker.AddServer(extraServer)
			extraClient := conncheck.NewClient(utils.GenerateRandomName("extra-cli"), extraNS)
			checker.AddClient(extraClient)
			checker.Deploy()
			checker.ExpectSuccess(extraClient, extraServer.ClusterIPs()...)
			checker.Execute()

			By("Verifying no recommendations are generated for the new namespace while disabled")
			// Wait 1.5× the engine interval to be sure the engine had a chance to run and produced nothing.
			Consistently(func() int {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				list := v3.NewStagedNetworkPolicyList()
				Expect(cclient.List(ctx, list, ctrlclient.InNamespace(extraNS.Name))).NotTo(HaveOccurred())
				return len(list.Items)
			}, recommendationInterval*3/2, 5*time.Second).Should(Equal(0),
				"no recommendations should be generated while disabled")

			By("Re-enabling policy recommendation")
			_, err = enablePolicyRecommendation(cclient, recommendationInterval, recommendationStabilization, clientNamespace, serverNamespace.Name, extraNS.Name)
			Expect(err).NotTo(HaveOccurred())

			By("Generating more traffic in the new namespace")
			checker.Execute()

			By("Verifying recommendations resume for the new namespace")
			waitForRecommendation(cclient, extraNS.Name)
		})
	})

// ---------------------------------------------------------------------------
// Flow log policy hit builders
// ---------------------------------------------------------------------------

// profilePolicyHit returns a PolicyHit for a Kubernetes namespace profile allow rule.
func profilePolicyHit(namespace string) lmaapi.PolicyHit {
	ruleIdx := 0
	ph, err := lmaapi.NewPolicyHit(lmaapi.ActionAllow, 0, "kns."+namespace, "", v3.KindProfile, "__PROFILE__", &ruleIdx)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return ph
}

// namespacedPolicyHit returns a PolicyHit for a namespaced policy allow rule.
func namespacedPolicyHit(kind, tier, policyName, namespace string) lmaapi.PolicyHit {
	ruleIdx := 0
	ph, err := lmaapi.NewPolicyHit(lmaapi.ActionAllow, 0, policyName, namespace, kind, tier, &ruleIdx)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return ph
}

// ---------------------------------------------------------------------------
// Recommendation helpers
// ---------------------------------------------------------------------------

// waitForRecommendation polls until a StagedNetworkPolicy appears in the given
// namespace and returns it. It fails the test if none appears within 1 minute.
func waitForRecommendation(c ctrlclient.Client, namespace string) *v3.StagedNetworkPolicy {
	var rec *v3.StagedNetworkPolicy
	EventuallyWithOffset(1, func() (err error) {
		rec, err = findRecommendation(c, namespace)
		return
	}, 1*time.Minute, 3*time.Second).Should(Succeed(),
		"expected a staged network policy recommendation in namespace %s", namespace)
	return rec
}

// findRecommendation returns the first StagedNetworkPolicy in the given namespace,
// or an error if none exist yet. It intentionally does no validation so callers
// can assert on the returned object directly.
func findRecommendation(c ctrlclient.Client, namespace string) (*v3.StagedNetworkPolicy, error) {
	return findRecommendationInTier(c, namespace, "")
}

// findRecommendationInTier returns the first StagedNetworkPolicy in the given namespace
// and tier. If tierName is empty, any tier matches.
func findRecommendationInTier(c ctrlclient.Client, namespace, tierName string) (*v3.StagedNetworkPolicy, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list := v3.NewStagedNetworkPolicyList()
	if err := c.List(ctx, list, ctrlclient.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("listing staged network policies: %w", err)
	}
	for i := range list.Items {
		if _, ok := list.Items[i].Annotations[polrecres.StatusKey]; !ok {
			continue
		}
		if tierName != "" && list.Items[i].Spec.Tier != tierName {
			continue
		}
		return &list.Items[i], nil
	}
	return nil, fmt.Errorf("no recommendations found in namespace %s tier %q (saw %d staged policies)", namespace, tierName, len(list.Items))
}

// waitForRecommendationInTier polls until a StagedNetworkPolicy in the given tier
// appears in the namespace.
func waitForRecommendationInTier(c ctrlclient.Client, namespace, tierName string) *v3.StagedNetworkPolicy {
	var rec *v3.StagedNetworkPolicy
	EventuallyWithOffset(1, func() (err error) {
		rec, err = findRecommendationInTier(c, namespace, tierName)
		return
	}, 90*time.Second, 3*time.Second).Should(Succeed(),
		"expected a staged network policy recommendation in namespace %s tier %s", namespace, tierName)
	return rec
}

// waitForRecommendationsInTierWithPorts polls until recommendations in the given namespace
// and tier collectively contain egress rules covering all specified destination ports.
func waitForRecommendationsInTierWithPorts(c ctrlclient.Client, namespace, tierName string, expectedPorts ...uint16) {
	EventuallyWithOffset(1, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		list := v3.NewStagedNetworkPolicyList()
		if err := c.List(ctx, list, ctrlclient.InNamespace(namespace)); err != nil {
			return fmt.Errorf("listing recommendations: %w", err)
		}
		ports := make(map[uint16]bool)
		for _, rec := range list.Items {
			if _, ok := rec.Annotations[polrecres.StatusKey]; !ok {
				continue
			}
			if rec.Spec.Tier != tierName {
				continue
			}
			for _, rule := range rec.Spec.Egress {
				for _, p := range rule.Destination.Ports {
					ports[p.MinPort] = true
				}
			}
		}
		for _, ep := range expectedPorts {
			if !ports[ep] {
				return fmt.Errorf("port %d not found in tier %s recommendations (ports seen: %v)", ep, tierName, ports)
			}
		}
		return nil
	}, 90*time.Second, 5*time.Second).Should(Succeed(),
		"recommendations in %s tier %s should include egress rules for ports %v", namespace, tierName, expectedPorts)
}

// waitForRecommendationStatus polls until a recommendation in the given namespace
// has the expected status annotation value. It returns the matching recommendation.
func waitForRecommendationStatus(c ctrlclient.Client, namespace, expectedStatus string) *v3.StagedNetworkPolicy {
	var rec *v3.StagedNetworkPolicy
	EventuallyWithOffset(1, func(g Gomega) {
		r, err := findRecommendation(c, namespace)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(r.Annotations).To(HaveKeyWithValue(polrecres.StatusKey, expectedStatus),
			"recommendation %s status is %q, waiting for %q", r.Name, r.Annotations[polrecres.StatusKey], expectedStatus)
		rec = r
	}, 2*time.Minute, 5*time.Second).Should(Succeed(),
		"recommendation in %s should reach %s status", namespace, expectedStatus)
	return rec
}

// validateRecommendation asserts that the staged network policy has the expected
// structure: StagedAction=Learn, a single Allow rule for the given direction,
// port, and protocol.
func validateRecommendation(rec *v3.StagedNetworkPolicy, direction string, protocol numorstring.Protocol, tierName string, expectedPorts ...uint16) {
	ExpectWithOffset(1, rec.Spec.StagedAction).To(Equal(v3.StagedActionLearn), "recommendation %s should have StagedAction=Learn", rec.Name)
	ExpectWithOffset(1, rec.Spec.Tier).To(Equal(tierName), "recommendation %s should be in tier %s", rec.Name, tierName)

	var rules []v3.Rule
	switch direction {
	case "egress":
		rules = rec.Spec.Egress
	case "ingress":
		rules = rec.Spec.Ingress
	default:
		Fail(fmt.Sprintf("unsupported direction %q, expected egress or ingress", direction))
	}

	ExpectWithOffset(1, rules).NotTo(BeEmpty(), "recommendation %s should have at least one %s rule", rec.Name, direction)

	// Collect all ports across all rules in the given direction.
	foundPorts := make(map[uint16]bool)
	for _, r := range rules {
		ExpectWithOffset(1, r.Action).To(Equal(v3.Allow), "%s rule in %s should be Allow", direction, rec.Name)
		ExpectWithOffset(1, r.Protocol).NotTo(BeNil(), "%s rule in %s should specify a protocol", direction, rec.Name)
		ExpectWithOffset(1, *r.Protocol).To(Equal(protocol), "%s rule in %s should match protocol %s", direction, rec.Name, protocol)
		for _, p := range r.Destination.Ports {
			foundPorts[p.MinPort] = true
		}
	}
	for _, ep := range expectedPorts {
		ExpectWithOffset(1, foundPorts).To(HaveKey(ep),
			"recommendation %s %s rules should include port %d, found ports: %v", rec.Name, direction, ep, foundPorts)
	}
}

// ---------------------------------------------------------------------------
// Tier / recommendation scope lifecycle
// ---------------------------------------------------------------------------

// deleteRecommendationTier deletes the given tier and all StagedNetworkPolicy
// and NetworkPolicy objects belonging to it. It is best-effort: individual
// deletion errors are logged but do not prevent cleanup of remaining resources.
// It is a no-op if the tier does not exist.
func deleteRecommendationTier(c ctrlclient.Client, tierName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tier := v3.NewTier()
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: tierName}, tier); err != nil {
		if apierrors.IsNotFound(err) {
			return // Tier doesn't exist — nothing to clean up.
		}
		logrus.WithError(err).Warnf("failed to get tier %s for cleanup", tierName)
		return
	}

	// Delete namespace-scoped staged policies.
	snps := v3.NewStagedNetworkPolicyList()
	if err := c.List(ctx, snps); err != nil {
		logrus.WithError(err).Warn("failed to list staged network policies for cleanup")
	} else {
		for i := range snps.Items {
			if snps.Items[i].Spec.Tier == tierName {
				if err := c.Delete(ctx, &snps.Items[i]); err != nil && !apierrors.IsNotFound(err) {
					logrus.WithError(err).Warnf("failed to delete staged network policy %s/%s", snps.Items[i].Namespace, snps.Items[i].Name)
				}
			}
		}
	}

	// Delete namespace-scoped enforced policies.
	nps := &v3.NetworkPolicyList{}
	if err := c.List(ctx, nps); err != nil {
		logrus.WithError(err).Warn("failed to list network policies for cleanup")
	} else {
		for i := range nps.Items {
			if nps.Items[i].Spec.Tier == tierName {
				if err := c.Delete(ctx, &nps.Items[i]); err != nil && !apierrors.IsNotFound(err) {
					logrus.WithError(err).Warnf("failed to delete network policy %s/%s", nps.Items[i].Namespace, nps.Items[i].Name)
				}
			}
		}
	}

	if err := c.Delete(ctx, tier); err != nil && !apierrors.IsNotFound(err) {
		logrus.WithError(err).Warnf("failed to delete tier %s", tierName)
		return
	}
	Eventually(func() error {
		pollCtx, pollCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer pollCancel()
		err := c.Get(pollCtx, ctrlclient.ObjectKey{Name: tierName}, v3.NewTier())
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("checking tier %s deletion: %w", tierName, err)
		}
		return fmt.Errorf("tier %s still exists", tierName)
	}, 1*time.Minute, 5*time.Second).Should(Succeed(), "tier %s should be deleted", tierName)
}

// enablePolicyRecommendation enables the recommendation engine with the given interval,
// stabilization period, and namespace selector. The selector restricts which namespaces
// the engine evaluates — pass the test namespace names to avoid generating recommendations
// for system namespaces (calico-system, tigera-*, kube-system, etc.).
func enablePolicyRecommendation(c ctrlclient.Client, interval, stabilization time.Duration, namespaces ...string) (disable func() error, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scope := v3.NewPolicyRecommendationScope()
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, scope); err != nil {
		return nil, fmt.Errorf("getting PolicyRecommendationScope: %w", err)
	}

	selector := ""
	if len(namespaces) > 0 {
		quoted := make([]string, len(namespaces))
		for i, ns := range namespaces {
			quoted[i] = fmt.Sprintf("'%s'", ns)
		}
		selector = fmt.Sprintf("projectcalico.org/name in {%s}", strings.Join(quoted, ", "))
	}

	By(fmt.Sprintf("Enabling Policy Recommendation (interval=%s, stabilization=%s, selector=%q)", interval, stabilization, selector))
	scope.Spec.NamespaceSpec.RecStatus = v3.PolicyRecommendationScopeEnabled
	scope.Spec.NamespaceSpec.Selector = selector
	scope.Spec.Interval = &metav1.Duration{Duration: interval}
	scope.Spec.StabilizationPeriod = &metav1.Duration{Duration: stabilization}

	if err := c.Update(ctx, scope); err != nil {
		return nil, fmt.Errorf("enabling PolicyRecommendationScope: %w", err)
	}

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.Get(ctx, ctrlclient.ObjectKey{Name: scope.Name}, scope); err != nil {
			return fmt.Errorf("getting PolicyRecommendationScope for disable: %w", err)
		}
		scope.Spec.NamespaceSpec.RecStatus = v3.PolicyRecommendationScopeDisabled
		return c.Update(ctx, scope)
	}, nil
}

// resetPolicyRecommendationScope disables the engine and resets all namespace spec
// fields to their zero values. This is best-effort cleanup for AfterEach — errors
// are logged but not fatal so remaining teardown can proceed.
func resetPolicyRecommendationScope(c ctrlclient.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scope := v3.NewPolicyRecommendationScope()
	if err := c.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, scope); err != nil {
		logrus.WithError(err).Warn("failed to get PolicyRecommendationScope for reset")
		return
	}
	scope.Spec.NamespaceSpec = v3.PolicyRecommendationScopeNamespaceSpec{
		RecStatus: v3.PolicyRecommendationScopeDisabled,
	}
	if err := c.Update(ctx, scope); err != nil {
		logrus.WithError(err).Warn("failed to reset PolicyRecommendationScope")
	}
}
