package pip

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"github.com/tigera/api/pkg/lib/numorstring"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	pelastic "github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/config"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/policycalc"
)

var (
	namespaceNs1 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns1",
		},
	}
	namespaceNs2 = &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ns2",
		},
	}
)

var _ = Describe("Test handling of flow splitting", func() {
	It("handles spliting of flow into the maximum number of possible splits", func() {
		// All flows from A -> B  (both pods)
		// Before conditions:
		//      A(allow)   -> B (allow)     [Current policy allows all flows]
		// After conditions:
		//      A(allow)   -> B (allow)     [Updated policy affects all flows]
		//      A(allow)   -> B (unknown)
		//      A(allow)   -> B (deny)
		//      A(unknown) -> B (allow)
		//      A(unknown) -> B (unknown)
		//      A(unknown) -> B (deny)
		//      A(deny)    -> B (X)
		//
		// Policy to handle the split:
		// Before: no policy before
		// After: Egress  - allow src port 1
		//                - allow src port 2 + service account x   [causes an unknown]
		//                - deny  src port 3
		//        Ingress - allow dst port 1
		//                - allow dst port 2 + service account x   [causes an unknown]
		//                - deny  dst port 3
		//
		// Create a client which has all of the flows that:
		// - allows all both ends using the *before* policy
		// - breaks out into 1 of each of the required after conditions using the *after* policy
		// - has a mixture of allow/deny flows recorded in Linseed - the policy calculator will recalculate the *before*
		//   flow so will readjust the actual flow data.
		By("Creating a client with a mocked out search results with all allow actions")
		flows := []v1.L3Flow{
			// before: deny/na       after: allow/allow
			// flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 1)), <- denied at source
			flow("src", "deny", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 1)),

			// before: allow/allow   after: allow/unknown
			flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 2)),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 2)),

			// before: allow/deny    after: allow/deny
			flow("dst", "deny", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 3)),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 3)),

			// before: allow/deny    after: unknown/allow
			flow("dst", "deny", "tcp", wepd("wepsrc", "ns1", 2), wepd("wepdst", "ns1", 1)),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 2), wepd("wepdst", "ns1", 1)),

			// before: allow/allow   after: unknown/unknown
			flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 2), wepd("wepdst", "ns1", 2)),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 2), wepd("wepdst", "ns1", 2)),

			// before: deny/na       after: deny/na
			// flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 3), wepd("wepdst", "ns1", 1)), <- denied at source
			flow("src", "deny", "tcp", wepd("wepsrc", "ns1", 3), wepd("wepdst", "ns1", 1)),

			// before: allow/allow   after: unknown/deny
			flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 2), wepd("wepdst", "ns1", 3)),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 2), wepd("wepdst", "ns1", 3)),
		}

		By("Creating a policy calculator with the required policy updates")
		np := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "policy",
				Namespace: "ns1",
			},
			Spec: v3.NetworkPolicySpec{
				Types: []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
				Egress: []v3.Rule{
					{
						Action: v3.Allow,
						Source: v3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(1),
							},
						},
					},
					{
						Action: v3.Allow,
						Source: v3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(2),
							},
							ServiceAccounts: &v3.ServiceAccountMatch{
								Names: []string{"service-account"},
							},
						},
					},
					{
						Action: v3.Deny,
						Source: v3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(3),
							},
						},
					},
				},
				Ingress: []v3.Rule{
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(1),
							},
						},
					},
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(2),
							},
							ServiceAccounts: &v3.ServiceAccountMatch{
								Names: []string{"service-account"},
							},
						},
					},
					{
						Action: v3.Deny,
						Destination: v3.EntityRule{
							Ports: []numorstring.Port{
								numorstring.SinglePort(3),
							},
						},
					},
				},
			},
		}
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(np), policycalc.Impact{Modified: true})
		pc := policycalc.NewPolicyCalculator(
			&config.Config{
				CalculateOriginalAction: true, // <- we want to recalculate the original action
			},
			policycalc.NewEndpointCache(),
			&policycalc.ResourceData{},
			&policycalc.ResourceData{
				Tiers: policycalc.Tiers{
					{policycalc.Policy{CalicoV3Policy: np, ResourceID: resources.GetResourceID(np)}},
				},
			},
			impacted,
		)

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", pc, 1000, false, pelastic.NewFlowFilterIncludeAll())
		var before []*pelastic.CompositeAggregationBucket
		var after []*pelastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		// Before: We expect 1 flow at source, 1 flow at dest.
		// After:  We expect 3 flows at source, 6 flows at dest (there is no corresponding dest flow for source deny)
		Expect(before).To(HaveLen(2))
		Expect(after).To(HaveLen(9))

		// Ordering is by reporter, action, source_action.
		Expect(before[0].DocCount).To(BeEquivalentTo(7))
		Expect(before[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(before[1].DocCount).To(BeEquivalentTo(7))
		Expect(before[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[0].DocCount).To(BeEquivalentTo(1))
		Expect(after[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[1].DocCount).To(BeEquivalentTo(1))
		Expect(after[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "unknown"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[2].DocCount).To(BeEquivalentTo(1))
		Expect(after[2].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[3].DocCount).To(BeEquivalentTo(1))
		Expect(after[3].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "unknown"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[4].DocCount).To(BeEquivalentTo(1))
		Expect(after[4].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "unknown"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[5].DocCount).To(BeEquivalentTo(1))
		Expect(after[5].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "unknown"},
			{Name: "source_action", Value: "unknown"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[6].DocCount).To(BeEquivalentTo(3))
		Expect(after[6].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[7].DocCount).To(BeEquivalentTo(1))
		Expect(after[7].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after[8].DocCount).To(BeEquivalentTo(3))
		Expect(after[8].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "unknown"},
			{Name: "source_action", Value: "unknown"},
			{Name: "flow_impacted", Value: true},
		}))
	})

	It("handles flows with staged ingress default-deny before and after", func() {
		// Before conditions:
		//      A(allow)   -> B (deny)      [End of tier deny]
		// After conditions:
		//      A(allow)   -> B (deny)      [end of tier deny with additional pass in another tier]
		//
		// Policy to handle the split:
		// Before: default tier match all ingress, no rules
		// After:  application tier, match all ingress, pass
		//
		// Create a client which has all of the flows that:
		By("Creating a client with a mocked out search results with all allow actions")
		flows := []v1.L3Flow{
			// before: allow/deny    after: allow/deny
			flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 3), "1|default|np:ns1/default.staged:ingress-defaultdeny|deny|-1", "0|__PROFILE__|pro:kns.ns1|allow"),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 3), "0|__PROFILE__|pro:kns.ns1|allow"),
		}

		By("Creating a policy calculator with the required policy updates")
		np_deny := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default.ingress-defaultdeny",
				Namespace: "ns1",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "default",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeIngress},
			},
		}

		// We are just enforcing a staged policy, so the policy is not modified.
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(np_deny), policycalc.Impact{Modified: false})
		pc := policycalc.NewPolicyCalculator(
			&config.Config{
				CalculateOriginalAction: true, // <- we want to recalculate the original action
			},
			policycalc.NewEndpointCache(),
			&policycalc.ResourceData{
				Tiers: policycalc.Tiers{
					// It's a staged policy (although we store as a non-staged type with Staged set to true.
					{policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny), Staged: true}},
				},
			},
			&policycalc.ResourceData{
				Tiers: policycalc.Tiers{
					{policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny), Staged: false}},
				},
			},
			impacted,
		)

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", pc, 1000, false, pelastic.NewFlowFilterIncludeAll())
		var before []*pelastic.CompositeAggregationBucket
		var after []*pelastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		// Before: We expect 1 flow at source, 1 flow at dest.
		// After:  We expect 3 flows at source, 6 flows at dest (there is no corresponding dest flow for source deny)
		Expect(before).To(HaveLen(2))
		Expect(after).To(HaveLen(2))

		// Ordering is by reporter, action, source_action.
		Expect(before[0].DocCount).To(BeEquivalentTo(1))
		Expect(before[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[0], []string{"__PROFILE__|pro:kns.ns1|allow|-"})

		Expect(before[1].DocCount).To(BeEquivalentTo(1))
		Expect(before[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[1], []string{"__PROFILE__|pro:kns.ns1|allow|-"})

		Expect(after[0].DocCount).To(BeEquivalentTo(1))
		Expect(after[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(after[0], []string{"default|np:ns1/default.ingress-defaultdeny|deny|-1"})

		Expect(after[1].DocCount).To(BeEquivalentTo(1))
		Expect(after[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(after[1], []string{"__PROFILE__|pro:kns.ns1|allow|-"})
	})

	It("handles flows with staged egress default-deny before and after", func() {
		// Before conditions:
		//      A(allow)   -> B (deny)      [End of tier deny]
		// After conditions:
		//      A(allow)   -> B (deny)      [end of tier deny with additional pass in another tier]
		//
		// Policy to handle the split:
		// Before: default tier match all ingress, no rules
		// After:  application tier, match all ingress, pass
		//
		// Create a client which has all of the flows that:
		By("Creating a client with a mocked out search results with all allow actions")
		flows := []v1.L3Flow{
			// before: allow/deny    after: allow/deny
			flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 3), "0|__PROFILE__|pro:kns.ns1|allow"),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns1", 3), "1|default|np:ns1/default.staged:egress-defaultdeny|deny|-1", "0|__PROFILE__|pro:kns.ns1|allow"),
		}

		By("Creating a policy calculator with the required policy updates")
		np_deny := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default.egress-defaultdeny",
				Namespace: "ns1",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "default",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			},
		}

		// We are just enforcing a staged policy, so the policy is not modified.
		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(np_deny), policycalc.Impact{Modified: false})
		pc := policycalc.NewPolicyCalculator(
			&config.Config{
				CalculateOriginalAction: true, // <- we want to recalculate the original action
			},
			policycalc.NewEndpointCache(),
			&policycalc.ResourceData{
				Tiers: policycalc.Tiers{
					// It's a staged policy (although we store as a non-staged type with Staged set to true.
					{policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny), Staged: true}},
				},
			},
			&policycalc.ResourceData{
				Tiers: policycalc.Tiers{
					{policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny), Staged: false}},
				},
			},
			impacted,
		)

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", pc, 1000, false, pelastic.NewFlowFilterIncludeAll())
		var before []*pelastic.CompositeAggregationBucket
		var after []*pelastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		// Before: We expect 1 flow at source, 1 flow at dest.
		// After:  We expect 3 flows at source, 6 flows at dest (there is no corresponding dest flow for source deny)
		Expect(before).To(HaveLen(2))
		Expect(after).To(HaveLen(1))

		// Ordering is by reporter, action, source_action.
		Expect(before[0].DocCount).To(BeEquivalentTo(1))
		Expect(before[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[0], []string{"__PROFILE__|pro:kns.ns1|allow|-"})

		Expect(before[1].DocCount).To(BeEquivalentTo(1))
		Expect(before[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[1], []string{"__PROFILE__|pro:kns.ns1|allow|-"})

		Expect(after[0].DocCount).To(BeEquivalentTo(1))
		Expect(after[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns1"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(after[0], []string{"default|np:ns1/default.egress-defaultdeny|deny|-1"})
	})

	It("handles flows with denied source previewing allow policy with flows before deny policy was added", func() {
		// Before conditions:
		//      A(allow)   -> B             [Profile allow]    (from before default deny was added)
		//      A(allow)   -> B (allow)     [Profile allow]    (from before default deny was added)
		//      A(deny)    -> B             [Default deny policy]
		// After conditions:
		//      A(allow)   -> B (allow)     [Policy overriding default deny]
		//
		// Policy to handle the split:
		// Before: default tier match all ingress, no rules
		// After:  application tier, match all ingress, pass
		//
		// Create a client which has all of the flows that:
		By("Creating a client with a mocked out search results with all allow actions")
		flows := []v1.L3Flow{
			// before: allow/deny    after: allow/deny
			flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns2", 3), "0|__PROFILE__|pro:kns.ns2|allow"),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns2", 3), "0|__PROFILE__|pro:kns.ns1|allow"),
			flow("src", "deny", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns2", 3), "1|default|np:ns1/default.defaultdeny|deny|-1"),
		}

		By("Creating a policy calculator with the required policy updates")
		np_deny := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default.defaultdeny",
				Namespace: "ns1",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "default",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			},
		}
		np_allow := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default.egress-allow",
				Namespace: "ns1",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "default",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeEgress},
				Egress: []v3.Rule{
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							Selector:          "all()",
							NamespaceSelector: "projectcalico.org/name==\"ns2\"",
						},
					},
				},
			},
		}

		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(np_allow), policycalc.Impact{Modified: true})
		pc := policycalc.NewPolicyCalculator(
			&config.Config{
				CalculateOriginalAction: false, // <- we do not want to recalculate the original action
			},
			policycalc.NewEndpointCache(),
			&policycalc.ResourceData{
				Namespaces: []*corev1.Namespace{namespaceNs1, namespaceNs2},
				Tiers: policycalc.Tiers{
					{
						policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny)},
					},
				},
			},
			&policycalc.ResourceData{
				Namespaces: []*corev1.Namespace{namespaceNs1, namespaceNs2},
				Tiers: policycalc.Tiers{
					{
						policycalc.Policy{CalicoV3Policy: np_allow, ResourceID: resources.GetResourceID(np_allow)},
						policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny)},
					},
				},
			},
			impacted,
		)

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", pc, 1000, false, pelastic.NewFlowFilterIncludeAll())
		var before []*pelastic.CompositeAggregationBucket
		var after []*pelastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		// Before: We expect 1 flow at source, 1 flow at dest.
		// After:  We expect 3 flows at source, 6 flows at dest (there is no corresponding dest flow for source deny)
		Expect(before).To(HaveLen(3))
		Expect(after).To(HaveLen(2))

		// Ordering is by reporter, action, source_action.
		Expect(before[0].DocCount).To(BeEquivalentTo(1))
		Expect(before[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[0], []string{"__PROFILE__|pro:kns.ns2|allow|-"})

		Expect(before[1].DocCount).To(BeEquivalentTo(1))
		Expect(before[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[1], []string{"__PROFILE__|pro:kns.ns1|allow|-"})

		Expect(before[2].DocCount).To(BeEquivalentTo(1))
		Expect(before[2].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[2], []string{"default|np:ns1/default.defaultdeny|deny|-1"})

		Expect(after[0].DocCount).To(BeEquivalentTo(2))
		Expect(after[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(after[0], []string{"__PROFILE__|pro:kns.ns2|allow|-"})

		Expect(after[1].DocCount).To(BeEquivalentTo(2))
		Expect(after[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(after[1], []string{"default|np:ns1/default.egress-allow|allow|-"})
	})

	It("handles flows with denied source previewing allow policy with flows before deny policy was added - recalculate before flows", func() {
		// Before conditions:
		//      A(allow)   -> B             [Profile allow]    (from before default deny was added)
		//      A(allow)   -> B (allow)     [Profile allow]    (from before default deny was added)
		//      A(deny)    -> B             [Default deny policy]
		// After conditions:
		//      A(allow)   -> B (allow)     [Policy overriding default deny]
		//
		// Policy to handle the split:
		// Before: default tier match all ingress, no rules
		// After:  application tier, match all ingress, pass
		//
		// Create a client which has all of the flows that:
		By("Creating a client with a mocked out search results with all allow actions")
		flows := []v1.L3Flow{
			// before: allow/deny    after: allow/deny
			flow("dst", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns2", 3), "0|__PROFILE__|pro:kns.ns2|allow"),
			flow("src", "allow", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns2", 3), "0|__PROFILE__|pro:kns.ns1|allow"),
			flow("src", "deny", "tcp", wepd("wepsrc", "ns1", 1), wepd("wepdst", "ns2", 3), "1|default|np:ns1/default.defaultdeny|deny|-1"),
		}

		By("Creating a policy calculator with the required policy updates")
		np_deny := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default.defaultdeny",
				Namespace: "ns1",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "default",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeEgress, v3.PolicyTypeIngress},
			},
		}
		np_allow := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default.egress-allow",
				Namespace: "ns1",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "default",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeEgress},
				Egress: []v3.Rule{
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							Selector:          "all()",
							NamespaceSelector: "projectcalico.org/name==\"ns2\"",
						},
					},
				},
			},
		}

		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(np_allow), policycalc.Impact{Modified: true})
		pc := policycalc.NewPolicyCalculator(
			&config.Config{
				CalculateOriginalAction: true, // <- we want to recalculate the original action
			},
			policycalc.NewEndpointCache(),
			&policycalc.ResourceData{
				Namespaces: []*corev1.Namespace{namespaceNs1, namespaceNs2},
				Tiers: policycalc.Tiers{
					{
						policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny)},
					},
				},
			},
			&policycalc.ResourceData{
				Namespaces: []*corev1.Namespace{namespaceNs1, namespaceNs2},
				Tiers: policycalc.Tiers{
					{
						policycalc.Policy{CalicoV3Policy: np_allow, ResourceID: resources.GetResourceID(np_allow)},
						policycalc.Policy{CalicoV3Policy: np_deny, ResourceID: resources.GetResourceID(np_deny)},
					},
				},
			},
			impacted,
		)

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", pc, 1000, false, pelastic.NewFlowFilterIncludeAll())
		var before []*pelastic.CompositeAggregationBucket
		var after []*pelastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		// Before: We expect 1 flow at source, 1 flow at dest.
		// After:  We expect 3 flows at source, 6 flows at dest (there is no corresponding dest flow for source deny)
		Expect(before).To(HaveLen(1))
		Expect(after).To(HaveLen(2))

		Expect(before[0].DocCount).To(BeEquivalentTo(2))
		Expect(before[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(before[0], []string{"default|np:ns1/default.defaultdeny|deny|-1"})

		Expect(after[0].DocCount).To(BeEquivalentTo(2))
		Expect(after[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(after[0], []string{"__PROFILE__|pro:kns.ns2|allow|-"})

		Expect(after[1].DocCount).To(BeEquivalentTo(2))
		Expect(after[1].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "wepsrc"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "ns2"},
			{Name: "dest_name", Value: "wepdst"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		expectPolicies(after[1], []string{"default|np:ns1/default.egress-allow|allow|-"})
	})

	It("handles global allowed flows with a CIDR match while previewing a deletion for a global allow policy", func() {
		// Before conditions:
		//      A(allow)   -> B             [allow]    (allowed by the policy within the source namespace)
		// After conditions:
		//      A(allow)   -> B (allow)     [allow]    (allowed by the policy within the source namespace)
		//
		// Policy to handle the impact:
		// Before: allow based on source policy
		// After:  allow bases on source policy
		//
		// Create a client which has all of the flows that:
		By("Creating a client with a mocked out search results with all allow actions")
		flows := []v1.L3Flow{
			// before: allow/allow    after: allow/allow
			flow("dst", "allow", "tcp", wepd("destination", "destinationNamespace", 1), wepd("source", "sourceNamespace", 3), "0|allow-flow|np:sourceNamespace/allow-flow.cidr-match|allow|0"),
		}

		By("Creating a policy calculator with the required policy updates")
		tcp := numorstring.ProtocolFromString("TCP")
		np_cidr_match := &v3.NetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-flow.cidr-match",
				Namespace: "sourceNamespace",
			},
			Spec: v3.NetworkPolicySpec{
				Tier:     "allow-flow",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
				Ingress: []v3.Rule{
					{
						Action:   v3.Allow,
						Protocol: &tcp,
						Source: v3.EntityRule{
							Nets: []string{
								"0.0.0.0/0",
							},
						},
					},
				},
				Egress: []v3.Rule{
					{
						Action: v3.Allow,
						Destination: v3.EntityRule{
							NamespaceSelector: "projectcalico.org/name == 'destinationNamespace'",
						},
					},
					{
						Action: v3.Pass,
					},
				},
			},
		}

		globalAllow := &v3.GlobalNetworkPolicy{
			TypeMeta: resources.TypeCalicoNetworkPolicies,
			ObjectMeta: metav1.ObjectMeta{
				Name: "allow-all.global-allow",
			},
			Spec: v3.GlobalNetworkPolicySpec{
				Tier:     "allow-all",
				Selector: "all()",
				Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
				Ingress: []v3.Rule{
					{
						Action: v3.Allow,
					},
				},
				Egress: []v3.Rule{
					{
						Action: v3.Allow,
					},
				},
			},
		}

		namespaceDestination := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "destinationNamespace",
			},
		}
		namespaceSource := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "sourceNamespace",
			},
		}
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "any",
			},
		}

		impacted := make(policycalc.ImpactedResources)
		impacted.Add(resources.GetResourceID(globalAllow), policycalc.Impact{Deleted: true})

		By("Adding a deletion of the global allow")
		pc := policycalc.NewPolicyCalculator(
			&config.Config{},
			policycalc.NewEndpointCache(),
			&policycalc.ResourceData{
				Namespaces: []*corev1.Namespace{namespaceDestination, namespaceSource, namespace},
				Tiers: policycalc.Tiers{
					{
						policycalc.Policy{CalicoV3Policy: np_cidr_match, ResourceID: resources.GetResourceID(np_cidr_match)},
					},
					{
						policycalc.Policy{CalicoV3Policy: globalAllow, ResourceID: resources.GetResourceID(globalAllow)},
					},
				},
			},
			&policycalc.ResourceData{
				Namespaces: []*corev1.Namespace{namespaceDestination, namespaceSource, namespace},
				Tiers: policycalc.Tiers{
					{
						policycalc.Policy{CalicoV3Policy: np_cidr_match, ResourceID: resources.GetResourceID(np_cidr_match)},
					},
					{
						policycalc.Policy{CalicoV3Policy: globalAllow, ResourceID: resources.GetResourceID(globalAllow)},
					},
				},
			},
			impacted,
		)

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", pc, 1000, false, pelastic.NewFlowFilterIncludeAll())
		var before []*pelastic.CompositeAggregationBucket
		var after []*pelastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		// Before: We expect 1 flow at destination
		// After:  We expect 1 flow at destination
		Expect(before).To(HaveLen(1))
		Expect(after).To(HaveLen(1))

		Expect(before[0].DocCount).To(BeEquivalentTo(1))
		Expect(before[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "destinationNamespace"},
			{Name: "source_name", Value: "destination"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "sourceNamespace"},
			{Name: "dest_name", Value: "source"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
		expectPolicies(before[0], []string{"allow-flow|np:sourceNamespace/allow-flow.cidr-match|allow|-"})

		Expect(after[0].DocCount).To(BeEquivalentTo(1))
		Expect(after[0].CompositeAggregationKey).To(Equal(pelastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "destinationNamespace"},
			{Name: "source_name", Value: "destination"},
			{Name: "dest_type", Value: "wep"},
			{Name: "dest_namespace", Value: "sourceNamespace"},
			{Name: "dest_name", Value: "source"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
		expectPolicies(after[0], []string{"allow-flow|np:sourceNamespace/allow-flow.cidr-match|allow|-"})
	})
})

func expectPolicies(doc *pelastic.CompositeAggregationBucket, ps []string) {
	ExpectWithOffset(1, doc.AggregatedTerms).To(HaveKey("policies"))
	for i, p := range ps {
		p := fmt.Sprintf("%d|%s", i, p)
		ExpectWithOffset(1, doc.AggregatedTerms["policies"].Buckets).To(HaveKey(p))
	}
}
