package pip

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/config"
	"github.com/projectcalico/calico/ui-apis/pkg/pip/policycalc"
)

// epData encapsulates endpoint data for these tests. It is not a full representation, merely enough to make the
// aggregation interesting - we have tested the actual aggregation of composite objects specificially in other UTs so
// don't need to worry about full tests here.
type epData struct {
	Type      string
	Namespace string
	NameAggr  string
	Port      int
}

// wepd creates an epData for a WEP.
func wepd(name, namespace string, port int) epData {
	return epData{
		Type:      "wep",
		Namespace: namespace,
		NameAggr:  name,
		Port:      port,
	}
}

// hepd creates an epData for a HEP.
func hepd(name string, port int) epData {
	return epData{
		Type:      "hep",
		NameAggr:  name,
		Namespace: "-",
		Port:      port,
	}
}

func flow(reporter, action, protocol string, source, dest epData, policies ...string) v1.L3Flow {
	if len(policies) == 0 {
		defaultPolicy := "0|calico-system|calico-monitoring/calico-system.elasticsearch-access|allow"
		policies = []string{defaultPolicy}
	}

	flow := v1.L3Flow{
		Key: v1.L3FlowKey{
			Reporter: v1.FlowReporter(reporter),
			Action:   v1.FlowAction(action),
			Protocol: protocol,
			Source: v1.Endpoint{
				Type:           v1.EndpointType(source.Type),
				Namespace:      source.Namespace,
				AggregatedName: source.NameAggr,
				Port:           int64(source.Port),
			},
			Destination: v1.Endpoint{
				Type:           v1.EndpointType(dest.Type),
				Namespace:      dest.Namespace,
				AggregatedName: dest.NameAggr,
				Port:           int64(dest.Port),
			},
		},
		SourceIPs:      []string{"0.0.0.0"},
		DestinationIPs: []string{"0.0.0.0"},
		LogStats: &v1.LogStats{
			FlowLogCount: 1,
		},
	}

	// Parse policies in the same way Linseed would produce them.
	for _, p := range policies {
		hit, err := api.PolicyHitFromFlowLogPolicyString(p)
		Expect(err).NotTo(HaveOccurred())

		flow.Policies = append(flow.Policies, v1.Policy{
			Tier:         hit.Tier(),
			Kind:         hit.Kind(),
			Namespace:    hit.Namespace(),
			Name:         hit.Name(),
			Action:       string(hit.Action()),
			IsStaged:     api.IsStaged(hit.Kind()),
			IsKubernetes: api.IsKubernetes(hit.Kind()),
			IsProfile:    api.IsProfile(hit.Kind()),
			RuleID:       hit.RuleIndex(),
		})
	}
	return flow
}

// alwaysAllowCalculator implements the policy calculator interface with an always allow source and dest response for
// the after buckets.
type alwaysAllowCalculator struct{}

func (c alwaysAllowCalculator) CalculateSource(flow *api.Flow) (bool, policycalc.EndpointResponse, policycalc.EndpointResponse) {
	before := policycalc.EndpointResponse{
		Include: true,
		Action:  flow.ActionFlag,
		Policies: []api.PolicyHit{
			mustCreatePolicyHit("0|tier1|tier1.policy1|pass"),
			mustCreatePolicyHit("1|default|default.policy1|allow"),
		},
	}
	after := policycalc.EndpointResponse{
		Include: true,
		Action:  api.ActionFlagAllow,
		Policies: []api.PolicyHit{
			mustCreatePolicyHit("0|tier1|tier1.policy1|pass"),
			mustCreatePolicyHit("1|default|default.policy1|allow"),
		},
	}
	return flow.ActionFlag != api.ActionFlagAllow, before, after
}

func (alwaysAllowCalculator) CalculateDest(
	flow *api.Flow, beforeSourceAction, afterSourceAction api.ActionFlag,
) (modified bool, before, after policycalc.EndpointResponse) {
	if beforeSourceAction != api.ActionFlagDeny {
		before = policycalc.EndpointResponse{
			Include: true,
			Action:  flow.ActionFlag,
			Policies: []api.PolicyHit{
				mustCreatePolicyHit("0|tier1|tier1.policy1|pass"),
				mustCreatePolicyHit("1|default|default.policy1|allow"),
			},
		}
	}
	if afterSourceAction != api.ActionFlagDeny {
		after = policycalc.EndpointResponse{
			// Add a destination flow if the original src flow was Deny and now we allow.
			Include: true,
			Action:  api.ActionFlagAllow,
			Policies: []api.PolicyHit{
				mustCreatePolicyHit("0|tier1|tier1.policy1|pass"),
				mustCreatePolicyHit("1|default|default.policy1|allow"),
			},
		}
	}
	return flow.ActionFlag != api.ActionFlagAllow, before, after
}

// alwaysDenyCalculator implements the policy calculator interface with an always deny source and dest response for the
// after buckets.
type alwaysDenyCalculator struct{}

func (c alwaysDenyCalculator) CalculateSource(flow *api.Flow) (bool, policycalc.EndpointResponse, policycalc.EndpointResponse) {
	before := policycalc.EndpointResponse{
		Include: true,
		Action:  flow.ActionFlag,
		Policies: []api.PolicyHit{
			mustCreatePolicyHit("0|tier1|tier1.policy1|pass"),
			mustCreatePolicyHit("1|default|default.policy1|allow"),
		},
	}
	after := policycalc.EndpointResponse{
		Include: true,
		Action:  api.ActionFlagDeny,
		Policies: []api.PolicyHit{
			mustCreatePolicyHit("0|tier1|tier1.policy1|pass"),
			mustCreatePolicyHit("1|default|default.policy1|allow"),
		},
	}
	return flow.ActionFlag != api.ActionFlagDeny, before, after
}

func (alwaysDenyCalculator) CalculateDest(
	flow *api.Flow, beforeSourceAction, afterSourceAction api.ActionFlag,
) (modified bool, before, after policycalc.EndpointResponse) {
	if beforeSourceAction != api.ActionFlagDeny {
		before = policycalc.EndpointResponse{
			Include: true,
			Action:  flow.ActionFlag,
			Policies: []api.PolicyHit{
				mustCreatePolicyHit("0|tier1|tier1.policy1|deny"),
				mustCreatePolicyHit("1|default|default.policy1|deny"),
			},
		}
	}
	if afterSourceAction != api.ActionFlagDeny {
		before = policycalc.EndpointResponse{
			Include: true,
			Action:  api.ActionFlagDeny,
			Policies: []api.PolicyHit{
				mustCreatePolicyHit("0|tier1|tier1.policy1|pass"),
				mustCreatePolicyHit("1|default|default.policy1|deny"),
			},
		}
	}
	return flow.ActionFlag != api.ActionFlagDeny, before, after
}

var _ = Describe("Test relationship between PIP and API queries", func() {
	It("has the same lower set of indexes", func() {
		Expect(PIPCompositeSourcesRawIdxSourceType).To(Equal(elastic.FlowCompositeSourcesIdxSourceType))
		Expect(PIPCompositeSourcesRawIdxSourceNamespace).To(Equal(elastic.FlowCompositeSourcesIdxSourceNamespace))
		Expect(PIPCompositeSourcesRawIdxSourceNameAggr).To(Equal(elastic.FlowCompositeSourcesIdxSourceNameAggr))
		Expect(PIPCompositeSourcesRawIdxDestType).To(Equal(elastic.FlowCompositeSourcesIdxDestType))
		Expect(PIPCompositeSourcesRawIdxDestNamespace).To(Equal(elastic.FlowCompositeSourcesIdxDestNamespace))
		Expect(PIPCompositeSourcesRawIdxDestNameAggr).To(Equal(elastic.FlowCompositeSourcesIdxDestNameAggr))
	})
})

var _ = Describe("Test handling of aggregated response", func() {
	It("handles simple aggregation of results where action does not change", func() {
		flows := []v1.L3Flow{
			// Dest api.
			flow("dst", "allow", "tcp", hepd("hep1", 100), hepd("hep2", 200)), // + Aggregate before and after
			flow("dst", "allow", "udp", hepd("hep1", 100), hepd("hep2", 200)), // |
			flow("dst", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)), // +
			// Source api.
			flow("src", "allow", "tcp", hepd("hep1", 100), hepd("hep2", 200)), // + Aggregate before and after
			flow("src", "allow", "udp", hepd("hep1", 100), hepd("hep2", 200)), // |
			flow("src", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)), // +
			// WEP
			flow("src", "allow", "tcp", wepd("hep1", "ns1", 100), hepd("hep2", 200)), // Missing dest flow
		}

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		p.MaxPageSize = 1 // Iterate after only a single response.
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows (always allow after)")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, errors := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", alwaysAllowCalculator{}, 1000, false, elastic.NewFlowFilterIncludeAll())

		// We shouldn't get an error.
		err := <-errors
		Expect(err).NotTo(HaveOccurred())

		var before []*elastic.CompositeAggregationBucket
		var after []*elastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		Expect(before).To(HaveLen(3))
		Expect(before[0].DocCount).To(BeEquivalentTo(3))
		Expect(before[0].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
		Expect(before[1].DocCount).To(BeEquivalentTo(3))
		Expect(before[1].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
		Expect(before[2].DocCount).To(BeEquivalentTo(1))
		Expect(before[2].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))

		Expect(after).To(HaveLen(3))
		Expect(after[0].DocCount).To(BeEquivalentTo(3))
		Expect(after[0].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
		Expect(after[1].DocCount).To(BeEquivalentTo(3))
		Expect(after[1].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
		Expect(after[2].DocCount).To(BeEquivalentTo(1))
		Expect(after[2].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
	})

	It("handles source flows changing from deny to allow", func() {
		flows := []v1.L3Flow{
			// Dest api.
			// flow("dst", "allow", "tcp", hepd("hep1", 100), hepd("hep2", 200)), <- this flow is now deny at source,
			//                                                                       but will reappear in "after flows"
			flow("dst", "deny", "udp", hepd("hep1", 100), hepd("hep2", 200)),  //                // + AggregatedProtoPorts after
			flow("dst", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)), //                // +
			// Source api.
			flow("src", "deny", "tcp", hepd("hep1", 100), hepd("hep2", 200)),  //                // + AggregatedProtoPorts after
			flow("src", "allow", "udp", hepd("hep1", 100), hepd("hep2", 200)), // + AggregatedProtoPorts   // |
			flow("src", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)), // + before       // +
			// WEP
			flow("src", "allow", "tcp", wepd("hep1", "ns1", 100), hepd("hep2", 200)), // Missing dest flow
		}

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		p.MaxPageSize = 1 // Iterate after only a single response.
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows (always allow after)")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", alwaysAllowCalculator{}, 1000, false, elastic.NewFlowFilterIncludeAll())
		var before []*elastic.CompositeAggregationBucket
		var after []*elastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		Expect(before).To(HaveLen(5))
		Expect(before[0].DocCount).To(BeEquivalentTo(1))
		Expect(before[0].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[1].DocCount).To(BeEquivalentTo(1))
		Expect(before[1].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[2].DocCount).To(BeEquivalentTo(2))
		Expect(before[2].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[3].DocCount).To(BeEquivalentTo(1))
		Expect(before[3].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[4].DocCount).To(BeEquivalentTo(1))
		Expect(before[4].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))

		Expect(after).To(HaveLen(3))
		Expect(after[0].DocCount).To(BeEquivalentTo(3))
		Expect(after[0].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(after[1].DocCount).To(BeEquivalentTo(3))
		Expect(after[1].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(after[2].DocCount).To(BeEquivalentTo(1))
		Expect(after[2].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: false},
		}))
	})

	It("handles source flows changing from allow to deny", func() {
		flows := []v1.L3Flow{
			flow("dst", "deny", "udp", hepd("hep1", 100), hepd("hep2", 200)),
			flow("src", "allow", "udp", hepd("hep1", 100), hepd("hep2", 200)),
			flow("src", "deny", "tcp", hepd("hep1", 100), hepd("hep2", 200)),

			flow("dst", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)),
			flow("src", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)),

			flow("src", "allow", "tcp", wepd("hep1", "ns1", 100), hepd("hep2", 200)),
		}

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		p.MaxPageSize = 1 // Iterate after only a single response.
		pager := client.NewMockListPager(&p, listFn)

		By("Creating a PIP instance with the mock client, and enumerating all aggregated flows (always deny after)")
		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", alwaysDenyCalculator{}, 1000, false, elastic.NewFlowFilterIncludeAll())
		var before []*elastic.CompositeAggregationBucket
		var after []*elastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
			after = append(after, flow.After...)
		}

		Expect(before).To(HaveLen(5))
		Expect(before[0].DocCount).To(BeEquivalentTo(1))
		Expect(before[0].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[1].DocCount).To(BeEquivalentTo(1))
		Expect(before[1].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[2].DocCount).To(BeEquivalentTo(2))
		Expect(before[2].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[3].DocCount).To(BeEquivalentTo(1))
		Expect(before[3].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[4].DocCount).To(BeEquivalentTo(1))
		Expect(before[4].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))

		Expect(after).To(HaveLen(2))
		Expect(after[0].DocCount).To(BeEquivalentTo(3))
		Expect(after[0].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(after[1].DocCount).To(BeEquivalentTo(1))
		Expect(after[1].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "wep"},
			{Name: "source_namespace", Value: "ns1"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
	})

	It("Should return only impacted flows when impactedOnly parameter is set to true", func() {
		flows := []v1.L3Flow{
			// Dest api.
			// flow("dst", "allow", "tcp", hepd("hep1", 100), hepd("hep2", 200)), <- this flow is now deny at source,
			//                                                                       but will reappear in "after flows"
			flow("dst", "deny", "udp", hepd("hep1", 100), hepd("hep2", 200)),  //                // + AggregatedProtoPorts after
			flow("dst", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)), //                // +
			// Source api.
			flow("src", "deny", "tcp", hepd("hep1", 100), hepd("hep2", 200)),  //                // + AggregatedProtoPorts after
			flow("src", "allow", "udp", hepd("hep1", 100), hepd("hep2", 200)), // + AggregatedProtoPorts   // |
			flow("src", "allow", "tcp", hepd("hep1", 500), hepd("hep2", 600)), // + before       // +
			// WEP
			flow("src", "allow", "tcp", wepd("hep1", "ns1", 100), hepd("hep2", 200)), // Missing dest flow
		}

		// listFn mocks out results from Linseed.
		listFn := func(context.Context, v1.Params) (*v1.List[v1.L3Flow], error) {
			return &v1.List[v1.L3Flow]{
				Items: flows,
			}, nil
		}

		p := v1.L3FlowParams{}
		p.MaxPageSize = 1 // Iterate after only a single response.
		pager := client.NewMockListPager(&p, listFn)

		pip := pip{lsclient: client.NewMockClient(""), cfg: config.MustLoadConfig()}
		flowsChan, _ := pip.SearchAndProcessFlowLogs(context.Background(), pager, "cluster", alwaysAllowCalculator{}, 1000, true, elastic.NewFlowFilterIncludeAll())
		var before []*elastic.CompositeAggregationBucket
		for flow := range flowsChan {
			before = append(before, flow.Before...)
		}

		By("Checking the length of the response, if impactedOnly was set to false before would contain 5 results")
		Expect(before).To(HaveLen(4))
		Expect(before[0].DocCount).To(BeEquivalentTo(1))
		Expect(before[0].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[1].DocCount).To(BeEquivalentTo(1))
		Expect(before[1].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "dst"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[2].DocCount).To(BeEquivalentTo(2))
		Expect(before[2].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "allow"},
			{Name: "source_action", Value: "allow"},
			{Name: "flow_impacted", Value: true},
		}))
		Expect(before[3].DocCount).To(BeEquivalentTo(1))
		Expect(before[3].CompositeAggregationKey).To(Equal(elastic.CompositeAggregationKey{
			{Name: "source_type", Value: "hep"},
			{Name: "source_namespace", Value: "-"},
			{Name: "source_name", Value: "hep1"},
			{Name: "dest_type", Value: "hep"},
			{Name: "dest_namespace", Value: "-"},
			{Name: "dest_name", Value: "hep2"},
			{Name: "reporter", Value: "src"},
			{Name: "action", Value: "deny"},
			{Name: "source_action", Value: "deny"},
			{Name: "flow_impacted", Value: true},
		}))
	})
})

func mustCreatePolicyHit(policyStr string) api.PolicyHit {
	policyHit, err := api.PolicyHitFromFlowLogPolicyString(policyStr)
	Expect(err).ShouldNot(HaveOccurred())

	return policyHit
}
