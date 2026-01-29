package fv

import (
	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
)

var MockPolicyRecFlows1 = []rest.MockResult{
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
	{
		Body: lapi.List[lapi.L3Flow]{
			Items: []lapi.L3Flow{
				// First flow - this is just the flow as reported by the source.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterSource,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace1", Action: "allow", IsProfile: true},
					},
				},
				// Second flow - this is the flow as reported by the destination.
				{
					Key: lapi.L3FlowKey{
						Source: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace1",
							AggregatedName: "app1-abcdef-*",
						},
						Destination: lapi.Endpoint{
							Type:           lapi.WEP,
							Namespace:      "namespace2",
							AggregatedName: "nginx-12345-*",
							Port:           80,
						},
						Protocol: "6",
						Reporter: lapi.FlowReporterDest,
						Action:   lapi.FlowActionAllow,
					},
					Policies: []lapi.Policy{
						{Tier: "__PROFILE__", Kind: "Profile", Name: "kns.namespace2", Action: "allow", IsProfile: true},
					},
				},
			},
		},
	},
}
