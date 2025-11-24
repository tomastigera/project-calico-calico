package servicegraph

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

	lapi "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	v1 "github.com/projectcalico/calico/lma/pkg/apis/v1"
	svapi "github.com/projectcalico/calico/ui-apis/pkg/apis/v1"
)

func TestGetL3FlowData(t *testing.T) {
	tests := []struct {
		name        string
		inputFlows  []lapi.L3Flow
		wantL3Flows []L3Flow
		wantErr     bool
	}{
		{
			name: "Display process info for flows reported only at source",
			inputFlows: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "src",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "frontend-8475b5657d-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "cartservice-5d844fc8b7-*",
							Namespace:      "online-boutique",
							Port:           7070,
						},
					},
					Process: &lapi.Process{
						Name: "/src/server",
					},
					// Process stats are only reported at source
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "dst",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "frontend-8475b5657d-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "cartservice-5d844fc8b7-*",
							Namespace:      "online-boutique",
							Port:           7070,
						},
					},
					Process: &lapi.Process{
						Name: "/app/cartservice",
					},
					// Process stats are missing at destination
					ProcessStats: nil,
				},
			},
			wantL3Flows: []L3Flow{
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "frontend-8475b5657d-*",
							PortNum:   0,
						},
						Dest: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "cartservice-5d844fc8b7-*",
							PortNum:   0,
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts: []svapi.AggregatedPorts{
							{PortRanges: []svapi.PortRange{{MinPort: 7070, MaxPort: 7070}}},
						},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
					Processes: &svapi.GraphProcesses{
						// We expect that process stat is extract from the flow reported at source
						Source: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"frontend-8475b5657d-*:cartservice-5d844fc8b7-*:/src/server": {
							Name:               "/src/server",
							Source:             "frontend-8475b5657d-*",
							Destination:        "cartservice-5d844fc8b7-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
						Dest: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"frontend-8475b5657d-*:cartservice-5d844fc8b7-*:/app/cartservice": {
							Name:        "/app/cartservice",
							Source:      "frontend-8475b5657d-*",
							Destination: "cartservice-5d844fc8b7-*",
						}}),
					},
				},
			},
		},
		{
			name: "Display process info and process name for flows reported only at source",
			inputFlows: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "src",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "frontend-8475b5657d-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "cartservice-5d844fc8b7-*",
							Namespace:      "online-boutique",
							Port:           7070,
						},
					},
					Process: &lapi.Process{
						Name: "/src/server",
					},
					// Process stats are only reported at source
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "dst",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "frontend-8475b5657d-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "cartservice-5d844fc8b7-*",
							Namespace:      "online-boutique",
							Port:           7070,
						},
					},
					Process: &lapi.Process{
						// Process name is missing at destination
						Name: "-",
					},
					// Process stats are missing at destination
					ProcessStats: nil,
				},
			},
			wantL3Flows: []L3Flow{
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "frontend-8475b5657d-*",
							PortNum:   0,
						},
						Dest: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "cartservice-5d844fc8b7-*",
							PortNum:   0,
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts: []svapi.AggregatedPorts{
							{PortRanges: []svapi.PortRange{{MinPort: 7070, MaxPort: 7070}}},
						},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
					Processes: &svapi.GraphProcesses{
						// We expect that process stat is extract from the flow reported at source
						Source: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"frontend-8475b5657d-*:cartservice-5d844fc8b7-*:/src/server": {
							Name:               "/src/server",
							Source:             "frontend-8475b5657d-*",
							Destination:        "cartservice-5d844fc8b7-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
						// We expect process name to be "-"
						Dest: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"frontend-8475b5657d-*:cartservice-5d844fc8b7-*:-": {
							Name:        "-",
							Source:      "frontend-8475b5657d-*",
							Destination: "cartservice-5d844fc8b7-*",
						}}),
					},
				},
			},
		},
		{
			name: "Display process info for flows reported only at destination",
			inputFlows: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "src",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "frontend-8475b5657d-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "cartservice-5d844fc8b7-*",
							Namespace:      "online-boutique",
							Port:           7070,
						},
					},
					Process: &lapi.Process{
						Name: "/src/server",
					},
					// Process stats are missing at source
					ProcessStats: nil,
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "dst",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "frontend-8475b5657d-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "cartservice-5d844fc8b7-*",
							Namespace:      "online-boutique",
							Port:           7070,
						},
					},
					Process: &lapi.Process{
						Name: "/app/cartservice",
					},
					// Process stats are reported only at destination
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
			},
			wantL3Flows: []L3Flow{
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "frontend-8475b5657d-*",
							PortNum:   0,
						},
						Dest: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "cartservice-5d844fc8b7-*",
							PortNum:   0,
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts: []svapi.AggregatedPorts{
							{PortRanges: []svapi.PortRange{{MinPort: 7070, MaxPort: 7070}}},
						},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
					Processes: &svapi.GraphProcesses{
						// We expect that process stat is extract from the flow reported at destination
						Dest: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"frontend-8475b5657d-*:cartservice-5d844fc8b7-*:/app/cartservice": {
							Name:               "/app/cartservice",
							Source:             "frontend-8475b5657d-*",
							Destination:        "cartservice-5d844fc8b7-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
						Source: svapi.GraphEndpointProcesses{
							"frontend-8475b5657d-*:cartservice-5d844fc8b7-*:/src/server": {
								Name:        "/src/server",
								Source:      "frontend-8475b5657d-*",
								Destination: "cartservice-5d844fc8b7-*",
							},
						},
					},
				},
			},
		},
		{
			name: "Display process info for flows reported at source and destination",
			inputFlows: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "src",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "recommendationservice-6ffb84bb94-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "productcatalogservice-5b9df8d49b-*",
							Namespace:      "online-boutique",
							Port:           3550,
						},
					},
					Process: &lapi.Process{
						Name: "/usr/local/bin/python",
					},
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "dst",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "recommendationservice-6ffb84bb94-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "productcatalogservice-5b9df8d49b-*",
							Namespace:      "online-boutique",
							Port:           3550,
						},
					},
					Process: &lapi.Process{
						Name: "/src/server",
					},
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
			},
			wantL3Flows: []L3Flow{
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "recommendationservice-6ffb84bb94-*",
							PortNum:   0,
						},
						Dest: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "productcatalogservice-5b9df8d49b-*",
							PortNum:   0,
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts: []svapi.AggregatedPorts{
							{PortRanges: []svapi.PortRange{{MinPort: 3550, MaxPort: 3550}}},
						},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
					Processes: &svapi.GraphProcesses{
						// We expect that process stat is extract from the flow reported at source
						Source: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"recommendationservice-6ffb84bb94-*:productcatalogservice-5b9df8d49b-*:/usr/local/bin/python": {
							Name:               "/usr/local/bin/python",
							Source:             "recommendationservice-6ffb84bb94-*",
							Destination:        "productcatalogservice-5b9df8d49b-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
						Dest: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"recommendationservice-6ffb84bb94-*:productcatalogservice-5b9df8d49b-*:/src/server": {
							Name:               "/src/server",
							Source:             "recommendationservice-6ffb84bb94-*",
							Destination:        "productcatalogservice-5b9df8d49b-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
					},
				},
			},
		},
		{
			name: "Display process info for processes with the same name",
			inputFlows: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "src",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "checkoutservice-84cb944764-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "paymentservice-866fd4b98-*",
							Namespace:      "online-boutique",
							Port:           50051,
						},
					},
					Process: &lapi.Process{
						Name: "/src/checkout",
					},
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "dst",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "checkoutservice-84cb944764-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "paymentservice-866fd4b98-*",
							Namespace:      "online-boutique",
							Port:           50051,
						},
					},
					Process: &lapi.Process{
						Name: "/usr/local/bin/node",
					},
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "src",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "checkoutservice-84cb944764-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "currencyservice-76f9b766b4-*",
							Namespace:      "online-boutique",
							Port:           7000,
						},
					},
					Process: &lapi.Process{
						Name: "/src/checkout",
					},
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "dst",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "checkoutservice-84cb944764-*",
							Namespace:      "online-boutique",
							Port:           0,
						},
						Destination: lapi.Endpoint{
							Type:           "wep",
							Name:           "",
							AggregatedName: "currencyservice-76f9b766b4-*",
							Namespace:      "online-boutique",
							Port:           7000,
						},
					},
					Process: &lapi.Process{
						Name: "/usr/local/bin/node",
					},
					ProcessStats: &lapi.ProcessStats{
						MaxNumNamesPerFlow: 1,
						MinNumNamesPerFlow: 1,
						MaxNumIDsPerFlow:   1,
						MinNumIDsPerFlow:   1,
					},
				},
			},
			wantL3Flows: []L3Flow{
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "checkoutservice-84cb944764-*",
							PortNum:   0,
						},
						Dest: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "paymentservice-866fd4b98-*",
							PortNum:   0,
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts: []svapi.AggregatedPorts{
							{PortRanges: []svapi.PortRange{{MinPort: 50051, MaxPort: 50051}}},
						},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
					Processes: &svapi.GraphProcesses{
						Source: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"checkoutservice-84cb944764-*:paymentservice-866fd4b98-*:/src/checkout": {
							Name:               "/src/checkout",
							Source:             "checkoutservice-84cb944764-*",
							Destination:        "paymentservice-866fd4b98-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
						Dest: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"checkoutservice-84cb944764-*:paymentservice-866fd4b98-*:/usr/local/bin/node": {
							Name:               "/usr/local/bin/node",
							Source:             "checkoutservice-84cb944764-*",
							Destination:        "paymentservice-866fd4b98-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
					},
				},
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "checkoutservice-84cb944764-*",
							PortNum:   0,
						},
						Dest: FlowEndpoint{
							Type:      "rep",
							Namespace: "online-boutique",
							Name:      "",
							NameAggr:  "currencyservice-76f9b766b4-*",
							PortNum:   0,
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts: []svapi.AggregatedPorts{
							{PortRanges: []svapi.PortRange{{MinPort: 7000, MaxPort: 7000}}},
						},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
					Processes: &svapi.GraphProcesses{
						Source: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"checkoutservice-84cb944764-*:currencyservice-76f9b766b4-*:/src/checkout": {
							Name:               "/src/checkout",
							Source:             "checkoutservice-84cb944764-*",
							Destination:        "currencyservice-76f9b766b4-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
						Dest: svapi.GraphEndpointProcesses(map[string]svapi.GraphEndpointProcess{"checkoutservice-84cb944764-*:currencyservice-76f9b766b4-*:/usr/local/bin/node": {
							Name:               "/usr/local/bin/node",
							Source:             "checkoutservice-84cb944764-*",
							Destination:        "currencyservice-76f9b766b4-*",
							MinNumNamesPerFlow: 1,
							MaxNumNamesPerFlow: 1,
							MinNumIDsPerFlow:   1,
							MaxNumIDsPerFlow:   1,
						}}),
					},
				},
			},
		},
		{
			name: "Translate host endpoint types by lables",
			inputFlows: []lapi.L3Flow{
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "src",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "hep",
							AggregatedName: "jwhuang-hep-rocky8-1",
						},
						Destination: lapi.Endpoint{
							Type:           "hep",
							AggregatedName: "jwhuang-hep-rocky9-1",
						},
					},
					Process: &lapi.Process{
						Name: "/some/process",
					},
					SourceLabels: []lapi.FlowLabels{
						{
							Key: "hostendpoint.projectcalico.org/type",
							Values: []lapi.FlowLabelValue{
								{
									Value: "nonclusterhost",
									Count: 1,
								},
							},
						},
					},
					DestinationLabels: []lapi.FlowLabels{
						{
							Key: "hostendpoint.projectcalico.org/type",
							Values: []lapi.FlowLabelValue{
								{
									Value: "clusternode",
									Count: 1,
								},
							},
						},
					},
				},
				{
					Key: lapi.L3FlowKey{
						Action:   "allow",
						Reporter: "dst",
						Protocol: "tcp",
						Source: lapi.Endpoint{
							Type:           "net",
							AggregatedName: "pub",
						},
						Destination: lapi.Endpoint{
							Type:           "hep",
							AggregatedName: "jwhuang-hep-rocky8-1",
						},
					},
					Process: &lapi.Process{
						Name: "/other/process",
					},
					DestinationLabels: []lapi.FlowLabels{
						{
							Key: "hostendpoint.projectcalico.org/type",
							Values: []lapi.FlowLabelValue{
								{
									Value: "nonclusterhost",
									Count: 1,
								},
							},
						},
					},
				},
			},
			wantL3Flows: []L3Flow{
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:     "host",
							NameAggr: "jwhuang-hep-rocky8-1",
						},
						Dest: FlowEndpoint{
							Type:     "clusternode",
							NameAggr: "jwhuang-hep-rocky9-1",
						},
					},
					Processes: &svapi.GraphProcesses{
						Source: svapi.GraphEndpointProcesses{
							"jwhuang-hep-rocky8-1:jwhuang-hep-rocky9-1:/some/process": {
								Name:        "/some/process",
								Source:      "jwhuang-hep-rocky8-1",
								Destination: "jwhuang-hep-rocky9-1",
							},
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts:        []svapi.AggregatedPorts{{}},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
				},
				{
					Edge: FlowEdge{
						Source: FlowEndpoint{
							Type:     "net",
							NameAggr: "pub",
						},
						Dest: FlowEndpoint{
							Type:     "host",
							NameAggr: "jwhuang-hep-rocky8-1",
						},
					},
					Processes: &svapi.GraphProcesses{
						Dest: svapi.GraphEndpointProcesses{
							"pub:jwhuang-hep-rocky8-1:/other/process": {
								Source:      "pub",
								Name:        "/other/process",
								Destination: "jwhuang-hep-rocky8-1",
							},
						},
					},
					AggregatedProtoPorts: &svapi.AggregatedProtoPorts{
						ProtoPorts:        []svapi.AggregatedPorts{{}},
						NumOtherProtocols: 0,
					},
					Stats: svapi.GraphL3Stats{
						Allowed:        &svapi.GraphPacketStats{},
						DeniedAtSource: nil,
						DeniedAtDest:   nil,
						Connections: svapi.GraphConnectionStats{
							TotalPerSampleInterval: -9223372036854775808,
						},
						TCP: nil,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := []rest.MockResult{}
			results = append(results, rest.MockResult{
				Body: lapi.List[lapi.L3Flow]{
					Items: tt.inputFlows,
				},
			})

			// mock linseed client
			lsc := client.NewMockClient("", results...)

			gotFs, err := GetL3FlowData(context.TODO(), lsc, "any", "", v1.TimeRange{}, &FlowConfig{}, &Config{ServiceGraphCacheMaxAggregatedRecords: 5})
			if (err != nil) != tt.wantErr {
				t.Errorf("GetL3FlowData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotFs, tt.wantL3Flows) {
				t.Log(cmp.Diff(gotFs, tt.wantL3Flows))
				t.Errorf("GetL3FlowData() gotFs = %v, want %v", gotFs, tt.wantL3Flows)
			}
		})
	}
}
