// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package flowlog

import (
	"fmt"
	"net"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/lib/std/uniquelabels"
)

var _ = Describe("FlowLog JSON serialization", func() {
	argList := []string{"arg1", "arg2"}
	emptyList := []string{"-"}
	Describe("should set every field", func() {
		policies := FlowPolicySet{
			"0|tier.policy|pass|0":                      emptyValue,
			"1|default.knp.default.default-deny|deny|1": emptyValue,
		}
		pendingPolicies := FlowPolicySet{
			"0|tier.policy|allow|0": emptyValue,
		}
		transitPolicies := FlowPolicySet{
			"0|forward-tier.foward-policy|pass|0": emptyValue,
		}
		flowLog := FlowLog{
			StartTime: time.Now(),
			EndTime:   time.Now(),
			FlowMeta: FlowMeta{
				Tuple: tuple.Tuple{
					Proto: 6,
					Src:   [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					Dst:   [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					L4Src: 345,
					L4Dst: 80,
				},
				SrcMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "test",
					Name:           "test",
					AggregatedName: "test-*",
				},
				DstMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "test",
					Name:           "test",
					AggregatedName: "test-*",
				},
				DstService: FlowService{
					Name:      "svc2",
					Namespace: "svc2-ns",
					PortName:  "*",
					PortNum:   80,
				},
				Action:   "allow",
				Reporter: "src",
			},
			FlowDestDomains: FlowDestDomains{
				Domains: map[string]empty{
					"google.com":     emptyValue,
					"www.google.com": emptyValue,
				},
			},
			FlowLabels: FlowLabels{
				SrcLabels: uniquelabels.Make(map[string]string{"foo": "bar", "foo2": "bar2"}),
				DstLabels: uniquelabels.Make(map[string]string{"foo": "bar", "foo2": "bar2"}),
			},
			FlowEnforcedPolicySet: policies,
			FlowPendingPolicySet:  pendingPolicies,
			FlowTransitPolicySet:  transitPolicies,
			FlowExtras: FlowExtras{
				OriginalSourceIPs:    []net.IP{net.ParseIP("10.0.1.1")},
				NumOriginalSourceIPs: 1,
			},
			FlowProcessReportedStats: FlowProcessReportedStats{
				ProcessName:      "*",
				NumProcessNames:  2,
				ProcessID:        "*",
				NumProcessIDs:    2,
				ProcessArgs:      argList,
				NumProcessArgs:   2,
				NatOutgoingPorts: []int{8999},
				FlowReportedStats: FlowReportedStats{
					PacketsIn:             1,
					PacketsOut:            2,
					BytesIn:               3,
					BytesOut:              4,
					TransitPacketsIn:      5,
					TransitPacketsOut:     6,
					TransitBytesIn:        7,
					TransitBytesOut:       8,
					NumFlowsStarted:       9,
					NumFlowsCompleted:     10,
					NumFlows:              11,
					HTTPRequestsAllowedIn: 12,
					HTTPRequestsDeniedIn:  13,
				},
				FlowReportedTCPStats: FlowReportedTCPStats{
					SendCongestionWnd: TCPWnd{
						Mean: 2,
						Min:  3,
					},
					SmoothRtt: TCPRtt{
						Mean: 2,
						Max:  3,
					},
					MinRtt: TCPRtt{
						Mean: 2,
						Max:  3,
					},
					Mss: TCPMss{
						Mean: 2,
						Min:  3,
					},
					TotalRetrans:   7,
					LostOut:        8,
					UnrecoveredRTO: 9,
					Count:          1,
				},
			},
		}

		out := ToOutput(&flowLog)
		// Use reflection to loop over the fields and ensure they all have non
		// zero values
		oType := reflect.TypeFor[JSONOutput]()
		oVal := reflect.ValueOf(out)
		for i := 0; i < oType.NumField(); i++ {
			field := oType.Field(i)
			zeroVal := reflect.Zero(field.Type)
			actualVal := oVal.Field(i)
			It(fmt.Sprintf("should set %s", field.Name), func() {
				Expect(actualVal.Interface()).ToNot(Equal(zeroVal.Interface()))
			})
		}
	})

	Describe("should handle empty fields", func() {
		flowLog := FlowLog{
			StartTime: time.Now(),
			EndTime:   time.Now(),
			FlowMeta: FlowMeta{
				Tuple: tuple.Tuple{
					Proto: 6,
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					L4Src: unsetIntField,
					L4Dst: 80,
				},
				SrcMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "test",
					Name:           "test",
					AggregatedName: "test-*",
				},
				DstMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "test",
					Name:           "test",
					AggregatedName: "test-*",
				},
				Action:   "allow",
				Reporter: "src",
			},
			FlowLabels: FlowLabels{
				SrcLabels: uniquelabels.Nil,
				DstLabels: uniquelabels.Nil,
			},
			FlowExtras: FlowExtras{
				OriginalSourceIPs:    []net.IP{},
				NumOriginalSourceIPs: 0,
			},
			FlowProcessReportedStats: FlowProcessReportedStats{
				ProcessName:     "-",
				NumProcessNames: 0,
				ProcessID:       "-",
				NumProcessIDs:   0,
				ProcessArgs:     emptyList,
				NumProcessArgs:  0,
				FlowReportedStats: FlowReportedStats{
					PacketsIn:             1,
					PacketsOut:            2,
					BytesIn:               3,
					BytesOut:              4,
					TransitPacketsIn:      5,
					TransitPacketsOut:     6,
					TransitBytesIn:        7,
					TransitBytesOut:       8,
					NumFlowsStarted:       9,
					NumFlowsCompleted:     10,
					NumFlows:              11,
					HTTPRequestsAllowedIn: 12,
					HTTPRequestsDeniedIn:  13,
				},
				FlowReportedTCPStats: FlowReportedTCPStats{
					SendCongestionWnd: TCPWnd{
						Mean: 2,
						Min:  3,
					},
					SmoothRtt: TCPRtt{
						Mean: 2,
						Max:  3,
					},
					MinRtt: TCPRtt{
						Mean: 2,
						Max:  3,
					},
					Mss: TCPMss{
						Mean: 2,
						Min:  3,
					},
					TotalRetrans:   7,
					LostOut:        8,
					UnrecoveredRTO: 9,
					Count:          1,
				},
			},
		}

		out := ToOutput(&flowLog)

		zeroFieldNames := map[string]any{
			"SourceIP":             nil,
			"DestIP":               nil,
			"SourcePortNum":        nil,
			"SourceLabels":         nil,
			"DestServiceNamespace": nil,
			"DestServiceName":      nil,
			"DestServicePortName":  nil,
			"DestServicePortNum":   0,
			"DestLabels":           nil,
			"DestDomains":          nil,
			"Policies":             nil,
			"OrigSourceIPs":        nil,
			"NumOrigSourceIPs":     nil,
			"NumProcessNames":      0,
			"NumProcessIDs":        0,
			"NumProcessArgs":       0,
			"NatOutgoingPorts":     nil,
		}
		// Use reflection to loop over the fields and ensure they all have non
		// zero values
		oType := reflect.TypeFor[JSONOutput]()
		oVal := reflect.ValueOf(out)
		for i := 0; i < oType.NumField(); i++ {
			field := oType.Field(i)
			zeroVal := reflect.Zero(field.Type)
			actualVal := oVal.Field(i)
			if _, ok := zeroFieldNames[field.Name]; ok {
				It(fmt.Sprintf("should not set %s", field.Name), func() {
					Expect(actualVal.Interface()).To(Equal(zeroVal.Interface()))
				})
			} else {
				It(fmt.Sprintf("should set %s", field.Name), func() {
					Expect(actualVal.Interface()).ToNot(Equal(zeroVal.Interface()))
				})
			}
		}
	})

	Describe("should not set source and destination ports for icmp flow", func() {
		flowLog := FlowLog{
			StartTime: time.Now(),
			EndTime:   time.Now(),
			FlowMeta: FlowMeta{
				Tuple: tuple.Tuple{
					Proto: 1,
					Src:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					Dst:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					L4Src: 1234,
					L4Dst: 2948,
				},
				SrcMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "test",
					Name:           "test",
					AggregatedName: "test-*",
				},
				DstMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "test",
					Name:           "test",
					AggregatedName: "test-*",
				},
				Action:   "allow",
				Reporter: "src",
			},
			FlowLabels: FlowLabels{
				SrcLabels: uniquelabels.Nil,
				DstLabels: uniquelabels.Nil,
			},
			FlowExtras: FlowExtras{
				OriginalSourceIPs:    []net.IP{},
				NumOriginalSourceIPs: 0,
			},
			FlowProcessReportedStats: FlowProcessReportedStats{
				ProcessName:     "felix",
				NumProcessNames: 2,
				ProcessID:       "1234",
				NumProcessIDs:   2,
				ProcessArgs:     argList,
				NumProcessArgs:  2,
				FlowReportedStats: FlowReportedStats{
					PacketsIn:             1,
					PacketsOut:            2,
					BytesIn:               3,
					BytesOut:              4,
					TransitPacketsIn:      5,
					TransitPacketsOut:     6,
					TransitBytesIn:        7,
					TransitBytesOut:       8,
					NumFlowsStarted:       9,
					NumFlowsCompleted:     10,
					NumFlows:              11,
					HTTPRequestsAllowedIn: 12,
					HTTPRequestsDeniedIn:  13,
				},
				FlowReportedTCPStats: FlowReportedTCPStats{
					SendCongestionWnd: TCPWnd{
						Mean: 2,
						Min:  3,
					},
					SmoothRtt: TCPRtt{
						Mean: 2,
						Max:  3,
					},
					MinRtt: TCPRtt{
						Mean: 2,
						Max:  3,
					},
					Mss: TCPMss{
						Mean: 2,
						Min:  3,
					},
					TotalRetrans:   7,
					LostOut:        8,
					UnrecoveredRTO: 9,
					Count:          1,
				},
			},
		}

		out := ToOutput(&flowLog)

		zeroFieldNames := map[string]any{
			"SourceIP":             nil,
			"DestIP":               nil,
			"SourcePortNum":        nil,
			"DestPortNum":          nil,
			"DestServiceNamespace": nil,
			"DestServiceName":      nil,
			"DestServicePortName":  nil,
			"DestServicePortNum":   0,
			"DestDomains":          nil,
			"SourceLabels":         nil,
			"DestLabels":           nil,
			"Policies":             nil,
			"OrigSourceIPs":        nil,
			"NumOrigSourceIPs":     nil,
			"NatOutgoingPorts":     nil,
		}
		// Use reflection to loop over the fields and ensure they all have non
		// zero values
		oType := reflect.TypeFor[JSONOutput]()
		oVal := reflect.ValueOf(out)
		for i := 0; i < oType.NumField(); i++ {
			field := oType.Field(i)
			zeroVal := reflect.Zero(field.Type)
			actualVal := oVal.Field(i)
			if _, ok := zeroFieldNames[field.Name]; ok {
				It(fmt.Sprintf("should not set %s", field.Name), func() {
					Expect(actualVal.Interface()).To(Equal(zeroVal.Interface()))
				})
			} else {
				It(fmt.Sprintf("should set %s", field.Name), func() {
					Expect(actualVal.Interface()).ToNot(Equal(zeroVal.Interface()))
				})
			}
		}
	})
})
