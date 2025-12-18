// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package l3

import (
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/testutils"
)

const dummyURL = "anyURL"

var (
	noFlows []v1.L3Flow
	flows   = []v1.L3Flow{
		{
			Key: v1.L3FlowKey{
				Action:   "pass",
				Reporter: "source",
				Protocol: "tcp",
				Source: v1.Endpoint{
					Type:           "wep",
					Name:           "",
					AggregatedName: "source-*",
				},
				Destination: v1.Endpoint{
					Type:           "wep",
					Name:           "",
					AggregatedName: "dest-*",
				},
			},
		},
		{
			Key: v1.L3FlowKey{
				Action:   "pass",
				Reporter: "source",
				Protocol: "udp",
				Source: v1.Endpoint{
					Type:           "wep",
					Name:           "",
					AggregatedName: "source-*",
				},
				Destination: v1.Endpoint{
					Type:           "wep",
					Name:           "",
					AggregatedName: "dns-*",
				},
			},
		},
	}
)

var (
	noFlowLogs []v1.FlowLog
	flowLogs   = []v1.FlowLog{
		{
			SourceNameAggr:  "source-*",
			SourceNamespace: "source-ns",
			SourceType:      "wep",
			SourceLabels:    &v1.FlowLogLabels{Labels: []string{"k8s-app=source-app", "projectcalico.org/namespace=source-ns"}},

			DestNameAggr:  "dest-*",
			DestNamespace: "dest-ns",
			DestPort:      testutils.Int64Ptr(443),
			DestType:      "ns",
			DestLabels:    &v1.FlowLogLabels{Labels: []string{"k8s-app=dest-app", "projectcalico.org/namespace=dest-ns"}},

			DestServiceNamespace: "dest-ns",
			DestServiceName:      "svc",
			DestServicePortNum:   testutils.Int64Ptr(443),

			Protocol: "tcp",
			Action:   "allow",
			Reporter: "src",
			Policies: &v1.FlowLogPolicy{
				AllPolicies:      []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
				EnforcedPolicies: []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
				PendingPolicies:  []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
				TransitPolicies:  []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
			},

			NumFlows:          1,
			NumFlowsCompleted: 0,
			NumFlowsStarted:   0,

			ProcessName:     "./server",
			NumProcessNames: 1,
			NumProcessIDs:   1,
			NumProcessArgs:  0,
			ProcessArgs:     []string{"-"},
			ProcessID:       "9667",
		},
		{
			SourceNameAggr:  "source-*",
			SourceNamespace: "source-ns",
			SourceType:      "wep",
			SourceLabels:    &v1.FlowLogLabels{Labels: []string{"k8s-app=source-app", "projectcalico.org/namespace=source-ns"}},

			DestNameAggr:  "dest-*",
			DestNamespace: "dest-ns",
			DestPort:      testutils.Int64Ptr(443),
			DestType:      "ns",
			DestLabels:    &v1.FlowLogLabels{Labels: []string{"k8s-app=dest-app", "projectcalico.org/namespace=dest-ns"}},

			DestServiceNamespace: "dest-ns",
			DestServiceName:      "svc",
			DestServicePortNum:   testutils.Int64Ptr(443),

			Protocol: "tcp",
			Action:   "allow",
			Reporter: "src",
			Policies: &v1.FlowLogPolicy{
				AllPolicies:      []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
				EnforcedPolicies: []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
				PendingPolicies:  []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
				TransitPolicies:  []string{"0|allow-tigera|dest-ns/allow-svc.dest-access|allow|1"},
			},

			NumFlows:          1,
			NumFlowsCompleted: 0,
			NumFlowsStarted:   0,

			ProcessName:     "./server",
			NumProcessNames: 1,
			NumProcessIDs:   1,
			ProcessArgs:     []string{"-"},
			ProcessID:       "9666",
			NumProcessArgs:  0,
		},
	}
)

var bulkResponseSuccess = &v1.BulkResponse{
	Total:     2,
	Succeeded: 2,
	Failed:    0,
}

var bulkResponsePartialSuccess = &v1.BulkResponse{
	Total:     2,
	Succeeded: 1,
	Failed:    1,
	Errors: []v1.BulkError{
		{
			Resource: "res",
			Type:     "index error",
			Reason:   "I couldn't do it",
		},
	},
}
