// Copyright (c) 2024 Tigera, Inc. All rights reserved

package file_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/prometheus/procfs"

	. "github.com/projectcalico/calico/felix/collector/file"
	"github.com/projectcalico/calico/felix/collector/flowlog"
	"github.com/projectcalico/calico/felix/collector/types/endpoint"
	"github.com/projectcalico/calico/felix/collector/types/tuple"
	"github.com/projectcalico/calico/felix/fv/flowlogs"
	"github.com/projectcalico/calico/felix/ip"
)

func BenchmarkFileReporter_Report(b *testing.B) {
	tempDir := os.TempDir()
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	reporter := NewReporter(tempDir, "test.log", 1, 2)
	if err := reporter.Start(); err != nil {
		b.Fatalf("Failed to start reporter: %v", err)
	}

	logSlice := makeLogSlice(b.N)
	proc, _ := procfs.NewProc(os.Getpid())
	stat, _ := proc.Stat()
	startCPU := stat.CPUTime()
	b.ReportAllocs()
	b.ResetTimer()

	err := reporter.Report(logSlice)
	if err != nil {
		b.Fatalf("Failed to report logs: %v", err)
	}

	runtime.GC()
	stat, _ = proc.Stat()
	endCPU := stat.CPUTime()
	b.ReportMetric((endCPU-startCPU)/float64(b.N)*1000000000, "ncpu/op")
}

func makeLogSlice(n int) []*flowlog.FlowLog {
	s := make([]*flowlog.FlowLog, n)
	for i := range n {

		ip1, _ := ip.ParseIPAs16Byte("10.65.0.0")
		ip2, _ := ip.ParseIPAs16Byte("10.65.1.0")
		tup := tuple.Make(ip1, ip2, 6, flowlogs.SourcePortIsIncluded, 8080)

		s[i] = &flowlog.FlowLog{
			FlowMeta: flowlog.FlowMeta{
				Tuple: tup,
				SrcMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "default",
					Name:           "foo-12345",
					AggregatedName: "foo-",
				},
				DstMeta: endpoint.Metadata{
					Type:           "wep",
					Namespace:      "default",
					Name:           "foo-1234b",
					AggregatedName: "foo-",
				},
				DstService: flowlog.EmptyService,
				Action:     "allow",
				Reporter:   "src",
			},
			FlowEnforcedPolicySet: flowlog.FlowPolicySet{
				"0|tier1|default/tier1.np1-1|pass|0":            {},
				"1|tier2|default/tier2.staged:np2-1|deny|-1":    {},
				"2|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
			},
			FlowPendingPolicySet: flowlog.FlowPolicySet{
				"0|tier1|default/tier1.np1-1|pass|0":            {},
				"1|tier2|default/tier2.staged:np2-1|deny|-1":    {},
				"2|__PROFILE__|__PROFILE__.kns.default|allow|0": {},
			},
			FlowProcessReportedStats: flowlog.FlowProcessReportedStats{
				FlowReportedStats: flowlog.FlowReportedStats{
					PacketsIn:       3,
					PacketsOut:      3,
					NumFlowsStarted: 3,
				},
			},
		}
	}
	return s
}
