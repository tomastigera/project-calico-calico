// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package report

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/compliance/pkg/config"
	"github.com/projectcalico/calico/compliance/pkg/flow"
	"github.com/projectcalico/calico/compliance/pkg/xrefcache"
	"github.com/projectcalico/calico/libcalico-go/lib/set"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

var (
	node1 = &v1.Benchmarks{
		Version:           "1.1.2",
		KubernetesVersion: "1.13.1",
		Type:              v1.TypeKubernetes,
		NodeName:          "node-1",
		Timestamp:         metav1.Now(),
		Tests: []v1.BenchmarkTest{
			{
				Section:     "2.0",
				SectionDesc: "desc-2.0",
				TestNumber:  "2.0.10",
				TestDesc:    "test-2.0.10",
				TestInfo:    "testinfo-2.0.10",
				Status:      "FAIL",
				Scored:      true,
			},
			{
				Section:     "1.0",
				SectionDesc: "desc-1.0",
				TestNumber:  "1.0.0",
				TestDesc:    "test-1.0.0",
				TestInfo:    "testinfo-1.0.0",
				Status:      "FAIL",
				Scored:      true,
			},
			{
				Section:     "1.1",
				SectionDesc: "desc-1.1",
				TestNumber:  "1.1.0",
				TestDesc:    "test-1.1.0",
				TestInfo:    "testinfo-1.1.0",
				Status:      "FAIL",
				Scored:      true,
			},
			{
				Section:     "1.0",
				SectionDesc: "desc-1.0",
				TestNumber:  "1.0.3",
				TestDesc:    "test-1.0.3",
				TestInfo:    "testinfo-1.0.3",
				Status:      "FAIL",
				Scored:      true,
			},
			{
				Section:     "1.0",
				SectionDesc: "desc-1.0",
				TestNumber:  "1.0.2",
				TestDesc:    "test-1.0.2",
				TestInfo:    "testinfo-1.0.2",
				Status:      "FAIL",
				Scored:      true,
			},
		},
	}

	// Node2 - all section1 is not scored
	node2 = &v1.Benchmarks{
		Version:   "1.1.2",
		Type:      v1.TypeKubernetes,
		NodeName:  "node-2",
		Timestamp: metav1.Now(),
		Tests: []v1.BenchmarkTest{
			{
				Section:     "1.0",
				SectionDesc: "desc-1.0",
				TestNumber:  "1.0.0",
				TestDesc:    "test-1.0.0",
				TestInfo:    "testinfo-1.0.0",
				Status:      "PASS",
				Scored:      false,
			},
			{
				Section:     "1.0",
				SectionDesc: "desc-1.0.1",
				TestNumber:  "1.0.1",
				TestDesc:    "test-1.0.1",
				TestInfo:    "testinfo-1.0.1",
				Status:      "PASS",
				Scored:      false,
			},
			{
				Section:     "2.0",
				SectionDesc: "desc-2.0",
				TestNumber:  "2.0.0",
				TestDesc:    "test-2.0.0",
				TestInfo:    "testinfo-2.0.0",
				Status:      "PASS",
				Scored:      true,
			},
		},
	}

	node3 = &v1.Benchmarks{
		Version:   "1.1.2",
		Type:      v1.TypeKubernetes,
		NodeName:  "node-abc",
		Timestamp: metav1.Now(),
		Tests: []v1.BenchmarkTest{
			{
				Section:     "1.0",
				SectionDesc: "desc-1.0",
				TestNumber:  "1.0.0",
				TestDesc:    "test-1.0.0",
				TestInfo:    "testinfo-1.0.0",
				Status:      "FAIL",
				Scored:      false,
			},
			{
				Section:     "1.1",
				SectionDesc: "desc-1.1",
				TestNumber:  "1.1.0",
				TestDesc:    "test-1.1.0",
				TestInfo:    "testinfo-1.1.0",
				Status:      "INFO",
				Scored:      false,
			},
			{
				Section:     "1.2",
				SectionDesc: "desc-1.2",
				TestNumber:  "1.2.0",
				TestDesc:    "test-1.2.0",
				TestInfo:    "testinfo-1.2.0",
				Status:      "PASS",
				Scored:      false,
			},
		},
	}
)

// Fake benchmarker
type fakeBenchmarker struct {
	started bool
	stopped bool
	results []api.BenchmarksResult
	start   time.Time
	end     time.Time
}

func (b *fakeBenchmarker) RetrieveLatestBenchmarks(
	ctx context.Context, ct v1.BenchmarkType, filters []v1.BenchmarksFilter, start, end time.Time,
) <-chan api.BenchmarksResult {
	b.start = start
	b.end = end
	ch := make(chan api.BenchmarksResult)
	go func() {
		defer close(ch)
		b.started = true
		for _, res := range b.results {
			ch <- res
		}
		b.stopped = true
	}()
	return ch
}

var (
	Threshold100 = 100
	Threshold75  = 75
)

var _ = Describe("CIS report tests", func() {
	var r *reporter
	var healthCnt int
	var reportStorer *fakeReportStorer
	var cfg *Config
	var benchmarker *fakeBenchmarker
	var run func()
	var rerr error

	BeforeEach(func() {
		// Reset the health count.
		healthCnt = 0

		// Create a config, by default include all CIS results.
		baseCfg := config.MustLoadConfig()
		baseCfg.ReportName = "report"
		numFailedTests := 5
		cfg = &Config{
			Config: *baseCfg,
			Report: &apiv3.GlobalReport{
				ObjectMeta: metav1.ObjectMeta{
					Name: "report",
				},
				Spec: apiv3.ReportSpec{
					ReportType: "report-type",
					Schedule:   "@daily",
					CIS: &apiv3.CISBenchmarkParams{
						IncludeUnscoredTests: true,
						HighThreshold:        nil,
						MedThreshold:         nil,
						NumFailedTests:       &numFailedTests,
					},
				},
			},
			ReportType: &apiv3.GlobalReportType{
				ObjectMeta: metav1.ObjectMeta{
					Name: "report-type",
				},
				Spec: apiv3.ReportTypeSpec{
					IncludeCISBenchmarkData: true,
				},
			},
		}

		// Create a fake backends
		benchmarker = &fakeBenchmarker{}
		reportStorer = &fakeReportStorer{}
		longTermArchiver := &fakeLogDispatcher{}

		// Create a reporter "by hand" passing in test interfaces.
		r = &reporter{
			ctx: context.Background(),
			cfg: cfg,
			clog: logrus.WithFields(logrus.Fields{
				"name":  cfg.Report.Name,
				"type":  cfg.ReportType.Name,
				"start": cfg.ParsedReportStart.Format(time.RFC3339),
				"end":   cfg.ParsedReportEnd.Format(time.RFC3339),
			}),
			benchmarker:      benchmarker,
			archiver:         reportStorer,
			healthy:          func() { healthCnt++ },
			inScopeEndpoints: make(map[apiv3.ResourceID]*reportEndpoint),
			services:         make(map[apiv3.ResourceID]xrefcache.CacheEntryFlags),
			namespaces:       make(map[apiv3.ResourceID]xrefcache.CacheEntryFlags),
			serviceAccounts:  set.New[apiv3.ResourceID](),
			policies:         set.New[apiv3.ResourceID](),
			data: &apiv3.ReportData{
				ReportName:     "report",
				ReportTypeName: "report-type",
				ReportSpec:     cfg.Report.Spec,
				ReportTypeSpec: cfg.ReportType.Spec,
				StartTime:      metav1.Time{Time: cfg.ParsedReportStart},
				EndTime:        metav1.Time{Time: cfg.ParsedReportEnd},
			},
			flowLogFilter:    flow.NewFlowLogFilter(),
			longTermArchiver: longTermArchiver,
		}

		run = func() {
			// Start the reporter and wait until completed.
			completed := false
			go func() {
				rerr = r.run()
				completed = true
			}()
			Eventually(func() bool { return benchmarker.started }, "5s", "0.1s").Should(BeTrue())
			Eventually(func() bool { return benchmarker.stopped }, "5s", "0.1s").Should(BeTrue())
			Eventually(func() bool { return completed }, "5s", "0.1s").Should(BeTrue())
		}
	})

	It("should handle no data at all", func() {
		run()
		Expect(rerr).NotTo(HaveOccurred())
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(0))
	})

	It("should fix start/end times that are too close", func() {
		By("Setting end-start to be less than 1.5xsnapshot interval")
		cfg.ParsedReportEnd = now
		cfg.ParsedReportStart = now.Add(-DayAndHalf + time.Hour)
		run()

		By("Checking start time was adjusted to 1.5xsnapshot interval from end")
		Expect(rerr).NotTo(HaveOccurred())
		Expect(benchmarker.end).To(Equal(cfg.ParsedReportEnd))
		Expect(benchmarker.start).To(Equal(cfg.ParsedReportEnd.Add(-DayAndHalf)))
	})

	It("should not fix start/end times that are sufficiently far apart", func() {
		By("Setting end-start to be greater than 1.5xsnapshot interval")
		cfg.ParsedReportEnd = now
		cfg.ParsedReportStart = now.Add(-DayAndHalf - time.Hour)
		run()

		By("Checking start time was not adjusted")
		Expect(rerr).NotTo(HaveOccurred())
		Expect(benchmarker.end).To(Equal(cfg.ParsedReportEnd))
		Expect(benchmarker.start).To(Equal(cfg.ParsedReportStart))
	})

	It("should handle a few reports with including all tests", func() {
		By("Setting the results to return 3 nodes")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node3,
			},
			{
				Benchmarks: node1,
			},
			{
				Benchmarks: node2,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(3))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 5,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     5,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    3,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.2",
							TestDesc:   "test-1.0.2",
							TestInfo:   "testinfo-1.0.2",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.3",
							TestDesc:   "test-1.0.3",
							TestInfo:   "testinfo-1.0.3",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.10",
							TestDesc:   "test-2.0.10",
							TestInfo:   "testinfo-2.0.10",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmark[1]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node2.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "HIGH",
				TotalFail: 0,
				TotalPass: 3,
				TotalInfo: 0,
				Total:     3,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "HIGH",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    0,
					Pass:    2,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "PASS",
							Scored:     false,
						},
						{
							TestNumber: "1.0.1",
							TestDesc:   "test-1.0.1",
							TestInfo:   "testinfo-1.0.1",
							Status:     "PASS",
							Scored:     false,
						},
					},
				},
				{
					Status:  "HIGH",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    0,
					Pass:    1,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.0",
							TestDesc:   "test-2.0.0",
							TestInfo:   "testinfo-2.0.0",
							Status:     "PASS",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmark[2]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node3.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "MED",
				TotalFail: 1,
				TotalPass: 1,
				TotalInfo: 1,
				Total:     2,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     false,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    0,
					Pass:    0,
					Info:    1,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "INFO",
							Scored:     false,
						},
					},
				},
				{
					Status:  "HIGH",
					Section: "1.2",
					Desc:    "desc-1.2",
					Fail:    0,
					Pass:    1,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.2.0",
							TestDesc:   "test-1.2.0",
							TestInfo:   "testinfo-1.2.0",
							Status:     "PASS",
							Scored:     false,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 1,
			MedCount:  1,
			LowCount:  1,
		}))
	})

	It("should handle filtering out unscored", func() {
		By("Setting the report filter to exclude unscored tests (the default)")
		cfg.Report.Spec.CIS.IncludeUnscoredTests = false

		By("Setting the results to return 3 nodes")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node3,
			},
			{
				Benchmarks: node1,
			},
			{
				Benchmarks: node2,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(3))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 5,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     5,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    3,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.2",
							TestDesc:   "test-1.0.2",
							TestInfo:   "testinfo-1.0.2",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.3",
							TestDesc:   "test-1.0.3",
							TestInfo:   "testinfo-1.0.3",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.10",
							TestDesc:   "test-2.0.10",
							TestInfo:   "testinfo-2.0.10",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmark[1]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node2.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "HIGH",
				TotalFail: 0,
				TotalPass: 1,
				TotalInfo: 0,
				Total:     1,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "HIGH",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    0,
					Pass:    1,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.0",
							TestDesc:   "test-2.0.0",
							TestInfo:   "testinfo-2.0.0",
							Status:     "PASS",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmark[2]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node3.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 0,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     0,
			},
			Results: nil,
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 1,
			MedCount:  0,
			LowCount:  2,
		}))
	})

	It("should handle a few reports with including all tests", func() {
		By("Setting the results to return 3 nodes")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node3,
			},
			{
				Benchmarks: node1,
			},
			{
				Benchmarks: node2,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(3))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 5,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     5,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    3,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.2",
							TestDesc:   "test-1.0.2",
							TestInfo:   "testinfo-1.0.2",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.3",
							TestDesc:   "test-1.0.3",
							TestInfo:   "testinfo-1.0.3",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.10",
							TestDesc:   "test-2.0.10",
							TestInfo:   "testinfo-2.0.10",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmark[1]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node2.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "HIGH",
				TotalFail: 0,
				TotalPass: 3,
				TotalInfo: 0,
				Total:     3,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "HIGH",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    0,
					Pass:    2,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "PASS",
							Scored:     false,
						},
						{
							TestNumber: "1.0.1",
							TestDesc:   "test-1.0.1",
							TestInfo:   "testinfo-1.0.1",
							Status:     "PASS",
							Scored:     false,
						},
					},
				},
				{
					Status:  "HIGH",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    0,
					Pass:    1,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.0",
							TestDesc:   "test-2.0.0",
							TestInfo:   "testinfo-2.0.0",
							Status:     "PASS",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmark[2]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node3.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "MED",
				TotalFail: 1,
				TotalPass: 1,
				TotalInfo: 1,
				Total:     2,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     false,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    0,
					Pass:    0,
					Info:    1,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "INFO",
							Scored:     false,
						},
					},
				},
				{
					Status:  "HIGH",
					Section: "1.2",
					Desc:    "desc-1.2",
					Fail:    0,
					Pass:    1,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.2.0",
							TestDesc:   "test-1.2.0",
							TestInfo:   "testinfo-1.2.0",
							Status:     "PASS",
							Scored:     false,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 1,
			MedCount:  1,
			LowCount:  1,
		}))
	})

	It("should handle excluded with no included", func() {
		By("Setting the report filter exclude a couple of tests")
		cfg.Report.Spec.CIS.ResultsFilters = []apiv3.CISBenchmarkFilter{{
			Exclude: []string{"1.0.2", "1.1.0"},
		}}

		By("Setting the results to return 1 node")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node1,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 3,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     3,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    2,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.3",
							TestDesc:   "test-1.0.3",
							TestInfo:   "testinfo-1.0.3",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.10",
							TestDesc:   "test-2.0.10",
							TestInfo:   "testinfo-2.0.10",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})

	It("should handle included with on excluded", func() {
		By("Setting the report filter to include one test")
		cfg.Report.Spec.CIS.ResultsFilters = []apiv3.CISBenchmarkFilter{{
			Include: []string{"1.0.2"},
		}}

		By("Setting the results to return 1 node")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node1,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 1,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     1,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.2",
							TestDesc:   "test-1.0.2",
							TestInfo:   "testinfo-1.0.2",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})

	It("should handle section-wide exclude and choose the first matching filter", func() {
		By("Setting the matching report filter to exclude a section")
		cfg.Report.Spec.CIS.ResultsFilters = []apiv3.CISBenchmarkFilter{
			{
				BenchmarkSelection: &apiv3.CISBenchmarkSelection{
					KubernetesVersion: "1.12",
				},
			},
			{
				BenchmarkSelection: &apiv3.CISBenchmarkSelection{
					KubernetesVersion: "1.13",
				},
				Exclude: []string{"1.0"},
			},
			{
				BenchmarkSelection: &apiv3.CISBenchmarkSelection{
					KubernetesVersion: "1.13.1",
				},
			},
		}

		By("Setting the results to return 1 node")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node1,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 2,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     2,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "LOW",
					Section: "2.0",
					Desc:    "desc-2.0",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "2.0.10",
							TestDesc:   "test-2.0.10",
							TestInfo:   "testinfo-2.0.10",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})

	It("should handle section-wide include", func() {
		By("Setting the report filter to include a section")
		cfg.Report.Spec.CIS.ResultsFilters = []apiv3.CISBenchmarkFilter{{
			Include: []string{"1.0"},
		}}

		By("Setting the results to return 1 node")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node1,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 3,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     3,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    3,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.2",
							TestDesc:   "test-1.0.2",
							TestInfo:   "testinfo-1.0.2",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.3",
							TestDesc:   "test-1.0.3",
							TestInfo:   "testinfo-1.0.3",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})

	It("should handle test exclusion over section inclustion", func() {
		By("Setting the report filter to include 1.0 and exclude 1.0.2")
		cfg.Report.Spec.CIS.ResultsFilters = []apiv3.CISBenchmarkFilter{{
			Include: []string{"1.0"},
			Exclude: []string{"1.0.2"},
		}}

		By("Setting the results to return 1 node")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: node1,
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 2,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     2,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.0",
					Desc:    "desc-1.0",
					Fail:    2,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.0.0",
							TestDesc:   "test-1.0.0",
							TestInfo:   "testinfo-1.0.0",
							Status:     "FAIL",
							Scored:     true,
						},
						{
							TestNumber: "1.0.3",
							TestDesc:   "test-1.0.3",
							TestInfo:   "testinfo-1.0.3",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})

	It("should handle duplicate tests by only using the first", func() {
		By("Setting the results to return 1 node with duplicate tests")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: &v1.Benchmarks{
					Version:   "1.1.2",
					Type:      v1.TypeKubernetes,
					NodeName:  "node-1",
					Timestamp: metav1.Now(),
					Tests: []v1.BenchmarkTest{
						{
							Section:     "1.1",
							SectionDesc: "desc-1.1",
							TestNumber:  "1.1.0",
							TestDesc:    "test-1.1.0",
							TestInfo:    "testinfo-1.1.0",
							Status:      "FAIL",
							Scored:      true,
						},
						{
							Section:     "1.1",
							SectionDesc: "desc-1.1",
							TestNumber:  "1.1.0",
							TestDesc:    "test-1.1.0",
							TestInfo:    "testinfo-1.1.0",
							Status:      "PASS",
							Scored:      true,
						},
					},
				},
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 1,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     1,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})

	It("should handle an errored benchmark", func() {
		By("Setting the results to return 1 node with an error")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: &v1.Benchmarks{
					Version:   "1.1.2",
					Type:      v1.TypeKubernetes,
					NodeName:  "node-1",
					Timestamp: metav1.Now(),
					Error:     "It didn't work",
				},
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))
		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 0,
				TotalPass: 0,
				TotalInfo: 0,
				Total:     0,
			},
			Results: nil,
		}))
		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})

	It("should handle an errored benchmark query", func() {
		By("Setting the results to return 1 node with duplicate tests")
		benchmarker.results = []api.BenchmarksResult{
			{
				Err: errors.New("This is an error"),
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).To(HaveOccurred())
		Expect(reportStorer.data).To(BeNil())
	})

	It("should handle explicitly specified thresholds", func() {
		By("Setting thresholds of 100 and 75")
		cfg.Report.Spec.CIS.HighThreshold = &Threshold100
		cfg.Report.Spec.CIS.MedThreshold = &Threshold75

		By("Setting results with one failed, one passed in different sections")
		benchmarker.results = []api.BenchmarksResult{
			{
				Benchmarks: &v1.Benchmarks{
					Version:   "1.1.2",
					Type:      v1.TypeKubernetes,
					NodeName:  "node-1",
					Timestamp: metav1.Now(),
					Tests: []v1.BenchmarkTest{
						{
							Section:     "1.1",
							SectionDesc: "desc-1.1",
							TestNumber:  "1.1.0",
							TestDesc:    "test-1.1.0",
							TestInfo:    "testinfo-1.1.0",
							Status:      "FAIL",
							Scored:      true,
						},
						{
							Section:     "1.2",
							SectionDesc: "desc-1.2",
							TestNumber:  "1.2.0",
							TestDesc:    "test-1.2.0",
							TestInfo:    "testinfo-1.2.0",
							Status:      "PASS",
							Scored:      true,
						},
					},
				},
			},
		}

		By("running the reporter")
		run()
		Expect(rerr).NotTo(HaveOccurred())

		By("checking the report data")
		Expect(reportStorer.data).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).ToNot(BeNil())
		Expect(reportStorer.data.CISBenchmark).To(HaveLen(1))

		Expect(reportStorer.data.CISBenchmark[0]).To(Equal(apiv3.CISBenchmarkNode{
			NodeName: node1.NodeName,
			Summary: apiv3.CISBenchmarkNodeSummary{
				Status:    "LOW",
				TotalFail: 1,
				TotalPass: 1,
				TotalInfo: 0,
				Total:     2,
			},
			Results: []apiv3.CISBenchmarkSectionResult{
				{
					Status:  "LOW",
					Section: "1.1",
					Desc:    "desc-1.1",
					Fail:    1,
					Pass:    0,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.1.0",
							TestDesc:   "test-1.1.0",
							TestInfo:   "testinfo-1.1.0",
							Status:     "FAIL",
							Scored:     true,
						},
					},
				},
				{
					Status:  "HIGH",
					Section: "1.2",
					Desc:    "desc-1.2",
					Fail:    0,
					Pass:    1,
					Info:    0,
					Results: []apiv3.CISBenchmarkResult{
						{
							TestNumber: "1.2.0",
							TestDesc:   "test-1.2.0",
							TestInfo:   "testinfo-1.2.0",
							Status:     "PASS",
							Scored:     true,
						},
					},
				},
			},
		}))

		Expect(reportStorer.data.CISBenchmarkSummary).To(Equal(apiv3.CISBenchmarkSummary{
			Type:      "kube",
			HighCount: 0,
			MedCount:  0,
			LowCount:  1,
		}))
	})
})
