// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
package api_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/api"
	"github.com/projectcalico/calico/libcalico-go/lib/resources"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/client"
	"github.com/projectcalico/calico/linseed/pkg/client/rest"
	"github.com/projectcalico/calico/lma/pkg/list"
)

var _ = Describe("Compliance elasticsearch report list tests", func() {
	var (
		complianceStore api.ComplianceStore
		ts              = time.Date(2019, 4, 15, 15, 0, 0, 0, time.UTC)
	)

	// addReport is a helper function used to add a report, and track how many reports have been added.
	addReport := func(typeName, name string, timeOffset int) *v1.ReportData {
		rep := &v1.ReportData{
			ReportData: &apiv3.ReportData{
				ReportTypeName: typeName,
				ReportName:     name,
				StartTime:      metav1.Time{Time: ts.Add(time.Duration(timeOffset) * time.Minute)},
				EndTime:        metav1.Time{Time: ts.Add((time.Duration(timeOffset) * time.Minute) + (2 * time.Minute))},
				GenerationTime: metav1.Time{Time: ts.Add(-time.Duration(timeOffset) * time.Minute)},
			},
		}
		Expect(complianceStore.StoreArchivedReport(rep)).ToNot(HaveOccurred())
		return rep
	}

	// waitForReports is a helper function used to wait for ES to process all of the report creations.
	waitForReports := func(numReports int) {
		get := func() error {
			r, err := complianceStore.RetrieveArchivedReportSummaries(context.Background(), api.ReportQueryParams{})
			if err != nil {
				return err
			}
			if r.Count != numReports {
				return fmt.Errorf("Expected %d results, found %d", numReports, r.Count)
			}
			return nil
		}
		Eventually(get, "5s", "0.1s").ShouldNot(HaveOccurred())
	}

	// ensureUTC updates the time fields in the ArchivedReportDatas are UTC so that ginkgo/gomega can be used to compare.
	ensureUTC := func(reps []*v1.ReportData) {
		for ii := range reps {
			reps[ii].EndTime.Time = reps[ii].EndTime.UTC()
			reps[ii].StartTime.Time = reps[ii].StartTime.UTC()
			reps[ii].GenerationTime.Time = reps[ii].GenerationTime.UTC()
		}
	}

	BeforeEach(func() {
		// Build a client for the FV linseed instance running locally.
		linseedDir := filepath.Join(os.Getenv("LINSEED_DIR"), "fv")
		cfg := rest.Config{
			CACertPath:     linseedDir + "/cert/RootCA.crt",
			URL:            "https://localhost:8444/",
			ClientCertPath: linseedDir + "/cert/localhost.crt",
			ClientKeyPath:  linseedDir + "/cert/localhost.key",
			ServerName:     "localhost",
		}
		linseed, err := client.NewClient("tenant-a", cfg, rest.WithTokenPath(filepath.Join(linseedDir, "client-token")))
		Expect(err).NotTo(HaveOccurred())

		// Use a random cluster name for each test.
		cluster := testutils.RandomClusterName()
		complianceStore = api.NewComplianceStore(linseed, cluster)
	})

	It("should store and retrieve reports properly", func() {
		By("storing a report")
		rep := &v1.ReportData{
			ReportData: &apiv3.ReportData{
				ReportName: "report-foo",
				EndTime:    metav1.Time{Time: ts.Add(time.Minute)},
			},
		}
		Expect(complianceStore.StoreArchivedReport(rep)).ToNot(HaveOccurred())

		By("retrieving report summaries")
		get := func() ([]*v1.ReportData, error) {
			s, err := complianceStore.RetrieveArchivedReportSummaries(context.Background(), api.ReportQueryParams{})
			if err != nil {
				return nil, err
			}
			return s.Reports, nil
		}
		Eventually(get, "5s", "0.1s").Should(HaveLen(1))

		By("retrieving a specific report")
		retrievedReport, err := complianceStore.RetrieveArchivedReport(context.TODO(), rep.UID())
		Expect(err).ToNot(HaveOccurred())
		Expect(retrievedReport.ReportName).To(Equal(rep.ReportName))

		By("storing a more recent second report")
		rep2 := &v1.ReportData{
			ReportData: &apiv3.ReportData{
				ReportName: "report-foo",
				EndTime:    metav1.Time{Time: ts.Add(2 * time.Minute)},
			},
		}
		Expect(complianceStore.StoreArchivedReport(rep2)).ToNot(HaveOccurred())

		By("retrieving last archived report summary")
		get2 := func() (time.Time, error) {
			rep, err := complianceStore.RetrieveLastArchivedReportSummary(context.TODO(), rep.ReportName)
			if err != nil {
				return time.Time{}, err
			}
			return rep.StartTime.UTC(), nil
		}
		Eventually(get2, "5s", "0.1s").Should(Equal(rep2.StartTime.UTC()))

		By("storing a more recent report with a different name")
		rep3 := &v1.ReportData{
			ReportData: &apiv3.ReportData{
				ReportName: "report-foo2",
				EndTime:    metav1.Time{Time: ts.Add(3 * time.Minute)},
			},
		}
		Expect(complianceStore.StoreArchivedReport(rep3)).ToNot(HaveOccurred())

		By("retrieving report-foo and not returning report-foo2")
		Eventually(get2, "5s", "0.1s").Should(Equal(rep2.StartTime.UTC()))
	})

	It("should retrieve no reportTypeName/reportName combinations when no reports are added", func() {
		By("retrieving the full set of unique reportTypeName/reportName combinations")
		r, err := complianceStore.RetrieveArchivedReportTypeAndNames(context.Background(), api.ReportQueryParams{})

		By("checking no results were returned")
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(HaveLen(0))
	})

	It("should retrieve the correct set of reportTypeName/reportName combinations", func() {
		By("storing a small number of reports with repeats")
		// Add a bunch of reports, with some repeated reportTypeName / reportName combinations.
		first := addReport("type1", "report1", 1) // 1
		_ = addReport("type2", "report1", 2)      // 2
		_ = addReport("type1", "report2", 3)      // 3
		_ = addReport("type3", "report3", 4)      // 4
		_ = addReport("type1", "report2", 3)      // Repeat of 3
		_ = addReport("type3", "report2", 5)      // 5
		last := addReport("type4", "report3", 6)  // 6
		waitForReports(6)

		By("retrieving the full set of unique reportTypeName/reportName combinations")
		cxt, cancel := context.WithCancel(context.Background())
		r, err := complianceStore.RetrieveArchivedReportTypeAndNames(cxt, api.ReportQueryParams{})

		By("checking we have the correct set of unique combinations")
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(HaveLen(6))
		Expect(r).To(ConsistOf(
			api.ReportTypeAndName{ReportTypeName: "type1", ReportName: "report1"},
			api.ReportTypeAndName{ReportTypeName: "type2", ReportName: "report1"},
			api.ReportTypeAndName{ReportTypeName: "type1", ReportName: "report2"},
			api.ReportTypeAndName{ReportTypeName: "type3", ReportName: "report3"},
			api.ReportTypeAndName{ReportTypeName: "type3", ReportName: "report2"},
			api.ReportTypeAndName{ReportTypeName: "type4", ReportName: "report3"},
		))

		By("retrieving the set of unique reportTypeName/reportName combinations with report filter")
		r, err = complianceStore.RetrieveArchivedReportTypeAndNames(cxt, api.ReportQueryParams{
			Reports: []api.ReportTypeAndName{{ReportTypeName: "type1"}, {ReportName: "report2"}, {ReportTypeName: "type3", ReportName: "report3"}},
		})

		By("checking we have the correct set of unique combinations")
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(HaveLen(4))
		Expect(r).To(ConsistOf(
			api.ReportTypeAndName{ReportTypeName: "type1", ReportName: "report1"},
			api.ReportTypeAndName{ReportTypeName: "type1", ReportName: "report2"},
			api.ReportTypeAndName{ReportTypeName: "type3", ReportName: "report3"},
			api.ReportTypeAndName{ReportTypeName: "type3", ReportName: "report2"},
		))

		By("retrieving the set of unique reportTypeName/reportName combinations with upper time filter")
		r, err = complianceStore.RetrieveArchivedReportTypeAndNames(cxt, api.ReportQueryParams{
			ToTime: first.StartTime.Format(time.RFC3339), // Query up to the first report
		})

		By("checking we have the correct set of unique combinations")
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r).To(ConsistOf(
			api.ReportTypeAndName{ReportTypeName: "type1", ReportName: "report1"},
		))

		By("retrieving the set of unique reportTypeName/reportName combinations with lower time filter")
		r, err = complianceStore.RetrieveArchivedReportTypeAndNames(cxt, api.ReportQueryParams{
			FromTime: last.EndTime.Format(time.RFC3339), // Query from the last report
		})

		By("checking we have the correct set of unique combinations")
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(HaveLen(1))
		Expect(r).To(ConsistOf(
			api.ReportTypeAndName{ReportTypeName: "type4", ReportName: "report3"},
		))

		By("retrieving the set of unique reportTypeName/reportName combinations with time range filter")
		r, err = complianceStore.RetrieveArchivedReportTypeAndNames(cxt, api.ReportQueryParams{
			FromTime: first.StartTime.Format(time.RFC3339), // Query from the first report
			ToTime:   last.EndTime.Format(time.RFC3339),    // to the last report.
		})

		By("checking we have the correct set of unique combinations")
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(HaveLen(6))
		Expect(r).To(ConsistOf(
			api.ReportTypeAndName{ReportTypeName: "type1", ReportName: "report1"},
			api.ReportTypeAndName{ReportTypeName: "type2", ReportName: "report1"},
			api.ReportTypeAndName{ReportTypeName: "type1", ReportName: "report2"},
			api.ReportTypeAndName{ReportTypeName: "type3", ReportName: "report3"},
			api.ReportTypeAndName{ReportTypeName: "type3", ReportName: "report2"},
			api.ReportTypeAndName{ReportTypeName: "type4", ReportName: "report3"},
		))

		By("checking we handle cancelled context")
		cancel()
		_, err = complianceStore.RetrieveArchivedReportTypeAndNames(cxt, api.ReportQueryParams{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle more than DefaultPageSize combinations of reportTypeName/reportName", func() {
		By("storing >DefaultPageSize unique reportTypeName/reportName combination with repeats")
		var unique []api.ReportTypeAndName
		// Add DefaultPageSize * 2 unique combinations (and add 2 reports of each)
		for ii := range api.DefaultPageSize * 2 {
			tn := fmt.Sprintf("type%d", ii)
			rn := fmt.Sprintf("report%d", ii)
			_ = addReport(tn, rn, ii*100)
			_ = addReport(tn, rn, ii*100)
			unique = append(unique, api.ReportTypeAndName{ReportTypeName: tn, ReportName: rn})
		}
		waitForReports(api.DefaultPageSize * 2)

		By("retrieving the full set of unique reportTypeName/reportName combinations")
		r, err := complianceStore.RetrieveArchivedReportTypeAndNames(context.Background(), api.ReportQueryParams{})
		By("checking we have the correct set of unique combinations")
		Expect(err).NotTo(HaveOccurred())
		Expect(r).To(HaveLen(api.DefaultPageSize * 2))
		Expect(r).To(ConsistOf(unique))
	})

	It("should retrieve no report summaries when no reports are added", func() {
		By("retrieving the full set of report summaries")
		r, err := complianceStore.RetrieveArchivedReportSummaries(context.Background(), api.ReportQueryParams{})

		By("checking no results were returned")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(0))
		Expect(r.Reports).To(HaveLen(0))
	})

	It("should retrieve the correct set of reports", func() {
		By("storing a small number of reports")
		// Add a bunch of reports, with some repeated reportTypeName / reportName combinations.
		r1 := addReport("type1", "report1", 10)
		r2 := addReport("type2", "report1", 20)
		r3 := addReport("type1", "report2", 30)
		r4 := addReport("type3", "report3", 40)
		r5 := addReport("type3", "report2", 50)
		r6 := addReport("type4", "report3", 60)
		waitForReports(6)

		By("retrieving the full set of report summaries (sort by startTime)")
		cxt, cancel := context.WithCancel(context.Background())
		r, err := complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{
			SortBy: []api.ReportSortBy{{Field: "startTime"}},
		})

		By("checking we have the correct set of reports in the correct order")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(6))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r6, r5, r4, r3, r2, r1}))

		By("retrieving the full set of report summaries (sort by ascending startTime)")
		r, err = complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{
			SortBy: []api.ReportSortBy{{Field: "startTime", Ascending: true}},
		})

		By("checking we have the correct set of reports in the correct order")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(6))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r1, r2, r3, r4, r5, r6}))

		By("retrieving the full set of report summaries (sort by ascending endTime)")
		r, err = complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{
			SortBy: []api.ReportSortBy{{Field: "endTime", Ascending: true}},
		})

		By("checking we have the correct set of reports in the correct order")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(6))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r1, r2, r3, r4, r5, r6}))

		By("retrieving the full set of report summaries (sort by generationTime)")
		r, err = complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{
			SortBy: []api.ReportSortBy{{Field: "generationTime"}}, // generationTime is in opposite order to start/end times
		})

		By("checking we have the correct set of reports in the correct order")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(6))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r1, r2, r3, r4, r5, r6}))

		By("retrieving the full set of report summaries (sort by descending reportTypeName and descending startTime)")
		r, err = complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{
			SortBy: []api.ReportSortBy{{Field: "reportTypeName"}, {Field: "startTime"}},
		})

		By("checking we have the correct set of reports in the correct order")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(6))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r6, r5, r4, r2, r3, r1}))

		By("retrieving the full set of report summaries (sort by ascending reportName and descending startTime), maxItems=4")
		maxItems := 4
		r, err = complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{
			SortBy:   []api.ReportSortBy{{Field: "reportName", Ascending: true}, {Field: "startTime"}},
			MaxItems: &maxItems,
		})

		By("checking we can receive the results for page 0")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(6))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r2, r1, r5, r3}))

		By("checking we can query page 1")
		r, err = complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{
			SortBy:   []api.ReportSortBy{{Field: "reportName", Ascending: true}, {Field: "startTime"}},
			MaxItems: &maxItems,
			Page:     1,
		})

		By("checking we can receive the results for page 1")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(6))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r6, r4}))

		By("checking we handle cancelled context")
		cancel()
		_, err = complianceStore.RetrieveArchivedReportSummaries(cxt, api.ReportQueryParams{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should handle the default sort order when start times are the same, sorting by time, type, name", func() {
		By("storing a small number of reports all with the same start time")
		// Add a bunch of reports all with the same start time
		r1 := addReport("type1", "report1", 1000)
		r2 := addReport("type2", "report1", 1000)
		r3 := addReport("type1", "report2", 1000)
		r4 := addReport("type3", "report3", 1000)
		r5 := addReport("type3", "report2", 1000)
		r6 := addReport("type4", "report3", 1000)
		r7 := addReport("type1", "report2", 1001) // Later start time from r1 (should appear first)
		waitForReports(7)

		By("retrieving the full set of report summaries (sort by startTime, reportTypeName, reportName)")
		r, err := complianceStore.RetrieveArchivedReportSummaries(context.Background(), api.ReportQueryParams{
			SortBy: []api.ReportSortBy{
				{Field: "startTime"}, {Field: "reportTypeName", Ascending: true}, {Field: "reportName", Ascending: true},
			},
		})

		By("checking we have the correct set of reports in the correct order")
		Expect(err).NotTo(HaveOccurred())
		Expect(r.Count).To(Equal(7))
		ensureUTC(r.Reports) // Normalize the times to make them comparable.
		Expect(r.Reports).To(Equal([]*v1.ReportData{r7, r1, r3, r2, r5, r4, r6}))
	})

	It("should store and retrieve lists properly", func() {
		ts := time.Date(2019, 4, 15, 15, 0, 0, 0, time.UTC)

		By("storing a network policy list")
		npResList := &list.TimestampedResourceList{
			ResourceList:              NewNetworkPolicyList(),
			RequestStartedTimestamp:   metav1.Time{Time: ts.Add(time.Minute)},
			RequestCompletedTimestamp: metav1.Time{Time: ts.Add(time.Minute)},
		}
		npResList.ResourceList.GetObjectKind().SetGroupVersionKind((&resources.TypeCalicoNetworkPolicies).GroupVersionKind())

		Expect(complianceStore.StoreList(resources.TypeCalicoNetworkPolicies, npResList)).ToNot(HaveOccurred())

		By("storing a second network policy list one hour in the future")
		npResList.RequestStartedTimestamp = metav1.Time{Time: ts.Add(2 * time.Minute)}
		npResList.RequestCompletedTimestamp = metav1.Time{Time: ts.Add(2 * time.Minute)}
		Expect(complianceStore.StoreList(resources.TypeCalicoNetworkPolicies, npResList)).ToNot(HaveOccurred())

		By("retrieving the network policy list, earliest first")
		start := ts.Add(-12 * time.Hour)
		end := ts.Add(12 * time.Hour)

		get := func() (*list.TimestampedResourceList, error) {
			return complianceStore.RetrieveList(resources.TypeCalicoNetworkPolicies, &start, &end, true)
		}
		Eventually(get, "5s", "0.1s").ShouldNot(BeNil())
	})
})

// NewNetworkPolicyList creates a new (zeroed) NetworkPolicyList struct with the TypeMetadata initialised to the current
// version.
// This is defined locally as it's a convenience method that is not widely used.
func NewNetworkPolicyList() *apiv3.NetworkPolicyList {
	return &apiv3.NetworkPolicyList{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindNetworkPolicyList,
			APIVersion: apiv3.GroupVersionCurrent,
		},
	}
}
