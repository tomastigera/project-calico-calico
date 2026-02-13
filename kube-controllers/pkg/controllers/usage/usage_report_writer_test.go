package usage

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	usagev1 "github.com/tigera/api/pkg/apis/usage.tigera.io/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	k8sFake "k8s.io/client-go/kubernetes/fake"
	crtlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// These UTs validate that the reportWriter performs retries as expected, and does not write incomplete reports.
// The validation of report enrichment and writing to the datastore is handled by the FVs.
var _ = Describe("Usage Writer UTs", func() {
	var fakeRuntimeClient *errorReturningFakeRuntimeClient
	var fakeK8sClient kubernetes.Interface
	var fakeV3Client clientv3.Interface
	var stopCh chan struct{}
	reportWriterForTest := func(usageClient crtlclient.Client) reportWriter {
		return newReportWriter(
			make(chan basicLicenseUsageReport),
			stopCh,
			context.Background(),
			fakeK8sClient,
			fakeV3Client,
			usageClient,
			3*time.Second,
		)
	}

	BeforeEach(func() {
		// Fake runtime client that can be configured to return errors at specific request counts.
		fakeRuntimeClient = newErrorReturningFakeRuntimeClient()
		// Fake kubernetes client with no objects associated with it.
		fakeK8sClient = k8sFake.NewSimpleClientset()
		// Fake calico client that will only respond to License GET with a 404.
		fakeV3Client = fakeCalicoClient{}
		// Stop channel used for tests where we run the main loop.
		stopCh = make(chan struct{})
	})

	AfterEach(func() {
		close(stopCh)
	})

	Context("creation retries", func() {
		It("should fail immediately if writing to storage results in a non-retryable error", func() {
			fakeRuntimeClient.setError(errors.NewBadRequest("you know what you did wrong"))
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.writeDatastoreReport(&usagev1.LicenseUsageReport{
				ObjectMeta: metav1.ObjectMeta{Name: "report"},
				Spec:       usagev1.LicenseUsageReportSpec{},
			})
			Expect(err).To(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("create")).To(Equal(1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(1))
		})

		It("should retry and succeed if a transient error eventually resolves", func() {
			fakeRuntimeClient.setError(errors.NewTooManyRequests("chill", 1))
			fakeRuntimeClient.resolveCallAt("create", 2)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.writeDatastoreReport(&usagev1.LicenseUsageReport{
				ObjectMeta: metav1.ObjectMeta{Name: "report"},
				Spec:       usagev1.LicenseUsageReportSpec{},
			})
			Expect(err).To(Not(HaveOccurred()))

			Expect(fakeRuntimeClient.getRequestCount("create")).To(BeNumerically(">", 1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(1))
		})

		It("should retry and eventually fail if a transient error never resolves", func() {
			fakeRuntimeClient.setError(errors.NewTooManyRequests("chill", 1))
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.writeDatastoreReport(&usagev1.LicenseUsageReport{
				ObjectMeta: metav1.ObjectMeta{Name: "report"},
				Spec:       usagev1.LicenseUsageReportSpec{},
			})
			Expect(err).To(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("create")).To(BeNumerically(">", 1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(1))
		})

		It("should fail immediately if writing to storage results in an error indicating the CRD isn't present", func() {
			fakeRuntimeClient.err = &discovery.ErrGroupDiscoveryFailed{
				Groups: map[schema.GroupVersion]error{
					{Group: "foo", Version: "v1"}: fmt.Errorf("discovery failure"),
				},
			}
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.writeDatastoreReport(&usagev1.LicenseUsageReport{
				ObjectMeta: metav1.ObjectMeta{Name: "report"},
				Spec:       usagev1.LicenseUsageReportSpec{},
			})
			Expect(err).To(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("create")).To(Equal(1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(1))
		})
	})

	Context("deletion retries", func() {
		BeforeEach(func() {
			// The list calls that are made should always resolve without error in these tests. They are backed
			// by a cache, so we do not retry them.
			fakeRuntimeClient.resolveImmediately("list")
		})

		It("should fail immediately if deleting results in a non-retryable error", func() {
			fakeRuntimeClient.err = errors.NewBadRequest("you know what you did wrong")
			fakeRuntimeClient.seedReportFrom(time.Minute)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).To(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.getRequestCount("delete")).To(Equal(1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(2))
		})

		It("should retry and succeed if a transient error eventually resolves", func() {
			fakeRuntimeClient.err = errors.NewTooManyRequests("chill", 1)
			fakeRuntimeClient.resolveCallAt("delete", 2)
			fakeRuntimeClient.seedReportFrom(time.Minute)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.getRequestCount("delete")).To(BeNumerically(">", 1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(2))
		})

		It("should retry and eventually fail if a transient error never resolves", func() {
			fakeRuntimeClient.err = errors.NewTooManyRequests("chill", 1)
			fakeRuntimeClient.seedReportFrom(time.Minute)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).To(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.getRequestCount("delete")).To(BeNumerically(">", 1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(2))
		})

		It("should fail immediately if writing to storage results in an error indicating the CRD isn't present", func() {
			fakeRuntimeClient.err = &discovery.ErrGroupDiscoveryFailed{
				Groups: map[schema.GroupVersion]error{
					{Group: "foo", Version: "v1"}: fmt.Errorf("discovery failure"),
				},
			}
			fakeRuntimeClient.seedReportFrom(time.Minute)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).To(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.getRequestCount("delete")).To(Equal(1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(2))
		})
	})

	Context("cleanup old reports", func() {
		BeforeEach(func() {
			// The list and delete calls do not error in this set of tests.
			fakeRuntimeClient.resolveImmediately("list")
			fakeRuntimeClient.resolveImmediately("delete")
		})

		// Controller will start here, building up reports within the retention period.
		It("should delete no reports when all reports are within retention period", func() {
			fakeRuntimeClient.seedReportFrom(0 * time.Second)
			fakeRuntimeClient.seedReportFrom(1 * time.Second)
			fakeRuntimeClient.seedReportFrom(2 * time.Second)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(1))
		})

		// Eventually we reach a steady state, where we have reports filling the retention period, and each
		// time we write a report, we move the retention period forward in time by one report interval. This
		// results in the deletion of the oldest report.
		It("should delete a single old report", func() {
			fakeRuntimeClient.seedReportFrom(0 * time.Second)
			fakeRuntimeClient.seedReportFrom(1 * time.Second)
			fakeRuntimeClient.seedReportFrom(2 * time.Second)
			fakeRuntimeClient.seedReportFrom(3 * time.Second)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.getRequestCount("delete")).To(Equal(1))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(2))
		})

		// The following cases are not expected in real operation, but we verify the expected behaviour regardless.
		It("should delete multiple old reports", func() {
			fakeRuntimeClient.seedReportFrom(0 * time.Second)
			fakeRuntimeClient.seedReportFrom(6 * time.Second)
			fakeRuntimeClient.seedReportFrom(7 * time.Second)
			fakeRuntimeClient.seedReportFrom(8 * time.Second)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.getRequestCount("delete")).To(Equal(3))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(2))
		})
		It("should delete all reports if they are all old", func() {
			fakeRuntimeClient.seedReportFrom(6 * time.Second)
			fakeRuntimeClient.seedReportFrom(7 * time.Second)
			fakeRuntimeClient.seedReportFrom(8 * time.Second)
			writer := reportWriterForTest(fakeRuntimeClient)

			err := writer.removeOldDatastoreReports()
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeRuntimeClient.getRequestCount("list")).To(Equal(1))
			Expect(fakeRuntimeClient.getRequestCount("delete")).To(Equal(3))
			Expect(fakeRuntimeClient.numberOfMethodsCalled()).To(Equal(2))
		})
		It("should delete old reports even if the creation of a new report fails", func() {
			// Set up the creation to fail, and setup 1 old report.
			fakeRuntimeClient.setError(errors.NewBadRequest("you know what you did wrong"))
			fakeRuntimeClient.seedReportFrom(3 * time.Second)
			writer := reportWriterForTest(fakeRuntimeClient)

			// Write a report to the go routine.
			report := basicLicenseUsageReport{
				intervalStart: time.Now(),
				intervalEnd:   time.Now(),
				minCounts: counts{
					vCPU:  1,
					nodes: 1,
				},
				maxCounts: counts{
					vCPU:  2,
					nodes: 2,
				},
				complete: true,
			}
			go writer.startWriting()
			writer.reports <- report

			// Verify that both creation and deletion were attempted.
			Eventually(fakeRuntimeClient.getRequestCount).WithArguments("create").WithTimeout(5 * time.Second).Should(Equal(1))
			Eventually(fakeRuntimeClient.getRequestCount).WithArguments("delete").WithTimeout(5 * time.Second).Should(Equal(1))
		})
	})

	Context("incomplete reports", func() {
		var writer reportWriter
		BeforeEach(func() {
			writer = reportWriterForTest(fakeRuntimeClient)
			go writer.startWriting()
		})

		BeforeEach(func() {
			// There should be no errors from the client in this test.
			fakeRuntimeClient.resolveImmediately("list")
			fakeRuntimeClient.resolveImmediately("delete")
			fakeRuntimeClient.resolveImmediately("create")
		})

		It("should write incomplete reports", func() {
			report := basicLicenseUsageReport{
				minCounts: counts{
					vCPU:  1,
					nodes: 1,
				},
				maxCounts: counts{
					vCPU:  2,
					nodes: 2,
				},
				complete: true,
			}

			// Verify that the report writes to the datastore when it's complete.
			writer.reports <- report
			Eventually(fakeRuntimeClient.getRequestCount).WithArguments("create").WithTimeout(5 * time.Second).Should(Equal(1))

			// Verify that the report also writes to the datastore when it's incomplete.
			fakeRuntimeClient.clearRequestCounts()
			report.complete = false
			writer.reports <- report
			Eventually(fakeRuntimeClient.getRequestCount).WithArguments("create").WithTimeout(5 * time.Second).Should(Equal(1))
		})
	})
})
