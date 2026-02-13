package usage

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	usagev1 "github.com/tigera/api/pkg/apis/usage.tigera.io/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	runtimeClient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	licenseClient "github.com/projectcalico/calico/licensing/client"
	"github.com/projectcalico/calico/licensing/utils"
)

const (
	secondsBetweenUsageReports = 4
	secondsPerDay              = 60 * 60 * 24
	reportsPerDay              = secondsPerDay / secondsBetweenUsageReports
	reportsPerTest             = 3
	secondsToRetainReports     = secondsBetweenUsageReports * reportsPerTest
)

// These FVs are responsible for ensuring that the following is under test:
// - usageController: whether it constructs its pipeline correctly and that the pipeline functions against a real datastore
// - reportWriter: whether it enriches basic reports properly for different values of license presence, last report UID, and uptime
// These FVs are _NOT_ responsible for the following being under test - they are handled by UTs:
// - reportGenerator: whether basic reports are generated correctly in all conceivable permutations of input events
// - reportWriter: whether retries of report writing are performed correctly, and that incomplete reports are not written to the datastore.
// - usageController: whether it handles stop channel sends correctly
var _ = Describe("Calico usage controller FV tests (KDD mode)", func() {
	var (
		etcd              *containers.Container
		controller        *containers.Container
		apiserver         *containers.Container
		usageClient       runtimeClient.Client
		calicoClient      clientv3.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		ctx               context.Context
		cancel            context.CancelFunc
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file.
		var err error
		kconfigfile, cancel := testutils.BuildKubeconfig(apiserver.IP)
		defer cancel()

		// Create the k8s client from the kubeconfig file.
		k8sClient, err = testutils.GetK8sClient(kconfigfile)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Apply CRDs.
		testutils.ApplyCRDs(apiserver)

		// Make a Calico client.
		calicoClient = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile)

		// Make a usage client.
		config, err := clientcmd.BuildConfigFromFlags("", kconfigfile)
		Expect(err).NotTo(HaveOccurred())
		usageClient, err = createUsageClient(ctx, config)
		Expect(err).NotTo(HaveOccurred())

		// Create namespace and service account for calico-node pods created with each node.
		_, err = k8sClient.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "calico-system"},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = k8sClient.CoreV1().ServiceAccounts("calico-system").Create(
			context.Background(),
			&v1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "default",
					Namespace: "calico-system",
				},
			},
			metav1.CreateOptions{},
		)
		Expect(err).NotTo(HaveOccurred())

		// Create two nodes and their calico-node pods.
		createNode(ctx, "node-a", "10", k8sClient)
		createNode(ctx, "node-b", "20", k8sClient)

		// Run the usage controller.
		controller = runUsageControllerForFV(apiconfig.Kubernetes, kconfigfile, reportsPerDay, secondsToRetainReports)

		// Run controller manager.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		_ = calicoClient.Close()
		controllerManager.Stop()
		controller.Stop()
		apiserver.Stop()
		etcd.Stop()
		cancel()
	})

	Context("Mainline FV tests", func() {
		for _, loopLicensePresent := range []bool{true, false} {
			licensePresent := loopLicensePresent
			It(fmt.Sprintf("should write usage reports according to the configured reports per day (license present: %v)", licensePresent), func() {
				// Create a license if required.
				var licenseClaims licenseClient.LicenseClaims
				if licensePresent {
					var err error
					licenseKey := utils.ValidEnterpriseTestLicense()
					licenseClaims, err = licenseClient.Decode(*licenseKey)
					Expect(err).NotTo(HaveOccurred())
					_, err = calicoClient.LicenseKey().Create(ctx, licenseKey, options.SetOptions{})
					Expect(err).NotTo(HaveOccurred())
				}

				// Get the list of reports, waiting until the expected amount of reports have been flushed.
				var usageReportList usagev1.LicenseUsageReportList
				getUsageReports := func() []usagev1.LicenseUsageReport {
					// Populate the list.
					err := usageClient.List(ctx, &usageReportList)
					Expect(err).NotTo(HaveOccurred())

					// Sort the list by time ascending.
					slices.SortFunc(usageReportList.Items, func(a, b usagev1.LicenseUsageReport) int {
						return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
					})

					return usageReportList.Items
				}
				timeout := fmt.Sprintf("%ds", reportsPerTest*secondsBetweenUsageReports*2)
				Eventually(getUsageReports, timeout, "1s").Should(HaveLen(reportsPerTest))

				// Get the kube-system namespace for report validation.
				ksNamespace, err := k8sClient.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())

				reportDatas := convertToTypedReportData(usageReportList.Items)
				for _, report := range reportDatas {
					// Ensure the report is complete.
					Expect(report.CompleteReport).To(BeTrue())

					// Validate interval start/end values.
					intervalLength := report.IntervalEnd.Sub(report.IntervalStart).Seconds()
					Expect(intervalLength).To(BeNumerically("~", secondsBetweenUsageReports, 0.01))

					// Validate subject UID.
					Expect(report.SubjectUID).To(Equal(string(ksNamespace.UID)))

					// Validate license UID.
					Expect(report.LicenseUID).To(Equal(licenseClaims.LicenseID))

					// Validate counts. Min and max should be the same as nodes were static.
					Expect(report.VCPUs).To(Equal(Stats{Min: 30, Max: 30}))
					Expect(report.Nodes).To(Equal(Stats{Min: 2, Max: 2}))
				}

				// Validate reporter uptime values: the first reports value should be something greater than zero, and the seconds should be roughly the time between reports.
				Expect(reportDatas[0].ReporterUptime).To(BeNumerically(">", 0))
				Expect(reportDatas[1].ReporterUptime - reportDatas[0].ReporterUptime).To(BeNumerically("~", secondsBetweenUsageReports, 1))

				// Validate last published report UID values.
				Expect(reportDatas[0].LastPublishedReportUID).To(BeEmpty())
				Expect(reportDatas[1].LastPublishedReportUID).To(Equal(string(usageReportList.Items[0].UID)))

				// Ensure the HMAC can be validated on read-back.
				for _, datastoreReport := range usageReportList.Items {
					computedHMAC := ComputeHMAC(datastoreReport.Spec.ReportData)
					Expect(computedHMAC).To(Equal(datastoreReport.Spec.HMAC))
				}

				// Delete a node.
				deleteNode(ctx, "node-a", k8sClient)

				// Validate that we see the drop in the report.
				Eventually(func() Stats {
					getUsageReports()
					reportDatas = convertToTypedReportData(usageReportList.Items)
					Expect(len(reportDatas)).To(BeNumerically(">", 0))
					return reportDatas[len(reportDatas)-1].Nodes
				}).WithTimeout(2 * secondsBetweenUsageReports * time.Second).Should(Equal(Stats{Min: 1, Max: 2}))

				// Add two nodes.
				createNode(ctx, "node-c", "10", k8sClient)
				createNode(ctx, "node-d", "10", k8sClient)

				// Validate that we see the increase in the report.
				Eventually(func() Stats {
					getUsageReports()
					reportDatas = convertToTypedReportData(usageReportList.Items)
					Expect(len(reportDatas)).To(BeNumerically(">", 0))
					return reportDatas[len(reportDatas)-1].Nodes
				}).WithTimeout(2 * secondsBetweenUsageReports * time.Second).Should(Equal(Stats{Min: 1, Max: 3}))

				// Validate (for multiple flushes) that report cleanup occurs after each flush
				oldReportIDSet, oldestReportID := getReportIDSetAndOldestReportID(reportDatas)
				for i := 0; i < 5; i++ {
					var newReportIDSet map[string]bool
					var oldestReportIDInNewSet string
					// The retention period is set such that we should expect a report to be deleted every time a
					// report is generated, meaning that we should expect to see a steady-state report count of
					// `reportsPerTest` for each interval. We wait for `secondsBetweenUsageReports` (with a bit of
					// grace) for this steady-state to manifest.
					Eventually(func() bool {
						err := usageClient.List(ctx, &usageReportList)
						Expect(err).NotTo(HaveOccurred())
						newReportDatas := convertToTypedReportData(usageReportList.Items)
						newReportIDSet, oldestReportIDInNewSet = getReportIDSetAndOldestReportID(newReportDatas)
						// Verify that we see the expected number of reports, and that
						return len(newReportIDSet) == reportsPerTest && !reflect.DeepEqual(newReportIDSet, oldReportIDSet)
					}).WithTimeout(secondsBetweenUsageReports * time.Duration(float64(time.Second)*1.5))

					// Once we've reached the expected steady-state, verify that the oldest report is no longer present.
					Expect(oldestReportID).NotTo(BeKeyOf(newReportIDSet))
					oldestReportID = oldestReportIDInNewSet
					oldReportIDSet = newReportIDSet
				}
			})
		}
	})
})

// createNode creates a node and a calico-node pod that runs on it.
func createNode(ctx context.Context, nodeName string, nodeVCPU string, k8sClient *kubernetes.Clientset) {
	_, err := k8sClient.CoreV1().Nodes().Create(ctx,
		&v1.Node{
			TypeMeta:   metav1.TypeMeta{Kind: "Node", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: nodeName, UID: types.UID(uuid.NewString())},
			Spec:       v1.NodeSpec{},
			Status: v1.NodeStatus{
				Capacity: v1.ResourceList{
					v1.ResourceCPU: resource.MustParse(nodeVCPU),
				},
			},
		},
		metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = k8sClient.CoreV1().Pods("calico-system").Create(ctx, &v1.Pod{
		TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID(uuid.NewString()),
			Name: fmt.Sprintf("calico-%s", nodeName),
			Labels: map[string]string{
				"app.kubernetes.io/name": "calico-node",
			},
		}, Spec: v1.PodSpec{
			NodeName: nodeName,
			Containers: []v1.Container{
				{
					Name:    "container1",
					Image:   "busybox",
					Command: []string{"sleep", "3600"},
				},
			},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func deleteNode(ctx context.Context, nodeName string, k8sClient *kubernetes.Clientset) {
	err := k8sClient.CoreV1().Pods("calico-system").Delete(ctx, fmt.Sprintf("calico-%s", nodeName), metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
	err = k8sClient.CoreV1().Nodes().Delete(ctx, nodeName, metav1.DeleteOptions{})
	Expect(err).NotTo(HaveOccurred())
}

// getReportIDSetAndOldestReportID returns a set of report IDs from the provided reports, along with the ID of the oldest report.
func getReportIDSetAndOldestReportID(reports []LicenseUsageReportData) (map[string]bool, string) {
	idSet := map[string]bool{}
	oldestReport := LicenseUsageReportData{IntervalStart: time.Now()}
	for _, report := range reports {
		idSet[getReportIDForTest(report)] = true

		// Update the oldest report.
		if report.IntervalEnd.Before(oldestReport.IntervalStart) {
			oldestReport = report
		}
	}
	return idSet, getReportIDForTest(oldestReport)
}

// getReportIDForTest creates a deterministic ID for a report based on the LicenseUsageReportData, i.e. when the datastore UID is not known.
func getReportIDForTest(report LicenseUsageReportData) string {
	return fmt.Sprintf("%v-%v", report.IntervalStart.Unix(), report.IntervalEnd.Unix())
}

func runUsageControllerForFV(datastoreType apiconfig.DatastoreType, kconfigfile string, reportsPerDay int, retentionPeriodSeconds int) *containers.Container {
	return containers.Run("calico-kube-controllers",
		containers.RunOpts{AutoRemove: true},
		"-e", fmt.Sprintf("DATASTORE_TYPE=%s", datastoreType),
		"-e", fmt.Sprintf("KUBECONFIG=%s", kconfigfile),
		"-v", fmt.Sprintf("%s:%s", kconfigfile, kconfigfile),
		"-e", fmt.Sprintf("USAGE_REPORTS_PER_DAY=%d", reportsPerDay),
		"-e", fmt.Sprintf("USAGE_REPORT_RETENTION_PERIOD=%ds", retentionPeriodSeconds),
		"-e", "ENABLED_CONTROLLERS=node,service,federatedservices,usage",
		"-e", "LOG_LEVEL=debug",
		"-e", "KUBE_CONTROLLERS_CONFIG_NAME=default",
		os.Getenv("CONTAINER_NAME"))
}

func convertToTypedReportData(datastoreReports []usagev1.LicenseUsageReport) (reportDatas []LicenseUsageReportData) {
	for _, datastoreReport := range datastoreReports {
		reportData, err := NewLicenseUsageReportDataFromMessage(datastoreReport.Spec.ReportData)
		Expect(err).NotTo(HaveOccurred())
		reportDatas = append(reportDatas, reportData)
	}
	return
}
