package usage

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	k8sFake "k8s.io/client-go/kubernetes/fake"
	runtimeFake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These UTs are responsible for ensuring that the usageController responds correctly to stop channel closure.
// Validation of the controllers pipeline and report writing is handled by the FVs, and in-depth testing of report
// generation is handled by the reportGenerator UTs.
var _ = Describe("Usage Controller UTs", func() {
	It("should cease operations when stop is issued", func() {
		// Fake kubernetes client with no objects associated with it.
		fakeClientSet := k8sFake.NewClientset()

		// Fake calico client that will only respond to License GET with a 404.
		fakeCalicoClient := fakeCalicoClient{}

		// Fake runtime client with no objects associated with it.
		fakeRuntimeClient := runtimeFake.NewClientBuilder().WithScheme(createScheme()).Build()

		// And finally, fake informers.
		fakeNodeInformer := &fakerInformer{}
		fakePodInformer := &fakerInformer{}

		controller := usageController{
			ctx:                context.Background(),
			k8sClient:          fakeClientSet,
			calicoClient:       fakeCalicoClient,
			usageClient:        fakeRuntimeClient,
			nodeInformer:       fakeNodeInformer,
			podInformer:        fakePodInformer,
			usageReportsPerDay: reportsPerDay,
		}

		// Start the controller and let it run for 5 report cycles.
		stopCh := make(chan struct{})
		go controller.Run(stopCh)
		time.Sleep(secondsBetweenUsageReports * 5)

		// Stop: we expect to be informed via a channel close rather than a value.
		close(stopCh)

		// Validate that nothing is receiving values on the reporter input channels.
		assertChannelNotReceiving[event[*v1.Node]](controller.reporter.nodeUpdates, event[*v1.Node]{})
		assertChannelNotReceiving[event[*v1.Pod]](controller.reporter.podUpdates, event[*v1.Pod]{})
		assertChannelNotReceiving[bool](controller.reporter.initialSyncComplete, true)
		assertChannelNotReceiving[bool](controller.reporter.intervalComplete, true)

		// Validate that nothing is receiving on the writer input channel
		assertChannelNotReceiving[basicLicenseUsageReport](controller.writer.reports, basicLicenseUsageReport{})
	})
})

func assertChannelNotReceiving[T any](ch chan T, dummyValue T) {
	Consistently(func() error {
		select {
		case ch <- dummyValue:
			return fmt.Errorf("expected channel to not have a receiver, but it did")
		default:
			return nil
		}
	}).WithTimeout(5 * time.Second).Should(Not(HaveOccurred()))
}
