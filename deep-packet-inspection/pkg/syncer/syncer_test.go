// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package syncer_test

import (
	"context"
	"fmt"
	"os"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/deep-packet-inspection/pkg/dispatcher"
	"github.com/projectcalico/calico/deep-packet-inspection/pkg/syncer"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	k8sresources "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dpisyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/pkg/buildinfo"
	"github.com/projectcalico/calico/typha/pkg/syncclientutils"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

var _ = Describe("Syncer", func() {
	var ctx context.Context
	nodename := "127.0.0.1"
	healthCh := make(chan bool)
	var cfg apiconfig.CalicoAPIConfig
	var calicoClient clientv3.Interface
	var k8sClientset *kubernetes.Clientset
	namespace := "test-dpi"
	name1 := "test-dpi-1"
	name2 := "test-dpi-2"

	BeforeEach(func() {
		ctx = context.Background()
		cfg = apiconfig.CalicoAPIConfig{
			Spec: apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.Kubernetes,
				KubeConfig: apiconfig.KubeConfig{
					Kubeconfig: os.Getenv("KUBECONFIG"),
				},
			},
		}

		// Create the backend client to obtain a syncerCallbacks interface.
		k8sBackend, err := backend.NewClient(cfg)
		Expect(err).NotTo(HaveOccurred())
		k8sClientset = k8sBackend.(*k8s.KubeClient).ClientSet
		_ = k8sBackend.Clean()

		// Remove the test namespace
		_ = k8sClientset.CoreV1().Pods(namespace).Delete(ctx, "pod1", metav1.DeleteOptions{})
		_ = k8sClientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})

		// setup
		ns := k8sapi.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespace,
			},
		}
		_, err = k8sClientset.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{})
		Expect(err).ShouldNot(HaveOccurred())

		sa := k8sapi.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
		}
		_, err = k8sClientset.CoreV1().ServiceAccounts(namespace).Create(ctx, &sa, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = k8sClientset.CoreV1().Pods(namespace).Create(ctx, &k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
			Spec: k8sapi.PodSpec{
				NodeName: nodename,
				Containers: []k8sapi.Container{
					{
						Name:  "container1",
						Image: "test",
					},
				},
			},
		},
			metav1.CreateOptions{})
		Expect(err).ShouldNot(HaveOccurred())

		_, err = k8sClientset.CoreV1().Pods(namespace).Create(ctx, &k8sapi.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "pod2"},
			Spec: k8sapi.PodSpec{
				NodeName: nodename,
				Containers: []k8sapi.Container{
					{
						Name:  "container2",
						Image: "test",
					},
				},
			},
		},
			metav1.CreateOptions{})
		Expect(err).ShouldNot(HaveOccurred())

		// Create a client.
		calicoClient, err = clientv3.New(cfg)
		Expect(err).ShouldNot(HaveOccurred())
	})

	AfterEach(func() {
		// Remove the test namespace
		_ = k8sClientset.CoreV1().Pods(namespace).Delete(ctx, "pod1", metav1.DeleteOptions{})
		_ = k8sClientset.CoreV1().Pods(namespace).Delete(ctx, "pod2", metav1.DeleteOptions{})
		_ = k8sClientset.CoreV1().Namespaces().Delete(ctx, namespace, metav1.DeleteOptions{})
	})

	It("syncs all resources created before and after the syncerCallbacks started", func() {
		ctx1, cancelFn := context.WithCancel(ctx)
		mockDispatcher := &dispatcher.MockDispatcher{}

		go func() {
			for {
				select {
				case <-healthCh:
				case <-ctx1.Done():
					return
				}
			}
		}()

		By("creating WEP before starting syncerCallbacks")
		ctxPatchCNI := k8sresources.ContextWithPatchMode(ctx1, k8sresources.PatchModeCNI)
		_, err := calicoClient.WorkloadEndpoints().Create(ctxPatchCNI, &internalapi.WorkloadEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: fmt.Sprintf("%s-k8s-pod1-eth0", nodename)},
			Spec: internalapi.WorkloadEndpointSpec{
				Orchestrator:  "k8s",
				Node:          nodename,
				ContainerID:   "container1",
				Pod:           "pod1",
				Endpoint:      "eth0",
				IPNetworks:    []string{"10.100.10.1"},
				Profiles:      []string{"this-profile", "that-profile"},
				InterfaceName: "cali01235",
			},
		}, options.SetOptions{})
		Expect(err).ShouldNot(HaveOccurred())

		By("creating DPI resource before starting syncerCallbacks")
		_, err = calicoClient.DeepPacketInspections().Create(
			ctx1,
			&v3.DeepPacketInspection{
				ObjectMeta: metav1.ObjectMeta{Name: name1, Namespace: namespace},
				Spec:       v3.DeepPacketInspectionSpec{Selector: "k8s-app=='dpi'"},
			},
			options.SetOptions{},
		)
		Expect(err).ShouldNot(HaveOccurred())

		// allReceived accumulates all CacheRequests across dispatches, since
		// the syncer may batch them differently depending on timing.
		var mu sync.Mutex
		var allReceived []dispatcher.CacheRequest
		mockDispatcher.On("Dispatch", ctx1, mock.Anything).Return().Run(
			func(args mock.Arguments) {
				defer GinkgoRecover()
				cacheReq := args.Get(1).([]dispatcher.CacheRequest)
				mu.Lock()
				allReceived = append(allReceived, cacheReq...)
				mu.Unlock()
			})

		dpiKey1 := model.KeyFromDefaultPath(fmt.Sprintf("/calico/resources/v3/projectcalico.org/deeppacketinspections/%s/%s", namespace, name1))
		dpiKey2 := model.KeyFromDefaultPath(fmt.Sprintf("/calico/resources/v3/projectcalico.org/deeppacketinspections/%s/%s", namespace, name2))
		wepKey1 := model.WorkloadEndpointKey{
			Hostname:       "127.0.0.1",
			OrchestratorID: "k8s",
			WorkloadID:     "test-dpi/pod1",
			EndpointID:     "eth0",
		}
		wepKey2 := model.WorkloadEndpointKey{
			Hostname:       "127.0.0.1",
			OrchestratorID: "k8s",
			WorkloadID:     "test-dpi/pod2",
			EndpointID:     "eth0",
		}

		// Helper to find received entries matching a key and update type.
		findReceived := func(key model.Key, updateType bapi.UpdateType) []dispatcher.CacheRequest {
			mu.Lock()
			defer mu.Unlock()
			var matched []dispatcher.CacheRequest
			for _, r := range allReceived {
				if r.KVPair.Key == key && r.UpdateType == updateType {
					matched = append(matched, r)
				}
			}
			return matched
		}

		receivedLen := func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(allReceived)
		}

		s := syncer.NewSyncerCallbacks(healthCh)
		typhaConfig := syncclientutils.ReadTyphaConfig([]string{"DPI_"})
		if syncclientutils.MustStartSyncerClientIfTyphaConfigured(
			&typhaConfig, syncproto.SyncerTypeDPI,
			buildinfo.Version, nodename, fmt.Sprintf("dpi %s", buildinfo.Version),
			s,
		) {
		} else {
			syncerClient := dpisyncer.New(calicoClient.(backendClientAccessor).Backend(), s)
			syncerClient.Start()
			defer syncerClient.Stop()
		}
		go s.Sync(ctx1, mockDispatcher)

		By("checking initial sync delivers DPI and WEP")
		Eventually(receivedLen).Should(BeNumerically(">=", 2))
		Expect(findReceived(dpiKey1, bapi.UpdateTypeKVNew)).To(HaveLen(1))
		Expect(findReceived(wepKey1, bapi.UpdateTypeKVNew)).To(HaveLen(1))

		By("creating WEP and checking updates are received by dispatcher")
		_, err = calicoClient.WorkloadEndpoints().Create(ctxPatchCNI, &internalapi.WorkloadEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: fmt.Sprintf("%s-k8s-pod2-eth0", nodename)},
			Spec: internalapi.WorkloadEndpointSpec{
				Orchestrator:  "k8s",
				Node:          nodename,
				ContainerID:   "container2",
				Pod:           "pod2",
				Endpoint:      "eth0",
				IPNetworks:    []string{"10.100.10.1"},
				Profiles:      []string{"this-profile", "that-profile"},
				InterfaceName: "cali01234",
			},
		}, options.SetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return len(findReceived(wepKey2, bapi.UpdateTypeKVNew)) }).Should(Equal(1))

		By("creating DPI and checking updates are received by syncerCallbacks")
		dpi, err := calicoClient.DeepPacketInspections().Create(
			ctx1,
			&v3.DeepPacketInspection{
				ObjectMeta: metav1.ObjectMeta{Name: name2, Namespace: namespace},
				Spec:       v3.DeepPacketInspectionSpec{Selector: "k8s-app=='dpi'"},
			},
			options.SetOptions{},
		)
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return len(findReceived(dpiKey2, bapi.UpdateTypeKVNew)) }).Should(Equal(1))

		By("creating WEP for non-local node and checking updates are not sent to syncerCallbacks")
		prevLen := receivedLen()
		tempNode := "tempnode"
		_, err = calicoClient.WorkloadEndpoints().Create(ctxPatchCNI, &internalapi.WorkloadEndpoint{
			ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: fmt.Sprintf("%s-k8s-pod1-eth0", tempNode)},
			Spec: internalapi.WorkloadEndpointSpec{
				Orchestrator:  "k8s",
				Node:          tempNode,
				ContainerID:   "container1",
				Pod:           "pod1",
				Endpoint:      "eth0",
				IPNetworks:    []string{"10.100.10.1"},
				Profiles:      []string{"this-profile", "that-profile"},
				InterfaceName: "cali01234",
			},
		}, options.SetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Consistently(receivedLen).Should(Equal(prevLen))

		By("updating DPI and checking updates are received by syncerCallbacks")
		_, err = calicoClient.DeepPacketInspections().Update(
			ctx1,
			&v3.DeepPacketInspection{
				ObjectMeta: dpi.ObjectMeta,
				Spec:       v3.DeepPacketInspectionSpec{Selector: "k8s=='dpi'"},
			},
			options.SetOptions{},
		)
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return len(findReceived(dpiKey2, bapi.UpdateTypeKVUpdated)) }).Should(Equal(1))

		By("deleting WEP & DPI resource and checking updates are received by dispatcher")
		_, err = calicoClient.WorkloadEndpoints().Delete(ctx1, namespace, fmt.Sprintf("%s-k8s-pod1-eth0", nodename), options.DeleteOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return len(findReceived(wepKey1, bapi.UpdateTypeKVDeleted)) }).Should(Equal(1))

		_, err = calicoClient.DeepPacketInspections().Delete(ctx1, namespace, name1, options.DeleteOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return len(findReceived(dpiKey1, bapi.UpdateTypeKVDeleted)) }).Should(Equal(1))

		_, err = calicoClient.WorkloadEndpoints().Delete(ctx1, namespace, fmt.Sprintf("%s-k8s-pod2-eth0", nodename), options.DeleteOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return len(findReceived(wepKey2, bapi.UpdateTypeKVDeleted)) }).Should(Equal(1))

		_, err = calicoClient.DeepPacketInspections().Delete(ctx1, namespace, name2, options.DeleteOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Eventually(func() int { return len(findReceived(dpiKey2, bapi.UpdateTypeKVDeleted)) }).Should(Equal(1))

		mockDispatcher.On("Close").Return()
		// StopGeneratingEventsForWEP the syncerCallbacks by cancelling the context
		cancelFn()
	})
})

// backendClientAccessor is an interface to access the backend client from the main v2 client.
type backendClientAccessor interface {
	Backend() bapi.Client
}
