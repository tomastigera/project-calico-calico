// Copyright (c) 2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dpisyncer_test

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	k8sapi "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	internalapi "github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dpisyncer"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("DPI syncer tests", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	Describe("DPI syncer functionality", func() {
		ctx := context.Background()
		var err error
		var v3Client clientv3.Interface
		var k8sBackend api.Client
		var k8sClientset *kubernetes.Clientset
		var syncer api.Syncer
		var syncTester *testutils.SyncerTester

		namespace := "test-ns"
		dpiName1 := "test-dpi1"
		dpiName2 := "test-dpi2"
		dpiPath := func(name string) string {
			return fmt.Sprintf("/calico/resources/v3/projectcalico.org/deeppacketinspections/%s/%s", namespace, name)
		}

		BeforeEach(func() {
			// Create a v3 client to drive data changes (luckily because this is the _test module,
			// we don't get circular imports.
			v3Client, err = clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			// Create the backend client to obtain a syncer interface.
			k8sBackend, err = backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			k8sClientset = k8sBackend.(*k8s.KubeClient).ClientSet
			k8sBackend.Clean()

			// Remove the test namespace
			testutils.DeleteNamespace(k8sClientset, namespace)

			syncTester = testutils.NewSyncerTester()
			syncer = dpisyncer.New(k8sBackend, syncTester)
		})

		AfterEach(func() {
			// Remove the test namespace
			testutils.DeleteNamespace(k8sClientset, namespace)
			syncTester.ExpectCacheSize(0)
			if syncer != nil {
				syncer.Stop()
			}
		})

		It("should sync and receive all current data", func() {

			syncer.Start()
			expectedCacheSize := 0

			By("Checking status is updated to sync'd at start of day")
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectStatusUpdate(api.InSync)
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Creating DeepPacketInspection resource")
			ns := k8sapi.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			dpiObj := func(name string) *apiv3.DeepPacketInspection {
				return &apiv3.DeepPacketInspection{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
					Spec:       apiv3.DeepPacketInspectionSpec{Selector: "k8s-app=='dpi'"},
				}
			}
			_, err := k8sClientset.CoreV1().Namespaces().Create(ctx, &ns, metav1.CreateOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			dpi, err := v3Client.DeepPacketInspections().Create(
				ctx,
				dpiObj(dpiName1),
				options.SetOptions{},
			)

			Expect(err).ShouldNot(HaveOccurred())
			expectedCacheSize += 1
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath(dpiPath(dpiName1))

			By("Creating WorkloadEndpoint resource")
			_, err = k8sClientset.CoreV1().Pods(namespace).Create(ctx, &k8sapi.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "pod1"},
				Spec: k8sapi.PodSpec{
					NodeName: "node1",
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

			wepObj := &internalapi.WorkloadEndpoint{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "node1-k8s-pod1-eth0"},
				Spec: internalapi.WorkloadEndpointSpec{
					Orchestrator:  "k8s",
					Node:          "node1",
					ContainerID:   "container1",
					Pod:           "pod1",
					Endpoint:      "eth0",
					IPNetworks:    []string{"10.100.10.1"},
					Profiles:      []string{"this-profile", "that-profile"},
					InterfaceName: "cali01234",
				},
			}
			ctxCNI := resources.ContextWithPatchMode(ctx, resources.PatchModeCNI)
			_, err = v3Client.WorkloadEndpoints().Create(ctxCNI, wepObj, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			expectedCacheSize += 1

			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath("/calico/v1/host/node1/workload/k8s/test-ns%2fpod1/endpoint/eth0")
			wepRes := syncTester.GetCacheValue("/calico/v1/host/node1/workload/k8s/test-ns%2fpod1/endpoint/eth0")
			modelWep, ok := wepRes.(*model.WorkloadEndpoint)
			Expect(ok).Should(BeTrue())
			Expect(modelWep.Name).ShouldNot(BeEmpty())

			By("Updating DeepPacketInspection resource")
			selector := "k8s-app=='new-dpi'"
			dpi.Spec = apiv3.DeepPacketInspectionSpec{Selector: selector}
			dpi, err = v3Client.DeepPacketInspections().Update(ctx, dpi, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath(dpiPath(dpiName1))
			resDpi := syncTester.GetCacheValue(dpiPath(dpiName1))
			dpi, ok = resDpi.(*apiv3.DeepPacketInspection)
			Expect(ok).Should(BeTrue())
			Expect(dpi.Spec.Selector).Should(Equal(selector))

			By("Updating DeepPacketInspection status sub-resource")
			status := apiv3.DeepPacketInspectionStatus{Nodes: []apiv3.DPINode{
				{
					Node:            "node1",
					Active:          apiv3.DPIActive{Success: true},
					ErrorConditions: []apiv3.DPIErrorCondition{{Message: "error in dpi"}},
				},
				{
					Node:   "node2",
					Active: apiv3.DPIActive{Success: false},
				},
			}}
			dpi.Status = status
			dpi, err = v3Client.DeepPacketInspections().UpdateStatus(ctx, dpi, options.SetOptions{})
			Expect(err).ShouldNot(HaveOccurred())

			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath(dpiPath(dpiName1))
			resDpi = syncTester.GetCacheValue(dpiPath(dpiName1))
			dpi, ok = resDpi.(*apiv3.DeepPacketInspection)
			Expect(ok).Should(BeTrue())
			Expect(dpi.Status.Nodes).ShouldNot(BeNil())
			Expect(len(dpi.Status.Nodes)).Should(Equal(2))
			Expect(dpi.Status.Nodes).Should(BeEquivalentTo(status.Nodes))

			By("Creating multiple DeepPacketInspection resource")
			dpi, err = v3Client.DeepPacketInspections().Create(
				ctx,
				dpiObj(dpiName2),
				options.SetOptions{},
			)

			Expect(err).ShouldNot(HaveOccurred())
			expectedCacheSize += 1
			syncTester.ExpectCacheSize(expectedCacheSize)
			syncTester.ExpectPath(dpiPath(dpiName2))

			By("Deleting the DeepPacketInspection resource")
			_, err = v3Client.DeepPacketInspections().Delete(ctx, namespace, dpiName1, options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			expectedCacheSize -= 1
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Starting a new syncer and verifying that all current entries are returned before sync status")
			// We need to create a new syncTester and syncer.
			current := syncTester.GetCacheEntries()
			syncTester = testutils.NewSyncerTester()
			syncer = dpisyncer.New(k8sBackend, syncTester)
			syncer.Start()

			// Verify the data is the same as the data from the previous cache.
			syncTester.ExpectStatusUpdate(api.WaitForDatastore)
			syncTester.ExpectStatusUpdate(api.ResyncInProgress)
			syncTester.ExpectCacheSize(expectedCacheSize)
			for _, e := range current {
				syncTester.ExpectData(e)
			}
			syncTester.ExpectStatusUpdate(api.InSync)

			By("Deleting the WorkloadEndpoint resource")
			_, err = v3Client.WorkloadEndpoints().Delete(ctx, namespace, "node1-k8s-pod1-eth0", options.DeleteOptions{})
			Expect(err).ShouldNot(HaveOccurred())
			expectedCacheSize -= 1
			syncTester.ExpectCacheSize(expectedCacheSize)

			By("Deleting the underlying Pod resource")
			var zero int64
			policy := metav1.DeletePropagationBackground
			err = k8sClientset.CoreV1().Pods(namespace).Delete(ctx, "pod1", metav1.DeleteOptions{
				GracePeriodSeconds: &zero,
				PropagationPolicy:  &policy,
			})
			Expect(err).ShouldNot(HaveOccurred())
			syncTester.ExpectCacheSize(expectedCacheSize)
		})
	})
})
