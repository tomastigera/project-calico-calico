// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package nonclusterhost

import (
	"context"
	"fmt"
	"os"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	fakecalico "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/testing"

	"github.com/projectcalico/calico/libcalico-go/lib/names"
)

var _ = Describe("NonClusterHost Custom Resource Tests", func() {
	var (
		ctx              context.Context
		fakeCalicoClient *fakecalico.Clientset
		hostname         string
	)

	BeforeEach(func() {
		ctx = context.TODO()
		fakeCalicoClient = fakecalico.NewSimpleClientset()
		Expect(fakeCalicoClient).NotTo(BeNil())

		var err error
		hostname, err = names.Hostname()
		Expect(err).NotTo(HaveOccurred())

		heps := []v3.HostEndpoint{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("%s-eth0", hostname),
				},
				Spec: v3.HostEndpointSpec{
					Node:          hostname,
					InterfaceName: "eth0",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: fmt.Sprintf("%s-eth1", hostname),
					Labels: map[string]string{
						"hostendpoint.projectcalico.org/type": "some-type",
						"kubernetes.io/arch":                  "some-arch",
						"kubernetes.io/hostname":              "some-hostname",
						"kubernetes.io/os":                    "some-os",
					},
				},
				Spec: v3.HostEndpointSpec{
					Node:          hostname,
					InterfaceName: "eth1",
				},
			},
		}

		for _, hep := range heps {
			_, err := fakeCalicoClient.ProjectcalicoV3().HostEndpoints().Create(ctx, &hep, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())
		}
	})

	It("should update HostEndpoint labels", func() {
		lu := &LabelUpdater{
			ctx:             ctx,
			calicoClientSet: fakeCalicoClient,
		}

		err := lu.UpdateLabels()
		Expect(err).NotTo(HaveOccurred())

		heps, err := fakeCalicoClient.ProjectcalicoV3().HostEndpoints().List(ctx, metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())

		for _, hep := range heps.Items {
			Expect(hep.Labels).To(HaveLen(4))
			Expect(hep.Labels).To(HaveKeyWithValue("hostendpoint.projectcalico.org/type", "nonclusterhost"))
			Expect(hep.Labels).To(HaveKeyWithValue("kubernetes.io/arch", runtime.GOARCH))
			Expect(hep.Labels).To(HaveKeyWithValue("kubernetes.io/hostname", hostname))
			Expect(hep.Labels).To(HaveKeyWithValue("kubernetes.io/os", runtime.GOOS))
		}
	})

	It("should return an error if HostEndpoint list fails", func() {
		fakeCalicoClient.PrependReactor("list", "hostendpoints", func(action testing.Action) (handled bool, ret k8sruntime.Object, err error) {
			return true, nil, fmt.Errorf("hostendpoint list error")
		})
		lu := &LabelUpdater{
			ctx:             ctx,
			calicoClientSet: fakeCalicoClient,
		}
		err := lu.UpdateLabels()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("hostendpoint list error"))
	})

	It("should return an error if KUBECONFIG is invalid", func() {
		_ = os.Unsetenv("KUBECONFIG")
		lu, err := NewLabelUpdater(ctx)
		Expect(err).To(HaveOccurred())
		Expect(lu).To(BeNil())
	})
})
