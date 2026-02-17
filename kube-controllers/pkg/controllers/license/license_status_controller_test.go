// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package license

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	tigeraapifake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/licensing/utils"
)

type mockInformer struct {
	cache.SharedIndexInformer
	handler cache.ResourceEventHandler
}

func (m *mockInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	m.handler = handler
	return nil, nil
}

func (m *mockInformer) HasSynced() bool {
	return true
}

var _ = Describe("LicenseStatusController tests", func() {
	var (
		ctx      context.Context
		cli      *tigeraapifake.Clientset
		ctrl     *LicenseStatusController
		informer *mockInformer
	)

	BeforeEach(func() {
		ctx = context.Background()
		cli = tigeraapifake.NewSimpleClientset()
		informer = &mockInformer{}
		c := NewStatusController(ctx, cli, informer)
		ctrl = c.(*LicenseStatusController)
	})

	It("should register event handlers", func() {
		Expect(informer.handler).NotTo(BeNil())
	})

	It("should reconcile on Add event", func() {
		licenseKey := utils.ValidEnterpriseTestLicense()
		licenseKey.Name = "default"
		_, err := cli.ProjectcalicoV3().LicenseKeys().Create(ctx, licenseKey, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		informer.handler.OnAdd(licenseKey, false)

		// Verify the status was updated.
		updated, err := cli.ProjectcalicoV3().LicenseKeys().Get(ctx, "default", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.Status.Expiry.IsZero()).To(BeFalse())
	})

	It("should reconcile on Update event", func() {
		licenseKey := utils.ValidEnterpriseTestLicense()
		licenseKey.Name = "default"
		_, err := cli.ProjectcalicoV3().LicenseKeys().Create(ctx, licenseKey, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		informer.handler.OnUpdate(nil, licenseKey)

		// Verify the status was updated.
		updated, err := cli.ProjectcalicoV3().LicenseKeys().Get(ctx, "default", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.Status.Expiry.IsZero()).To(BeFalse())
	})

	It("should reconcile a valid LicenseKey and update its status", func() {
		// Create a valid license key using utils.
		licenseKey := utils.ValidEnterpriseTestLicense()
		licenseKey.Name = "default"

		// Mock the client to return the license key on UpdateStatus.
		// tigeraapifake.NewSimpleClientset() already handles this.

		// Create the license key in the fake client.
		_, err := cli.ProjectcalicoV3().LicenseKeys().Create(ctx, licenseKey, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Reconcile the license key.
		err = ctrl.Reconcile(licenseKey)
		Expect(err).NotTo(HaveOccurred())

		// Verify the status was updated.
		updated, err := cli.ProjectcalicoV3().LicenseKeys().Get(ctx, "default", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(updated.Status.Expiry.IsZero()).To(BeFalse())
		Expect(updated.Status.MaxNodes).To(BeNumerically(">", 0))
		Expect(updated.Status.Package).NotTo(BeEmpty())
	})

	It("should stop when the stop channel is closed", func() {
		stopCh := make(chan struct{})
		done := make(chan struct{})

		go func() {
			ctrl.Run(stopCh)
			close(done)
		}()

		// Give it a moment to start.
		Consistently(done).ShouldNot(BeClosed())

		close(stopCh)
		Eventually(done).Should(BeClosed())
	})

	It("should fail to reconcile an invalid LicenseKey", func() {
		licenseKey := &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: "invalid",
			},
			Spec: v3.LicenseKeySpec{
				Token: "invalid-token",
			},
		}

		err := ctrl.Reconcile(licenseKey)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to decode license key"))
	})
})
