// // Copyright (c) 2021 Tigera, Inc. All rights reserved.

package license_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	tigeraapifake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/license"
)

var _ = Describe("License Controller tests", func() {

	It("Copies license when the managed cluster is missing a license", func() {
		managedCalicoCLI := tigeraapifake.NewSimpleClientset()    //nolint:staticcheck // TODO: switch to NewClientset() once k8s.io TestOnlyStaticRESTMapper correctly pluralizes "LicenseKey" to "licensekeys" instead of "licensekeies"
		managementCalicoCLI := tigeraapifake.NewSimpleClientset() //nolint:staticcheck // TODO: switch to NewClientset() once k8s.io TestOnlyStaticRESTMapper correctly pluralizes "LicenseKey" to "licensekeys" instead of "licensekeies"
		reconciler := license.NewLicenseReconciler(managedCalicoCLI, managementCalicoCLI, "cluster")

		_, err := managementCalicoCLI.ProjectcalicoV3().LicenseKeys().Create(context.Background(), &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.LicenseKeySpec{
				Token:       "token",
				Certificate: "certificate",
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		err = reconciler.Reconcile(types.NamespacedName{})
		Expect(err).NotTo(HaveOccurred())

		lic, err := managedCalicoCLI.ProjectcalicoV3().LicenseKeys().Get(context.Background(), "default", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(lic.Name).To(Equal("default"))
		Expect(lic.Spec.Token).To(Equal("token"))
		Expect(lic.Spec.Certificate).To(Equal("certificate"))
	})

	It("Fail to copy license when the management cluster is missing the license", func() {
		managedCalicoCLI := tigeraapifake.NewSimpleClientset()    //nolint:staticcheck // TODO: switch to NewClientset() once k8s.io TestOnlyStaticRESTMapper correctly pluralizes "LicenseKey" to "licensekeys" instead of "licensekeies"
		managementCalicoCLI := tigeraapifake.NewSimpleClientset() //nolint:staticcheck // TODO: switch to NewClientset() once k8s.io TestOnlyStaticRESTMapper correctly pluralizes "LicenseKey" to "licensekeys" instead of "licensekeies"
		reconciler := license.NewLicenseReconciler(managedCalicoCLI, managementCalicoCLI, "cluster")

		err := reconciler.Reconcile(types.NamespacedName{})
		Expect(err).To(HaveOccurred())

		_, err = managedCalicoCLI.ProjectcalicoV3().LicenseKeys().Get(context.Background(), "default", metav1.GetOptions{})
		Expect(err).To(HaveOccurred())
	})
})
