// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package resource_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	tigeraapifake "github.com/tigera/api/pkg/client/clientset_generated/clientset/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
)

var _ = Describe("ConfigMap", func() {
	It("Creates the config map when it doesn't exist", func() {
		cli := fake.NewClientset()
		Expect(resource.WriteConfigMapToK8s(cli, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "TestName",
				Namespace: "TestNamespace",
			},
		})).ShouldNot(HaveOccurred())

		_, err := cli.CoreV1().ConfigMaps("TestNamespace").Get(context.Background(), "TestName", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("Updates the config map when it exists", func() {
		cli := fake.NewClientset()
		Expect(resource.WriteConfigMapToK8s(cli, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "TestName",
				Namespace: "TestNamespace",
			},
			Data: map[string]string{
				"key": "value",
			},
		})).ShouldNot(HaveOccurred())

		cm, err := cli.CoreV1().ConfigMaps("TestNamespace").Get(context.Background(), "TestName", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cm.Data["key"]).Should(Equal("value"))

		Expect(resource.WriteConfigMapToK8s(cli, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "TestName",
				Namespace: "TestNamespace",
			},
			Data: map[string]string{
				"key": "newvalue",
			},
		})).ShouldNot(HaveOccurred())

		cm, err = cli.CoreV1().ConfigMaps("TestNamespace").Get(context.Background(), "TestName", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cm.Data["key"]).Should(Equal("newvalue"))
	})
})

var _ = Describe("Secret", func() {
	It("Creates the Secret when it doesn't exist", func() {
		cli := fake.NewClientset()
		Expect(resource.WriteSecretToK8s(cli, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "TestName",
				Namespace: "TestNamespace",
			},
		})).ShouldNot(HaveOccurred())

		_, err := cli.CoreV1().Secrets("TestNamespace").Get(context.Background(), "TestName", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("Updates the Secret when it exists", func() {
		cli := fake.NewClientset()
		Expect(resource.WriteSecretToK8s(cli, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "TestName",
				Namespace: "TestNamespace",
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		})).ShouldNot(HaveOccurred())

		s, err := cli.CoreV1().Secrets("TestNamespace").Get(context.Background(), "TestName", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(s.Data["key"]).Should(Equal([]byte("value")))

		Expect(resource.WriteSecretToK8s(cli, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "TestName",
				Namespace: "TestNamespace",
			},
			Data: map[string][]byte{
				"key": []byte("newvalue"),
			},
		})).ShouldNot(HaveOccurred())

		s, err = cli.CoreV1().Secrets("TestNamespace").Get(context.Background(), "TestName", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(s.Data["key"]).Should(Equal([]byte("newvalue")))
	})
})

var _ = Describe("LicenseKey", func() {
	It("Creates the LicenseKey when it doesn't exist", func() {
		cli := tigeraapifake.NewSimpleClientset() //nolint:staticcheck // TODO: switch to NewClientset() once k8s.io TestOnlyStaticRESTMapper correctly pluralizes "LicenseKey" to "licensekeys" instead of "licensekeies"
		Expect(resource.WriteLicenseKeyToK8s(cli, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.LicenseKeySpec{
				Token:       "token",
				Certificate: "certificate",
			},
		})).ShouldNot(HaveOccurred())

		_, err := cli.ProjectcalicoV3().LicenseKeys().Get(context.Background(), "default", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("Updates the LicenseKey when it exists", func() {
		cli := tigeraapifake.NewSimpleClientset() //nolint:staticcheck // TODO: switch to NewClientset() once k8s.io TestOnlyStaticRESTMapper correctly pluralizes "LicenseKey" to "licensekeys" instead of "licensekeies"
		Expect(resource.WriteLicenseKeyToK8s(cli, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.LicenseKeySpec{
				Token:       "token",
				Certificate: "certificate",
			},
		})).ShouldNot(HaveOccurred())

		lic, err := cli.ProjectcalicoV3().LicenseKeys().Get(context.Background(), "default", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(lic.Spec.Token).Should(Equal("token"))
		Expect(lic.Spec.Certificate).Should(Equal("certificate"))

		Expect(resource.WriteLicenseKeyToK8s(cli, &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v3.LicenseKeySpec{
				Token:       "new-token",
				Certificate: "new-certificate",
			},
		})).ShouldNot(HaveOccurred())

		lic, err = cli.ProjectcalicoV3().LicenseKeys().Get(context.Background(), "default", metav1.GetOptions{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(lic.Spec.Token).Should(Equal("new-token"))
		Expect(lic.Spec.Certificate).Should(Equal("new-certificate"))
	})
})
