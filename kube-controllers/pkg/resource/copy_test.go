// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package resource_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/projectcalico/calico/kube-controllers/pkg/resource"
)

var _ = Describe("ConfigMap", func() {
	It("Copies the expected values to the new ConfigMap", func() {
		deleteTime := metav1.Now()
		i := int64(5)

		configMap := &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:                       "TestName",
				GenerateName:               "TestGenerateName",
				Namespace:                  "TestNamespace",
				UID:                        "TestUID",
				ResourceVersion:            "TestResourceVersion",
				Generation:                 int64(4),
				CreationTimestamp:          metav1.Now(),
				DeletionTimestamp:          &deleteTime,
				DeletionGracePeriodSeconds: &i,
				Labels: map[string]string{
					"labelkey": "labelvalue",
				},
				Annotations: map[string]string{
					"annotationkey": "annotationvalue",
				},
				OwnerReferences: []metav1.OwnerReference{{
					Name: "TestOwner",
				}},
				Finalizers: []string{"TestFinalizer"},
			},
			Data: map[string]string{
				"key": "value",
			},
		}
		cp := resource.CopyConfigMap(configMap)

		Expect(cp.Data).Should(Equal(configMap.Data))

		compareMetaObject(configMap.ObjectMeta, cp.ObjectMeta)
	})
})

var _ = Describe("Secret", func() {
	It("Copies the expected values to the new Secret", func() {
		deleteTime := metav1.Now()
		i := int64(5)

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:                       "TestName",
				GenerateName:               "TestGenerateName",
				Namespace:                  "TestNamespace",
				UID:                        "TestUID",
				ResourceVersion:            "TestResourceVersion",
				Generation:                 int64(4),
				CreationTimestamp:          metav1.Now(),
				DeletionTimestamp:          &deleteTime,
				DeletionGracePeriodSeconds: &i,
				Labels: map[string]string{
					"labelkey": "labelvalue",
				},
				Annotations: map[string]string{
					"annotationkey": "annotationvalue",
				},
				OwnerReferences: []metav1.OwnerReference{{
					Name: "TestOwner",
				}},
				Finalizers: []string{"TestFinalizer"},
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		}
		cp := resource.CopySecret(secret)

		Expect(cp.Data).Should(Equal(secret.Data))

		compareMetaObject(secret.ObjectMeta, cp.ObjectMeta)
	})
})

var _ = Describe("LicenseKey", func() {
	It("Copies the expected values to the new LicenseKey", func() {
		deleteTime := metav1.Now()
		i := int64(5)

		licenseKey := &v3.LicenseKey{
			ObjectMeta: metav1.ObjectMeta{
				Name:                       "default",
				GenerateName:               "TestGenerateName",
				UID:                        "TestUID",
				ResourceVersion:            "TestResourceVersion",
				Generation:                 int64(4),
				CreationTimestamp:          metav1.Now(),
				DeletionTimestamp:          &deleteTime,
				DeletionGracePeriodSeconds: &i,
				Labels: map[string]string{
					"labelkey": "labelvalue",
				},
				Annotations: map[string]string{
					"annotationkey": "annotationvalue",
				},
				OwnerReferences: []metav1.OwnerReference{{
					Name: "TestOwner",
				}},
				Finalizers: []string{"TestFinalizer"},
			},
			Spec: v3.LicenseKeySpec{
				Token:       "token",
				Certificate: "certificate",
			},
		}

		cp := resource.CopyLicenseKey(licenseKey)

		Expect(cp.Spec.Certificate).Should(Equal(licenseKey.Spec.Certificate))
		Expect(cp.Spec.Token).Should(Equal(licenseKey.Spec.Token))

		compareMetaObject(licenseKey.ObjectMeta, cp.ObjectMeta)
	})
})

func compareMetaObject(orig, cp metav1.ObjectMeta) {
	Expect(cp.Name).Should(Equal(orig.Name))
	Expect(cp.Namespace).Should(Equal(orig.Namespace))
	Expect(cp.UID).Should(Equal(types.UID("")))
	Expect(cp.ResourceVersion).Should(Equal(""))
	Expect(cp.Generation).Should(Equal(int64(0)))
	Expect(cp.CreationTimestamp).Should(Equal(metav1.Time{}))
	Expect(cp.DeletionTimestamp).Should(Equal((*metav1.Time)(nil)))
	Expect(cp.DeletionGracePeriodSeconds).Should(Equal((*int64)(nil)))
	Expect(cp.Labels).Should(Equal(orig.Labels))
	Expect(cp.Annotations).Should(Equal(orig.Annotations))
	Expect(cp.OwnerReferences).Should(Equal(([]metav1.OwnerReference)(nil)))
	Expect(cp.Finalizers).Should(Equal(orig.Finalizers))
}
