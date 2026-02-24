// Copyright (c) 2017-2020 Tigera, Inc. All rights reserved.
//
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

package converter_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	k8sconversion "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
)

// Private repo tests to keep the private tests from conflicting with changes
// made in the OS repo.
var _ = Describe("PodConverter private", func() {

	c := converter.NewPodConverter()

	It("should convert a Pod with AWS SG annotation to label", func() {
		pod := v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "podA",
				Namespace: "default",
				Annotations: map[string]string{
					k8sconversion.AnnotationSecurityGroups: "[\"sg-test\"]",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "nodeA",
			},
		}

		wepDataList, err := c.Convert(&pod)
		By("not generating a conversion error", func() {
			Expect(err).NotTo(HaveOccurred())
		})

		wepData := wepDataList[0]

		// Assert that the returned name / namespace is correct.
		By("returning a WorkloadEndpointData with the correct key information", func() {
			Expect(wepData.PodName).To(Equal("podA"))
			Expect(wepData.Namespace).To(Equal("default"))
		})

		// Assert that GetKey returns the right value.
		key := c.GetKey(wepData)
		By("generating the correct key from the wepData", func() {
			Expect(key).To(Equal("default/podA"))
		})

		By("returning a WorkloadEndpointData with correctly convert AWS SG label", func() {
			Expect(wepData.Labels).Should(
				HaveKeyWithValue(k8sconversion.SecurityGroupLabelPrefix+"/sg-test", ""))
		})
	})
})
