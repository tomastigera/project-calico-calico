// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package event

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("EventStatistics middleware tests", func() {
	Context("MITRE Technique GetMitreTechnique() function", func() {
		It("should return a valid MITRE technique", func() {
			mt, err := GetMitreTechnique("T1222")
			Expect(err).NotTo(HaveOccurred())
			Expect(mt).To(Equal(MitreTechnique{
				MitreID:        "T1222",
				Name:           "File and Directory Permissions Modification",
				DisplayName:    "T1222: File and Directory Permissions Modification",
				Url:            "https://attack.mitre.org/techniques/T1222",
				IsSubtechnique: false,
			}))
		})

		It("should return a valid MITRE sub-technique", func() {
			mt, err := GetMitreTechnique("T1222.002")
			Expect(err).NotTo(HaveOccurred())
			Expect(mt).To(Equal(MitreTechnique{
				MitreID:        "T1222.002",
				Name:           "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
				DisplayName:    "T1222.002: File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification",
				Url:            "https://attack.mitre.org/techniques/T1222/002",
				IsSubtechnique: true,
			}))
		})

		It("should return an error when MITRE technique does not exists", func() {
			_, err := GetMitreTechnique("T1404")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unknown MITRE technique with ID T1404"))
		})

	})
})
