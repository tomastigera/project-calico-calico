// Copyright (c) 2022-2023 Tigera, Inc. All rights reserved.

package v3

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	api "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = DescribeTable("GlobalAlertTemplate Validator",
	func(input interface{}, valid bool) {
		if valid {
			Expect(Validate(input)).NotTo(HaveOccurred(),
				"expected value to be valid")
		} else {
			Expect(Validate(input)).To(HaveOccurred(),
				"expected value to be invalid")
		}
	},
	Entry("GlobalAlertTemplate with type AnomalyDetection - no longer valid",
		&api.GlobalAlertTemplate{
			ObjectMeta: v1.ObjectMeta{Name: "tigera.io.detector.port-scan"},
			Spec: api.GlobalAlertSpec{
				Type:        api.GlobalAlertTypeAnomalyDetection,
				Description: "test",
				Detector: &api.DetectorParams{
					Name: "port_scan",
				},
				Severity: 100,
			},
		},
		false,
	),
)
