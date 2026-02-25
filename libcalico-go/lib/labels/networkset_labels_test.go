// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package labels_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/labels"
)

var shortNetworksetName = "my-netset"
var longNetworksetName = "my-very-long-networkset-name-for-testing-shortening-very-long-networkset-names"
var hashedLongNetworksetName = "my-very-long-networkset-name-for-testing-shortening-ver-9dc9e83"

var _ = Describe("lib/labels tests", func() {
	DescribeTable("AddKindandNameLabels",
		func(name string, inputLabels, expectedLabels map[string]string) {
			Expect(labels.AddKindandNameLabels(name, inputLabels)).To(Equal(expectedLabels))
		},

		Entry("Nil labels",
			shortNetworksetName,
			nil,
			map[string]string{apiv3.LabelKind: apiv3.KindNetworkSet, apiv3.LabelName: shortNetworksetName},
		),
		Entry("Empty labels",
			shortNetworksetName,
			map[string]string{},
			map[string]string{apiv3.LabelKind: apiv3.KindNetworkSet, apiv3.LabelName: shortNetworksetName},
		),
		Entry("Filled labels",
			shortNetworksetName,
			map[string]string{"a": "b", "projectcalico.org/namespace": "my-namespace"},
			map[string]string{"a": "b", apiv3.LabelKind: apiv3.KindNetworkSet, apiv3.LabelName: shortNetworksetName, "projectcalico.org/namespace": "my-namespace"},
		),
		Entry("Empty labels with long name",
			longNetworksetName,
			map[string]string{},
			map[string]string{apiv3.LabelKind: apiv3.KindNetworkSet, apiv3.LabelName: hashedLongNetworksetName},
		),
	)

	DescribeTable("ValidateNetworkSetLabels",
		func(name string, inputLabels map[string]string, expectedValidation bool) {
			Expect(labels.ValidateNetworkSetLabels(name, inputLabels)).To(Equal(expectedValidation))
		},

		Entry("Nil labels",
			shortNetworksetName,
			nil,
			false,
		),
		Entry("Empty labels",
			shortNetworksetName,
			map[string]string{},
			false,
		),
		Entry("Filled labels",
			shortNetworksetName,
			map[string]string{"a": "b", apiv3.LabelKind: apiv3.KindNetworkSet, apiv3.LabelName: shortNetworksetName, "projectcalico.org/namespace": "my-namespace"},
			true,
		),
		Entry("Filled labels with long name",
			longNetworksetName,
			map[string]string{"a": "b", apiv3.LabelKind: apiv3.KindNetworkSet, apiv3.LabelName: hashedLongNetworksetName, "projectcalico.org/namespace": "my-namespace"},
			true,
		),
	)
})
