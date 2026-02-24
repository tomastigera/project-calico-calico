// Copyright (c) 2021 Tigera, Inc. All rights reserved.
package servicegraph_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/ui-apis/pkg/middleware/servicegraph"
)

var _ = Describe("LabelSelector", func() {
	DescribeTable("Append labels",
		func(source servicegraph.LabelSelectors, labels map[string]string, expectedSelectors servicegraph.LabelSelectors) {
			var sel = servicegraph.AppendLabels(source, labels)
			Expect(sel).To(ConsistOf(expectedSelectors))
		},
		Entry("No input", nil, nil, nil),
		Entry("No source", nil, map[string]string{}, []string{}),
		Entry("Simple labels", nil, map[string]string{"a": "b"}, []string{"a == \"b\""}),
		Entry("Multiple labels", nil, map[string]string{"a": "b", "c": "d"}, []string{"a == \"b\"", "c == \"d\""}),
		Entry("Append to source", []string{"anyVal"}, map[string]string{"a": "b"}, []string{"anyVal", "a == \"b\""}),
	)

	var simpleLabels = &metav1.LabelSelector{
		MatchLabels: map[string]string{"a": "b"},
	}
	var multipleLabels = &metav1.LabelSelector{
		MatchLabels: map[string]string{"a": "b", "c": "d"},
	}
	var labelSelIn = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "a",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"b", "c"},
			},
		},
	}
	var labelSelNotIn = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "a",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{"b", "c"},
			},
		},
	}
	var labelSelExists = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "a",
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	}
	var labelSelNotExists = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "a",
				Operator: metav1.LabelSelectorOpDoesNotExist,
			},
		},
	}
	var multipleLabelSel = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      "a",
				Operator: metav1.LabelSelectorOpExists,
			},
			{
				Key:      "b",
				Operator: metav1.LabelSelectorOpDoesNotExist,
			},
			{
				Key:      "x",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{"y"},
			},
			{
				Key:      "x",
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"z"},
			},
		},
	}
	DescribeTable("Append labels selectors",
		func(source servicegraph.LabelSelectors, labelSel *metav1.LabelSelector, expectedSelectors servicegraph.LabelSelectors) {
			var sel = servicegraph.AppendLabelSelectors(source, labelSel)
			Expect(sel).To(ConsistOf(expectedSelectors))
		},
		Entry("No input", nil, nil, nil),
		Entry("No source", nil, &metav1.LabelSelector{}, []string{}),
		Entry("Simple labels", nil, simpleLabels, []string{"a in {\"b\"}"}),
		Entry("Multiple labels", nil, multipleLabels, []string{"a in {\"b\"}", "c in {\"d\"}"}),
		Entry("Append to source", []string{"anyVal"}, simpleLabels, []string{"anyVal", "a in {\"b\"}"}),
		Entry("LabelSelector In", nil, labelSelIn, []string{"a in {\"b\",\"c\"}"}),
		Entry("LabelSelector NotIn", nil, labelSelNotIn, []string{"a not in {\"b\",\"c\"}"}),
		Entry("LabelSelector Exists", nil, labelSelExists, []string{"has(a)"}),
		Entry("LabelSelector NotExists", nil, labelSelNotExists, []string{"!has(a)"}),
		Entry("Multiple LabelSelector", nil, multipleLabelSel, []string{"has(a)", "!has(b)", "x not in {\"y\"}", "x in {\"z\"}"}),
	)
})
