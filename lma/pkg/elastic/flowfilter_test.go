// Copyright (c) 2020-2021 Tigera, Inc. All rights reserved.
package elastic_test

import (
	"fmt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"

	"github.com/projectcalico/calico/lma/pkg/api"
	"github.com/projectcalico/calico/lma/pkg/elastic"
	"github.com/projectcalico/calico/lma/pkg/rbac"
)

var _ = Describe("FlowFilter", func() {
	DescribeTable(
		"IncludeFlow",
		func(flow *elastic.CompositeAggregationBucket, shouldBeIncluded bool, mockFunc func(mockFlowHelper *rbac.MockFlowHelper)) {
			mockFlowHelper := new(rbac.MockFlowHelper)
			mockFunc(mockFlowHelper)

			filter := elastic.NewFlowFilterUserRBAC(mockFlowHelper)
			include, err := filter.IncludeFlow(flow)

			Expect(err).NotTo(HaveOccurred())
			Expect(include).To(Equal(shouldBeIncluded))

			mockFlowHelper.AssertExpectations(GinkgoT())
		},
		TableEntry{
			Description: "Should return true if the user can list pods in the source namespace but not the destination",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "wep"},
						{"source_namespace", "ns1"},
						{"source_name", "a"},
						{"dest_type", "wep"},
						{"dest_namespace", "ns2"},
						{"dest_name", "b"},
					},
				},
				true,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeWep, "ns1").Return(true, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return true if the user can list pods in the destination namespace but not the source",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "wep"},
						{"source_namespace", "ns1"},
						{"source_name", "a"},
						{"dest_type", "wep"},
						{"dest_namespace", "ns2"},
						{"dest_name", "b"},
					},
				},
				true,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeWep, "ns1").Return(false, nil)
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeWep, "ns2").Return(true, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return true if the user can list pods in the destination namespace and the source is of type 'net'",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "net"},
						{"source_namespace", ""},
						{"source_name", "a"},
						{"dest_type", "wep"},
						{"dest_namespace", "ns2"},
						{"dest_name", "b"},
					},
				},
				true,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "").Return(true, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return true if the user can list pods in the source namespace and the destination is of type 'net'",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "wep"},
						{"source_namespace", "ns1"},
						{"source_name", "a"},
						{"dest_type", "net"},
						{"dest_namespace", ""},
						{"dest_name", "b"},
					},
				},
				true,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeWep, "ns1").Return(true, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return false if the user can't list host endpoints and the flow's source type is a host " +
				"endpoint and the destination type is net",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "hep"},
						{"source_namespace", ""},
						{"source_name", "a"},
						{"dest_type", "net"},
						{"dest_namespace", "ns2"},
						{"dest_name", "b"},
					},
				},
				false,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeHep, "").Return(false, nil)
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "ns2").Return(false, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return true if the user can't list host endpoints, the flow's destination type is a host " +
				"endpoint and the source type is net",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "net"},
						{"source_namespace", ""},
						{"source_name", "a"},
						{"dest_type", "hep"},
						{"dest_namespace", "ns2"},
						{"dest_name", "b"},
					},
				},
				true,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "").Return(true, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return true if the user can list global network sets, the source type is ns without a namespace " +
				"and the destination type is net",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "net"},
						{"source_namespace", ""},
						{"source_name", "a"},
						{"dest_type", "net"},
						{"dest_namespace", ""},
						{"dest_name", "b"},
					},
				},
				true,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "").Return(true, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return false if the user can't list global network sets, the source type is ns without a namespace " +
				"and the destination type is net",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "net"},
						{"source_namespace", ""},
						{"source_name", "a"},
						{"dest_type", "net"},
						{"dest_namespace", ""},
						{"dest_name", "b"},
					},
				},
				false,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "").Return(false, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return true if the user can list the network set in the sources namespace, the source type " +
				"is ns, and the destination type is net",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "net"},
						{"source_namespace", "ns1"},
						{"source_name", "a"},
						{"dest_type", "net"},
						{"dest_namespace", ""},
						{"dest_name", "b"},
					},
				},
				true,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "ns1").Return(true, nil)
				},
			},
		},
		TableEntry{
			Description: "Should return false if the user can't list the network set in the sources namespace, the source type " +
				"is ns, and the destination type is net",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					CompositeAggregationKey: elastic.CompositeAggregationKey{
						{"source_type", "net"},
						{"source_namespace", "ns1"},
						{"source_name", "a"},
						{"dest_type", "net"},
						{"dest_namespace", ""},
						{"dest_name", "b"},
					},
				},
				false,
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "ns1").Return(false, nil)
					mockFlowHelper.On("CanListEndpoint", api.EndpointTypeNet, "").Return(false, nil)
				},
			},
		},
	)

	DescribeTable(
		"ModifyFlow",
		func(flow *elastic.CompositeAggregationBucket, mockFunc func(mockFlowHelper *rbac.MockFlowHelper), expectedPolicyBuckets map[interface{}]int64) {
			mockFlowHelper := new(rbac.MockFlowHelper)
			mockFunc(mockFlowHelper)

			filter := elastic.NewFlowFilterUserRBAC(mockFlowHelper)
			err := filter.ModifyFlow(flow)

			Expect(err).NotTo(HaveOccurred())
			Expect(flow.AggregatedTerms["policies"].Buckets).To(Equal(expectedPolicyBuckets))
			mockFlowHelper.AssertExpectations(GinkgoT())
		},
		TableEntry{
			Description: "Should not modify the flow if the user has access to all policy types",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					AggregatedTerms: map[string]*elastic.AggregatedTerm{
						"policies": {
							Buckets: map[interface{}]int64{
								"0|tier1|tier1.np1|pass":                     1000,
								"1|tier1|tier1.staged:np1|allow":             1000,
								"2|tier2|ns1/tier2.np1|pass":                 1000,
								"3|tier2|ns1/tier2.staged:np1|allow":         1000,
								"4|default|ns1/staged:knp.default.np1|allow": 1000,
								"5|default|ns1/knp.default.np1|allow":        1000,
							},
						},
					},
				},
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListPolicy", mock.Anything).Return(true, nil)
				},
				map[interface{}]int64{
					"0|tier1|gnp:tier1.np1|pass|-":      1000,
					"1|tier1|sgnp:tier1.np1|allow|-":    1000,
					"2|tier2|np:ns1/tier2.np1|pass|-":   1000,
					"3|tier2|snp:ns1/tier2.np1|allow|-": 1000,
					"4|default|sknp:ns1/np1|allow|-":    1000,
					"5|default|knp:ns1/np1|allow|-":     1000,
				},
			},
		},
		TableEntry{
			Description: "Should not modify all non staged flows if the user only has access to staged flows",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					AggregatedTerms: map[string]*elastic.AggregatedTerm{
						"policies": {
							Buckets: map[interface{}]int64{
								"0|tier1|tier1.np1|pass|0":                     1000,
								"1|tier1|staged:tier1.np1|allow|1":             1000,
								"2|tier2|ns1/tier2.np1|pass|0":                 1000,
								"3|tier2|ns1/staged:tier2.np1|allow|1":         1000,
								"4|default|ns1/staged:knp.default.np1|allow|0": 1000,
								"5|default|ns1/knp.default.np1|allow|1":        1000,
							},
						},
					},
				},
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("0|tier1|tier1.np1|pass|0", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("1|tier1|staged:tier1.np1|allow|1", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("2|tier2|ns1/tier2.np1|pass|0", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("3|tier2|ns1/staged:tier2.np1|allow|1", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("4|default|ns1/staged:knp.default.np1|allow|0", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("5|default|ns1/knp.default.np1|allow|1", 1000)).Return(true, nil)
				},
				map[interface{}]int64{
					"0|*|*|pass|*":                   1000,
					"1|default|sknp:ns1/np1|allow|0": 1000,
					"2|default|knp:ns1/np1|allow|1":  1000,
				},
			},
		},
		TableEntry{
			Description: "Should not modify all non staged flows if the user only has access to staged flows, mixed policies",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					AggregatedTerms: map[string]*elastic.AggregatedTerm{
						"policies": {
							Buckets: map[interface{}]int64{
								"0|tier1|tier1.np1|allow|0":                     1000,
								"1|tier1|tier1.np1|deny|-1":                     1000,
								"2|tier1|tier1.np1|pass":                        1000,
								"3|tier1|staged:tier1.np1|allow":                1000,
								"4|tier2|ns1/tier2.np1|deny|0":                  1000,
								"5|tier2|ns1/tier2.np1|pass|-":                  1000,
								"6|tier2|ns1/staged:tier2.np1|allow":            1000,
								"7|tier3|ns2/tier3.np2|allow|0":                 1000,
								"8|tier3|ns2/tier3.np3|allow|1":                 1000,
								"9|tier3|ns3/tier3.np3|deny|-1":                 1000,
								"10|tier3|ns3/tier3.np3|pass|0":                 1000,
								"11|default|ns1/staged:knp.default.np1|allow|-": 1000,
								"12|default|ns1/knp.default.np1|allow|-":        1000,
							},
						},
					},
				},
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("0|tier1|tier1.np1|allow|0", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("1|tier1|tier1.np1|deny|-1", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("2|tier1|tier1.np1|pass", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("3|tier1|staged:tier1.np1|allow", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("4|tier2|ns1/tier2.np1|deny|0", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("5|tier2|ns1/tier2.np1|pass", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("6|tier2|ns1/staged:tier2.np1|allow", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("7|tier3|ns2/tier3.np2|allow|0", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("8|tier3|ns2/tier3.np3|allow|1", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("9|tier3|ns3/tier3.np3|deny|-1", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("10|tier3|ns3/tier3.np3|pass|0", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("11|default|ns1/staged:knp.default.np1|allow", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("12|default|ns1/knp.default.np1|allow|-", 1000)).Return(true, nil)
				},
				map[interface{}]int64{
					"6|tier2|snp:ns1/tier2.np1|allow|-": 1000,
					"8|tier3|np:ns2/tier3.np3|allow|1":  1000,
					"11|default|knp:ns1/np1|allow|-":    1000,
					"4|*|*|deny|*":                      1000,
					"5|tier2|np:ns1/tier2.np1|pass|-":   1000,
					"2|*|*|pass|*":                      1000,
					"3|tier1|sgnp:tier1.np1|allow|-":    1000,
					"7|tier3|np:ns2/tier3.np2|allow|0":  1000,
					"9|*|*|deny|*":                      1000,
					"10|tier3|np:ns3/tier3.np3|pass|0":  1000,
					"0|*|*|allow|*":                     1000,
					"1|*|*|deny|*":                      1000,
				},
			},
		},
		TableEntry{
			Description: "Should not modify all staged flows if the user only has access to non staged flows",
			Parameters: []interface{}{
				&elastic.CompositeAggregationBucket{
					AggregatedTerms: map[string]*elastic.AggregatedTerm{
						"policies": {
							Buckets: map[interface{}]int64{
								"0|tier1|tier1.np1|pass|0":                     1000,
								"1|tier1|staged:tier1.np1|allow|1":             1000,
								"2|tier2|ns1/tier2.np1|pass|0":                 1000,
								"3|tier2|ns1/staged:tier2.np1|allow|1":         1000,
								"4|default|ns1/staged:knp.default.np1|allow|0": 1000,
								"5|default|ns1/knp.default.np1|allow|1":        1000,
							},
						},
					},
				},
				func(mockFlowHelper *rbac.MockFlowHelper) {
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("0|tier1|tier1.np1|pass|0", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("1|tier1|staged:tier1.np1|allow|1", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("2|tier2|ns1/tier2.np1|pass|0", 1000)).Return(true, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("3|tier2|ns1/staged:tier2.np1|allow|1", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("4|default|ns1/staged:knp.default.np1|allow|0", 1000)).Return(false, nil)
					mockFlowHelper.On("CanListPolicy", mustParsePolicyHit("5|default|ns1/knp.default.np1|allow|1", 1000)).Return(true, nil)
				},
				map[interface{}]int64{
					"0|tier1|gnp:tier1.np1|pass|0":    1000,
					"1|tier2|np:ns1/tier2.np1|pass|0": 1000,
					"2|default|knp:ns1/np1|allow|1":   1000,
				},
			},
		},
	)
})

func mustParsePolicyHit(str string, count int64) api.PolicyHit {
	ph, err := api.PolicyHitFromFlowLogPolicyString(str, count)
	if err != nil {
		panic(fmt.Sprintf("failed to parse policy hit '%s'", str))
	}

	return ph
}
