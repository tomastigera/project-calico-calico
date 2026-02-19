// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package flow_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/compliance/pkg/flow"
)

const (
	ns1    = "ns1"
	ns2    = "ns2"
	wep1   = "wep-1"
	wep2   = "wep-2"
	hep1   = "hep-1"
	aggr1  = "wep-*"
	noAggr = ""
	node1  = "node1"
)

var (
	flowWEP1 = apiv3.FlowEndpoint{
		Kind:                    "Pod",
		Name:                    aggr1,
		NameIsAggregationPrefix: true,
		Namespace:               ns1,
	}
	_ = apiv3.FlowEndpoint{
		Kind:                    "Pod",
		Name:                    wep2,
		NameIsAggregationPrefix: false,
		Namespace:               ns2,
	}
	_ = apiv3.FlowEndpoint{
		Kind:                    "HostEndpoint",
		Name:                    node1,
		NameIsAggregationPrefix: true,
		Namespace:               "",
	}
	someOtherWep1 = apiv3.FlowEndpoint{
		Kind:                    "Pod",
		Name:                    "sow-*",
		NameIsAggregationPrefix: true,
		Namespace:               ns1,
	}
	someOtherWep2 = apiv3.FlowEndpoint{
		Kind:                    "Pod",
		Name:                    "wos-*",
		NameIsAggregationPrefix: true,
		Namespace:               ns2,
	}

	matchingFlow = &apiv3.EndpointsReportFlow{
		Source:      flowWEP1,
		Destination: someOtherWep1,
	}
	notMatchingFlow = &apiv3.EndpointsReportFlow{
		Source:      someOtherWep1,
		Destination: someOtherWep2,
	}
)

var _ = Describe("Flow", func() {
	var filter *flow.FlowLogFilter
	BeforeEach(func() {
		filter = flow.NewFlowLogFilter()
	})
	It("match endpoints and aggregated endpoint names that are tracked", func() {
		By("tracking an endpoint in a namespace")
		filter.TrackNamespaceAndEndpoint(ns1, wep1, aggr1)
		filter.TrackNamespaceAndEndpoint(ns2, wep2, noAggr)

		By("verifying that it matches endpoints")
		Expect(filter.FilterInEndpoint(ns1, wep1)).To(BeTrue())
		Expect(filter.FilterInEndpoint(ns2, wep2)).To(BeTrue())

		By("verifying that it matches aggregated endpoints")
		Expect(filter.FilterInAggregateName(ns1, aggr1)).To(BeTrue())
		Expect(filter.FilterInAggregateName(ns2, noAggr)).To(BeFalse())

		By("tracking a host endpoint in global namespace")
		filter.TrackNamespaceAndEndpoint("", hep1, node1)

		By("verifying that it matches the endpoint name and aggregated name")
		Expect(filter.FilterInEndpoint(flow.FlowLogGlobalNamespace, hep1)).To(BeTrue())
		Expect(filter.FilterInAggregateName(flow.FlowLogGlobalNamespace, node1)).To(BeTrue())
	})
	It("matches flows", func() {
		By("tracking endpoints")
		filter.TrackNamespaceAndEndpoint(ns1, wep1, aggr1)
		filter.TrackNamespaceAndEndpoint(ns2, wep2, noAggr)
		filter.TrackNamespaceAndEndpoint("", hep1, node1)

		By("verifying that it matches flows")
		Expect(filter.FilterInFlow(matchingFlow)).To(BeTrue())

		By("verifying that it doesn't match flows that aren't required")
		Expect(filter.FilterInFlow(notMatchingFlow)).To(BeFalse())
	})
})
