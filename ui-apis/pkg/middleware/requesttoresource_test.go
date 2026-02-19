// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package middleware

import (
	"fmt"
	"net/http"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	lmak8s "github.com/projectcalico/calico/lma/pkg/k8s"
)

func genRequest(q string) *http.Request {
	uri, _ := url.Parse(q)
	return &http.Request{URL: uri}
}

func genRequestWithHeader(q, xclu string) *http.Request {
	uri, _ := url.Parse(q)
	req := &http.Request{URL: uri, Header: make(map[string][]string, 1)}
	req.Header.Add(lmak8s.XClusterIDHeader, xclu)
	return req
}

var _ = Describe("Test request to resource name conversion", func() {
	DescribeTable("successful conversion",
		func(req *http.Request, expectedName string) {
			clu, rn, _, err := parseURLPath(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(rn).To(Equal(expectedName))
			Expect(clu).To(Equal("cluster"))
		},
		Entry("Flow conversion",
			genRequest("/tigera_secure_ee_flows.cluster.*/_search"),
			"flows"),
		Entry("Flow conversion with cluster-name",
			genRequest("/tigera_secure_ee_flows.cluster-name.*/_search"),
			"flows"),
		Entry("Flow conversion with cluster.name",
			genRequest("/tigera_secure_ee_flows.cluster.name.*/_search"),
			"flows"),
		Entry("Flow conversion postfix *",
			genRequest("/tigera_secure_ee_flows*/_search"),
			"flows"),
		Entry("Flow conversion",
			genRequest("/tigera_secure_ee_flows.cluster.*/_search?size=0"),
			"flows"),
		// This is the actual audit request made at the time of writing.
		Entry("Audit conversion (...audit_*)",
			genRequest("/tigera_secure_ee_audit_*/_search"),
			"audit*"),
		Entry("All audit conversion (...audit_*)",
			genRequest("/tigera_secure_ee_audit_*.cluster.*/_search"),
			"audit*"),
		Entry("All audit alternate conversion (...audit*)",
			genRequest("/tigera_secure_ee_audit*.cluster.*/_search"),
			"audit*"),
		Entry("All audit conversion with cluster-name",
			genRequest("/tigera_secure_ee_audit_*.cluster-name.*/_search"),
			"audit*"),
		Entry("All audit conversion with cluster.name",
			genRequest("/tigera_secure_ee_audit_*.cluster.name.*/_search"),
			"audit*"),
		Entry("Audit ee conversion",
			genRequest("/tigera_secure_ee_audit_ee.cluster.*/_search"),
			"audit_ee"),
		Entry("Audit ee conversion with cluster-name",
			genRequest("/tigera_secure_ee_audit_ee.cluster-name.*/_search"),
			"audit_ee"),
		Entry("Audit ee conversion with cluster.name",
			genRequest("/tigera_secure_ee_audit_ee.cluster.name.*/_search"),
			"audit_ee"),
		Entry("L7 conversion",
			genRequest("/tigera_secure_ee_l7.cluster.*/_search"),
			"l7"),
		Entry("L7 conversion with cluster-name",
			genRequest("/tigera_secure_ee_l7.cluster-name.*/_search"),
			"l7"),
		Entry("L7 conversion with cluster.name",
			genRequest("/tigera_secure_ee_l7.cluster.name.*/_search"),
			"l7"),
		Entry("Audit kube conversion with cluster.name",
			genRequest("/tigera_secure_ee_audit_kube.cluster.name.*/_search"),
			"audit_kube"),
		// This is the actual events request made at the time of writing.
		Entry("Events conversion",
			genRequest("/tigera_secure_ee_events*/_search"),
			"events"),
		Entry("Flow conversion with extra prefix",
			genRequest("/this.should/be_tolerated/tigera_secure_ee_flows.cluster.*/_search"),
			"flows"),
		Entry("Flow conversion from flowLogNames endpoint",
			genRequest("/flowLogNames"),
			"flows"),
		Entry("Flow conversion from flowLogNamespaces endpoint",
			genRequest("/flowLogNamespaces"),
			"flows"),
		Entry("Flow conversion from flowLogs endpoint",
			genRequest("/flowLogs"),
			"flows"),
		Entry("Flow conversion from flowLogNames endpoint with extra prefix",
			genRequest("/this.should/be_tolerated/flowLogNames"),
			"flows"),
		Entry("Flow conversion from flowLogNamespaces endpoint with extra prefix",
			genRequest("/this.should/be_tolerated/flowLogNamespaces"),
			"flows"),
		Entry("Flow conversion from flowLogs endpoint with extra prefix",
			genRequest("/this.should/be_tolerated/flowLogs"),
			"flows"),
	)
	DescribeTable("failed conversion",
		func(req *http.Request) {
			_, _, _, err := parseURLPath(req)
			Expect(err).To(HaveOccurred())
		},

		Entry("missing first slash",
			genRequest("tigera_secure_ee_flows.cluster.*/_search")),
		Entry("No trailing _search",
			genRequest("/tigera_secure_ee_flows.cluster.*/")),
		Entry("Wrong index name",
			genRequest("/tigera_wrong_ee_flows.cluster.*/_search")),
		Entry("missing first slash",
			genRequest("flowLogs")),
		Entry("lower cased endpoint name",
			genRequest("/flowlogs")),
		Entry("index that is not present in query resource map",
			genRequest("/tigera_secure_ee_l7_abc.cluster-name.*/_search")),
		Entry("Random attempts to create panics",
			genRequest("http://foo.com/blah_blah_(wikipedia)_(again)")),
		Entry("Random attempts to create panics",
			genRequest("http://www.example.com/wpstyle/?p=364")),
		Entry("Random attempts to create panics",
			genRequest("http://userid:password@example.com:8080")),
		Entry("Random attempts to create panics",
			genRequest("/")),
		Entry("Random attempts to create panics",
			genRequest("http://例子.测试")),
	)
})

var _ = Describe("Test url path modifications in parseLegacyURLPath()", func() {
	DescribeTable("successful conversion",

		func(uriStr, xclu, resultUri string) {
			req := genRequestWithHeader(uriStr, xclu)
			clu, _, urlPath, _ := parseLegacyURLPath(req)
			Expect(xclu).To(Equal(clu))
			req.URL.Path = urlPath
			req.URL.RawPath = urlPath
			Expect(fmt.Sprintf("%v", req.URL)).To(Equal(resultUri))
		},

		Entry("Standard scenario",
			"/tigera_secure_ee_flows.cluster.*/_search", "cluster", "/tigera_secure_ee_flows.cluster.*/_search"),
		Entry("Standard scenario, different x-cluster-id",
			"/tigera_secure_ee_flows.cluster.*/_search", "different", "/tigera_secure_ee_flows.different.*/_search"),
		Entry("Standard scenario no .cluster",
			"/tigera_secure_ee_flows*/_search", "cluster", "/tigera_secure_ee_flows*.cluster.*/_search"),

		Entry("Standard scenario l7",
			"/tigera_secure_ee_l7.cluster.*/_search", "cluster", "/tigera_secure_ee_l7.cluster.*/_search"),
		Entry("Standard scenario, different x-cluster-id",
			"/tigera_secure_ee_l7.cluster.*/_search", "different", "/tigera_secure_ee_l7.different.*/_search"),
		Entry("Standard scenario no .cluster",
			"/tigera_secure_ee_l7*/_search", "cluster", "/tigera_secure_ee_l7*.cluster.*/_search"),

		Entry("Path prepended to standard scenario",
			"/a.b/c/tigera_secure_ee_flows.cluster.*/_search", "cluster", "/a.b/c/tigera_secure_ee_flows.cluster.*/_search"),
		Entry("Path prepended to standard scenario, different x-cluster-id",
			"/a.b/c/tigera_secure_ee_flows.cluster.*/_search", "different", "/a.b/c/tigera_secure_ee_flows.different.*/_search"),
		Entry("Path prepended to standard scenario no .cluster",
			"/a.b/c/tigera_secure_ee_flows*/_search", "cluster", "/a.b/c/tigera_secure_ee_flows*.cluster.*/_search"),

		Entry("Url Parameters",
			"/tigera_secure_ee_flows.cluster.*/_search?foo=bar", "cluster", "/tigera_secure_ee_flows.cluster.*/_search?foo=bar"),
		Entry("Url Parameters, different x-cluster-id",
			"/tigera_secure_ee_flows.cluster.*/_search?foo=bar", "different", "/tigera_secure_ee_flows.different.*/_search?foo=bar"),
		Entry("Url Parameters no .cluster",
			"/tigera_secure_ee_flows*/_search?foo=bar", "cluster", "/tigera_secure_ee_flows*.cluster.*/_search?foo=bar"),

		Entry("Events (without asterisk)",
			"/tigera_secure_ee_events.cluster/_search", "cluster", "/tigera_secure_ee_events.cluster/_search"),
		Entry("Events (without asterisk) different x-cluster-id",
			"/tigera_secure_ee_events.cluster/_search", "different", "/tigera_secure_ee_events.different/_search"),
		Entry("Events (without asterisk) no .cluster",
			"/tigera_secure_ee_events/_search", "cluster", "/tigera_secure_ee_events.cluster/_search"),

		Entry("Standard scenario",
			"/tigera_secure_ee_audit.cluster.*/_search", "cluster", "/tigera_secure_ee_audit.cluster.*/_search"),
		Entry("Standard scenario no .cluster",
			"/tigera_secure_ee_audit*/_search", "cluster", "/tigera_secure_ee_audit*.cluster.*/_search"),
		Entry("Standard scenario",
			"/tigera_secure_ee_audit_ee.cluster.*/_search", "cluster", "/tigera_secure_ee_audit_ee.cluster.*/_search"),
		Entry("Standard scenario no .cluster",
			"/tigera_secure_ee_audit_ee*/_search", "cluster", "/tigera_secure_ee_audit_ee*.cluster.*/_search"),
		Entry("Standard scenario",
			"/tigera_secure_ee_audit_kube.cluster.*/_search", "cluster", "/tigera_secure_ee_audit_kube.cluster.*/_search"),
		Entry("Standard scenario no .cluster",
			"/tigera_secure_ee_audit_kube*/_search", "cluster", "/tigera_secure_ee_audit_kube*.cluster.*/_search"),
		Entry("Standard scenario",
			"/tigera_secure_ee_dns.cluster.*/_search", "cluster", "/tigera_secure_ee_dns.cluster.*/_search"),
		Entry("Standard scenario no .cluster",
			"/tigera_secure_ee_dns*/_search", "cluster", "/tigera_secure_ee_dns*.cluster.*/_search"),
	)

})
