// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("DNS",
	func(input Atom, expected string, ok bool) {
		actual := input

		err := IsValidDNSAtom(&actual)
		if ok {
			Expect(err).ShouldNot(HaveOccurred())
			Expect(actual.Value).Should(Equal(expected))
		} else {
			Expect(err).Should(HaveOccurred())
		}
	},
	Entry("start_time", Atom{Key: "start_time", Value: "2019-01-01"}, "2019-01-01", true),
	Entry("end_time", Atom{Key: "end_time", Value: "2019-01-01"}, "2019-01-01", true),
	Entry("count", Atom{Key: "count", Value: "0"}, "0", true),
	Entry("count invalid", Atom{Key: "count", Value: "abc"}, "", false),
	Entry("client_name", Atom{Key: "client_name", Value: "test"}, "test", true),
	Entry("client_name bad idna", Atom{Key: "client_name", Value: "xn--test"}, "", false),
	Entry("client_name_aggr", Atom{Key: "client_name_aggr", Value: "test-*"}, "test-*", true),
	Entry("client_name_aggr bad idna", Atom{Key: "client_name_aggr", Value: "xn--test-*"}, "", false),
	Entry("client_namespace", Atom{Key: "client_namespace", Value: "test"}, "test", true),
	Entry("client_namespace bad idna", Atom{Key: "client_namespace", Value: "xn--test"}, "", false),
	Entry("client_ip ipv6", Atom{Key: "client_ip", Value: "0::1"}, "::1", true),
	Entry("client_ip invalid", Atom{Key: "client_ip", Value: "invalid"}, "", false),
	Entry("host", Atom{Key: "host", Value: "test"}, "test", true),
	Entry("latency_count=0", Atom{Key: "latency_count", Value: "0"}, "0", true),
	Entry("latency_count=-1", Atom{Key: "latency_count", Value: "-1"}, "", false),
	Entry("latency_count invalid", Atom{Key: "latency_count", Value: "abc"}, "", false),
	Entry("latency_max=0", Atom{Key: "latency_max", Value: "0"}, "0", true),
	Entry("latency_max=-1", Atom{Key: "latency_max", Value: "-1"}, "", false),
	Entry("latency_max invalid", Atom{Key: "latency_max", Value: "abc"}, "", false),
	Entry("latency_mean=0", Atom{Key: "latency_mean", Value: "0"}, "0", true),
	Entry("latency_mean=-1", Atom{Key: "latency_mean", Value: "-1"}, "", false),
	Entry("latency_mean invalid", Atom{Key: "latency_mean", Value: "abc"}, "", false),
	Entry("client_labels parent", Atom{Key: "client_labels", Value: "bar"}, "", false),
	Entry("client_labels.valid", Atom{Key: "client_labels.foo", Value: "bar"}, "bar", true),
	Entry("client_labels multiple dots in label", Atom{Key: "client_labels.labels.foo.baz", Value: "bar"}, "bar", true),
	Entry("servers parent", Atom{Key: "servers", Value: "foo"}, "", false),
	Entry("servers.name", Atom{Key: "servers.name", Value: "foo"}, "foo", true),
	Entry("servers.name_aggr", Atom{Key: "servers.name_aggr", Value: "foo-*"}, "foo-*", true),
	Entry("servers.namespace", Atom{Key: "servers.namespace", Value: "foo"}, "foo", true),
	Entry("servers.labels parent", Atom{Key: "servers.labels", Value: "foo"}, "", false),
	Entry("servers.labels valid", Atom{Key: "servers.labels.foo", Value: "bar"}, "bar", true),
	Entry("servers.labels multiple dots in label", Atom{Key: "servers.labels.foo.baz", Value: "bar"}, "bar", true),
	Entry("servers.ip ipv6", Atom{Key: "servers.ip", Value: "0::1"}, "::1", true),
	Entry("servers.ip invalid", Atom{Key: "servers.ip", Value: "invalid"}, "", false),
	Entry("qtype AAAA", Atom{Key: "qtype", Value: "AAAA"}, "AAAA", true),
	Entry("qtype #2", Atom{Key: "qtype", Value: "#2"}, "#2", true),
	Entry("qtype invalid", Atom{Key: "qtype", Value: "AA"}, "", false),
	Entry("qtype empty", Atom{Key: "qtype", Value: ""}, "", false),
	Entry("rrsets parent", Atom{Key: "rrsets"}, "", false),
	Entry("rrsets.name", Atom{Key: "rrsets.name", Value: "test"}, "test", true),
	Entry("rrsets.type NS", Atom{Key: "rrsets.type", Value: "NS"}, "NS", true),
	Entry("rrsets.type #1", Atom{Key: "rrsets.type", Value: "#1"}, "#1", true),
	Entry("rrsets.type invalid", Atom{Key: "rrsets.type", Value: "test"}, "", false),
	Entry("rrsets.type empty", Atom{Key: "rrsets.type", Value: ""}, "", false),
	Entry("rrsets.class", Atom{Key: "rrsets.class", Value: "test"}, "test", true),
	Entry("rrsets.rdata", Atom{Key: "rrsets.rdata", Value: "test"}, "test", true),
	Entry("invalid field", Atom{Key: "test", Value: "test"}, "", false),
)
