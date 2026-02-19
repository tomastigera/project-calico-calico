// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package query

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("L7", func(atom Atom, ok bool) {
	actual := atom
	err := IsValidL7LogsAtom(&actual)
	if ok {
		Expect(err).ShouldNot(HaveOccurred())
	} else {
		Expect(err).Should(HaveOccurred())
	}
},
	Entry("start_time", Atom{Key: "start_time", Value: "2019-01-01"}, true),
	Entry("end_time", Atom{Key: "end_time", Value: "2019-01-01"}, true),
	Entry("duration_mean=0", Atom{Key: "duration_mean", Value: "0"}, true),
	Entry("duration_mean=1", Atom{Key: "duration_mean", Value: "1"}, true),
	Entry("duration_mean=-1", Atom{Key: "duration_mean", Value: "-1"}, false),
	Entry("duration_mean parse error", Atom{Key: "duration_mean", Value: "abc"}, false),
	Entry("duration_max=0", Atom{Key: "duration_max", Value: "0"}, true),
	Entry("duration_max=1", Atom{Key: "duration_max", Value: "1"}, true),
	Entry("duration_max=-1", Atom{Key: "duration_max", Value: "-1"}, false),
	Entry("duration_max parse error", Atom{Key: "duration_max", Value: "abc"}, false),
	Entry("bytes_in=0", Atom{Key: "bytes_in", Value: "0"}, true),
	Entry("bytes_in=1", Atom{Key: "bytes_in", Value: "1"}, true),
	Entry("bytes_in=-1", Atom{Key: "bytes_in", Value: "-1"}, false),
	Entry("bytes_in parse error", Atom{Key: "bytes_in", Value: "abc"}, false),
	Entry("bytes_out=0", Atom{Key: "bytes_out", Value: "0"}, true),
	Entry("bytes_out=1", Atom{Key: "bytes_out", Value: "1"}, true),
	Entry("bytes_out=-1", Atom{Key: "bytes_out", Value: "-1"}, false),
	Entry("bytes_out parse error", Atom{Key: "bytes_out", Value: "abc"}, false),
	Entry("count=0", Atom{Key: "bytes_out", Value: "0"}, true),
	Entry("count=1", Atom{Key: "bytes_out", Value: "1"}, true),
	Entry("count=-1", Atom{Key: "bytes_out", Value: "-1"}, false),
	Entry("count parse error", Atom{Key: "bytes_out", Value: "abc"}, false),
	Entry("source_name_aggr", Atom{Key: "source_name_aggr", Value: "foo"}, true),
	Entry("source_namespace", Atom{Key: "source_namespace", Value: "foo"}, true),
	Entry("source_type=wep", Atom{Key: "source_type", Value: "wep"}, true),
	Entry("source_type=ns", Atom{Key: "source_type", Value: "ns"}, true),
	Entry("source_type=net", Atom{Key: "source_type", Value: "net"}, true),
	Entry("source_type unknown", Atom{Key: "source_type", Value: "foo"}, false),
	Entry("source_port_num=0", Atom{Key: "source_port_num", Value: "0"}, true),
	Entry("source_port_num=65535", Atom{Key: "source_port_num", Value: "65535"}, true),
	Entry("source_port_num negative", Atom{Key: "source_port_num", Value: "-1"}, false),
	Entry("source_port_num out of range", Atom{Key: "source_port_num", Value: "65536"}, false),
	Entry("src_name_aggr", Atom{Key: "src_name_aggr", Value: "foo"}, true),
	Entry("src_namespace", Atom{Key: "src_namespace", Value: "foo"}, true),
	Entry("src_type=wep", Atom{Key: "src_type", Value: "wep"}, true),
	Entry("src_type=ns", Atom{Key: "src_type", Value: "ns"}, true),
	Entry("src_type=net", Atom{Key: "src_type", Value: "net"}, true),
	Entry("src_type unknown", Atom{Key: "src_type", Value: "foo"}, false),
	Entry("dest_name", Atom{Key: "dest_name", Value: "foo"}, true),
	Entry("dest_name_aggr", Atom{Key: "dest_name_aggr", Value: "foo"}, true),
	Entry("dest_namespace", Atom{Key: "dest_namespace", Value: "foo"}, true),
	Entry("dest_service_name", Atom{Key: "dest_service_name", Value: "foo"}, true),
	Entry("dest_service_namespace", Atom{Key: "dest_service_namespace", Value: "foo"}, true),
	Entry("dest_service_port_name", Atom{Key: "dest_service_port_name", Value: "foo"}, true),
	Entry("dest_service_port_num=0", Atom{Key: "dest_service_port_num", Value: "0"}, true),
	Entry("dest_service_port_num=65535", Atom{Key: "dest_service_port_num", Value: "65535"}, true),
	Entry("dest_service_port_num negative", Atom{Key: "dest_service_port_num", Value: "-1"}, false),
	Entry("dest_service_port_num=65536", Atom{Key: "dest_service_port_num", Value: "65536"}, false),
	Entry("dest_service_port_num=foo", Atom{Key: "dest_service_port_num", Value: "foo"}, false),
	Entry("dest_type=wep", Atom{Key: "dest_type", Value: "wep"}, true),
	Entry("dest_type=ns", Atom{Key: "dest_type", Value: "ns"}, true),
	Entry("dest_type=net", Atom{Key: "dest_type", Value: "net"}, true),
	Entry("dest_type unknown", Atom{Key: "dest_type", Value: "foo"}, false),
	Entry("dest_port_num=0", Atom{Key: "dest_port_num", Value: "0"}, true),
	Entry("dest_port_num=65535", Atom{Key: "dest_port_num", Value: "65535"}, true),
	Entry("dest_port_num negative", Atom{Key: "dest_port_num", Value: "-1"}, false),
	Entry("dest_port_num out of range", Atom{Key: "dest_port_num", Value: "65536"}, false),
	Entry("method", Atom{Key: "method", Value: "foo"}, true),
	Entry("user_agent", Atom{Key: "user_agent", Value: "foo"}, true),
	Entry("url", Atom{Key: "url", Value: "www.voodoohoodoo.com/v1/foo/bar"}, true),
	Entry("response_code", Atom{Key: "response_code", Value: "foo"}, true),
	Entry("type", Atom{Key: "type", Value: "foo"}, true),
	Entry("gateway_name", Atom{Key: "gateway_name", Value: "foo"}, true),
	Entry("gateway_namespace", Atom{Key: "gateway_namespace", Value: "foo"}, true),
	Entry("gateway_route_name", Atom{Key: "gateway_route_name", Value: "foo"}, true),
	Entry("gateway_route_namespace", Atom{Key: "gateway_route_namespace", Value: "foo"}, true),
	Entry("gateway_listener_full_name", Atom{Key: "gateway_listener_full_name", Value: "foo"}, true),
	Entry("gateway_class", Atom{Key: "gateway_class", Value: "foo"}, true),
	Entry("gateway_status", Atom{Key: "gateway_status", Value: "foo"}, true),
	Entry("gateway_route_status", Atom{Key: "gateway_route_status", Value: "foo"}, true),
)
