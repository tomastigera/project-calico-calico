// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package query

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("WAF", func(input Atom, ok bool) {
	actual := input

	err := IsValidWAFAtom(&actual)
	if ok {
		Expect(err).ShouldNot(HaveOccurred())
	} else {
		Expect(err).Should(HaveOccurred())
	}
},
	Entry("timestamp", Atom{Key: "timestamp", Value: "2022-01-17"}, true),
	Entry("path", Atom{Key: "path", Value: "/test/artists.php"}, true),
	Entry("method", Atom{Key: "method", Value: "GET"}, true),
	Entry("protocol", Atom{Key: "protocol", Value: "HTTP/1.1"}, true),
	Entry("source.ip", Atom{Key: "source.ip", Value: "192.168.68.202"}, true),
	Entry("source.port_num", Atom{Key: "source.port_num", Value: "57904"}, true),
	Entry("source.hostname", Atom{Key: "source.hostname", Value: ""}, true),
	Entry("destination.ip", Atom{Key: "destination.ip", Value: "192.168.68.200"}, true),
	Entry("destination.port_num", Atom{Key: "destination.port_num", Value: "80"}, true),
	Entry("destination.hostname", Atom{Key: "destination.hostname", Value: "echo-a"}, true),
	Entry("rule_info", Atom{Key: "rule_info", Value: "rule_info:Host:'192.168.68.200' File:'/etc/waf2/custom-REQUEST-942-APPLICATION-ATTACK-SQLI.conf' Line:'45' ID:'942100' Data:'' Severity:'0' Version:'OWASP_CRS/3.3.2' "}, true),
	Entry("node", Atom{Key: "node", Value: "ip-172-16-101-111.us-west-2.compute.internal"}, true),
)
