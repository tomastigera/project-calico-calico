// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.

package query

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Events", func(atom Atom, ok bool) {
	actual := atom
	err := IsValidEventsKeysAtom(&actual)
	if ok {
		Expect(err).ShouldNot(HaveOccurred())
	} else {
		Expect(err).Should(HaveOccurred())
	}
},
	Entry("attack_vector", Atom{Key: "attack_vector", Value: "Process"}, true),
	Entry("description", Atom{Key: "description", Value: "alert description"}, true),
	Entry("dest_ip invalid", Atom{Key: "dest_ip", Value: "invalid-ip"}, false),
	Entry("dest_ip", Atom{Key: "dest_ip", Value: "1.2.3.4"}, true),
	Entry("dest_name", Atom{Key: "dest_name", Value: "foo"}, true),
	Entry("dest_name_aggr", Atom{Key: "dest_name_aggr", Value: "foo"}, true),
	Entry("dest_namespace", Atom{Key: "dest_namespace", Value: "foo"}, true),
	Entry("dest_port invalid", Atom{Key: "dest_port", Value: "-1"}, false),
	Entry("dest_port", Atom{Key: "dest_port", Value: "1234"}, true),
	Entry("dismissed invalid", Atom{Key: "dismissed", Value: "invalid"}, false),
	Entry("dismissed", Atom{Key: "dismissed", Value: "false"}, true),
	Entry("dismissed", Atom{Key: "dismissed", Value: "true"}, true),
	Entry("host", Atom{Key: "host", Value: "foo"}, true),
	Entry("mitre_tactic", Atom{Key: "mitre_tactic", Value: "Access"}, true),
	Entry("name", Atom{Key: "name", Value: "bar"}, true),
	Entry("origin", Atom{Key: "origin", Value: "foo"}, true),
	Entry("severity", Atom{Key: "severity", Value: "-1"}, false),
	Entry("severity", Atom{Key: "severity", Value: "0"}, true),
	Entry("severity", Atom{Key: "severity", Value: "100"}, true),
	Entry("severity", Atom{Key: "severity", Value: "101"}, false),
	Entry("source_ip invalid", Atom{Key: "source_ip", Value: "invalid-ip"}, false),
	Entry("source_ip", Atom{Key: "source_ip", Value: "1.2.3.4"}, true),
	Entry("source_name", Atom{Key: "source_name", Value: "foo"}, true),
	Entry("source_name_aggr", Atom{Key: "source_name_aggr", Value: "foo"}, true),
	Entry("source_namespace", Atom{Key: "source_namespace", Value: "foo"}, true),
	Entry("source_port invalid", Atom{Key: "source_port", Value: "-1"}, false),
	Entry("source_port", Atom{Key: "source_port", Value: "1234"}, true),
	Entry("time invalid", Atom{Key: "time", Value: "-1"}, false),
	Entry("time", Atom{Key: "time", Value: "1234567890"}, true),
	Entry("type alert", Atom{Key: "type", Value: "alert"}, true),
	Entry("type anomaly_detection_job", Atom{Key: "type", Value: "anomaly_detection_job"}, true),
	Entry("type deep_packet_inspection", Atom{Key: "type", Value: "deep_packet_inspection"}, true),
	Entry("type global_alert", Atom{Key: "type", Value: "global_alert"}, true),
	Entry("type gtf_suspicious_dns_query", Atom{Key: "type", Value: "gtf_suspicious_dns_query"}, true),
	Entry("type gtf_suspicious_flow", Atom{Key: "type", Value: "gtf_suspicious_flow"}, true),
	Entry("type invalid", Atom{Key: "type", Value: "invalid"}, false),
	Entry("type runtime_security", Atom{Key: "type", Value: "runtime_security"}, true),
	Entry("type suspicious_dns_query", Atom{Key: "type", Value: "suspicious_dns_query"}, true),
	Entry("type suspicious_flow", Atom{Key: "type", Value: "suspicious_flow"}, true),
)
