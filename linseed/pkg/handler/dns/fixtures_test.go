// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package dns

import (
	"github.com/gopacket/gopacket/layers"

	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

const dummyURL = "anyURL"

var (
	noDNSLogs []v1.DNSLog
	dnsLogs   = []v1.DNSLog{
		{
			QName:  "srv.namespace.svc.cluster.local",
			QClass: v1.DNSClass(layers.DNSClassIN),
			QType:  v1.DNSType(layers.DNSTypeA),
			RCode:  v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
		},
		{
			QName:  "srv.namespace.svc.cluster.local",
			QClass: v1.DNSClass(layers.DNSClassIN),
			QType:  v1.DNSType(layers.DNSTypeA),
			RCode:  v1.DNSResponseCode(layers.DNSResponseCodeNoErr),
		},
	}
)

var bulkResponseSuccess = &v1.BulkResponse{
	Total:     2,
	Succeeded: 2,
	Failed:    0,
}

var bulkResponsePartialSuccess = &v1.BulkResponse{
	Total:     2,
	Succeeded: 1,
	Failed:    1,
	Errors: []v1.BulkError{
		{
			Resource: "res",
			Type:     "index error",
			Reason:   "I couldn't do it",
		},
	},
}
