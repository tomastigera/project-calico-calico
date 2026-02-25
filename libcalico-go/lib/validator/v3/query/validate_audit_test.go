// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Audit",
	func(atom Atom, ok bool) {
		actual := atom
		err := IsValidAuditAtom(&actual)
		if ok {
			Expect(err).ShouldNot(HaveOccurred())
		} else {
			Expect(err).Should(HaveOccurred())
		}
	},
	Entry("apiVersion", Atom{Key: "apiVersion", Value: "abc"}, true),
	Entry("auditID", Atom{Key: "auditID", Value: "abc"}, true),
	Entry("kind", Atom{Key: "kind", Value: "abc"}, true),
	Entry("level=None", Atom{Key: "level", Value: "None"}, true),
	Entry("level=Metadata", Atom{Key: "level", Value: "Metadata"}, true),
	Entry("level=Request", Atom{Key: "level", Value: "Request"}, true),
	Entry("level=RequestResponse", Atom{Key: "level", Value: "RequestResponse"}, true),
	Entry("level invalid", Atom{Key: "level", Value: "abc"}, false),
	Entry("metadata", Atom{Key: "metadata", Value: "abc"}, false),
	Entry("name", Atom{Key: "name", Value: "abc"}, true),
	Entry("objectRef parent", Atom{Key: "objectRef", Value: "abc"}, false),
	Entry("objectRef.apiGroup", Atom{Key: "objectRef.apiGroup", Value: "abc"}, true),
	Entry("objectRef.apiVersion", Atom{Key: "objectRef.apiVersion", Value: "abc"}, true),
	Entry("objectRef.name", Atom{Key: "objectRef.name", Value: "abc"}, true),
	Entry("objectRef.resource", Atom{Key: "objectRef.resource", Value: "abc"}, true),
	Entry("objectRef.namespace", Atom{Key: "objectRef.namespace", Value: "abc"}, true),
	Entry("requestObject", Atom{Key: "requestObject", Value: "abc"}, false),
	Entry("requestReceivedTimestamp", Atom{Key: "requestReceivedTimestamp", Value: "2019-01-01 10:00:00"}, true),
	Entry("requestURI", Atom{Key: "requestURI", Value: "/v1/foo/bar"}, true),
	Entry("responseObject parent", Atom{Key: "responseObject", Value: "abc"}, false),
	Entry("responseObject.apiVersion", Atom{Key: "responseObject.apiVersion", Value: "abc"}, true),
	Entry("responseObject.kind", Atom{Key: "responseObject.kind", Value: "abc"}, true),
	Entry("responseObject.metadata", Atom{Key: "responseObject.metadata", Value: "abc"}, false),
	Entry("responseObject.spec", Atom{Key: "responseObject.spec", Value: "abc"}, false),
	Entry("responseObject.status", Atom{Key: "responseObject.status", Value: "abc"}, false),
	Entry("responseStatus parent", Atom{Key: "responseStatus", Value: "abc"}, false),
	Entry("responseStatus.code<100", Atom{Key: "responseStatus.code", Value: "99"}, false),
	Entry("responseStatus.code=100", Atom{Key: "responseStatus.code", Value: "100"}, true),
	Entry("responseStatus.code=599", Atom{Key: "responseStatus.code", Value: "599"}, true),
	Entry("responseStatus.code>=600", Atom{Key: "responseStatus.code", Value: "600"}, false),
	Entry("responseStatus.code invalid", Atom{Key: "responseStatus.code", Value: "abc"}, false),
	Entry("responseStatus.metadata", Atom{Key: "responseStatus.metadata", Value: "abc"}, false),
	Entry("sourceIPs ipv4", Atom{Key: "sourceIPs", Value: "127.0.0.1"}, true),
	Entry("sourceIPs invalid", Atom{Key: "sourceIPs", Value: "abc"}, false),
	Entry("stage=RequestReceived", Atom{Key: "stage", Value: "RequestReceived"}, true),
	Entry("stage=ResponseStarted", Atom{Key: "stage", Value: "ResponseStarted"}, true),
	Entry("stage=ResponseComplete", Atom{Key: "stage", Value: "ResponseComplete"}, true),
	Entry("stage=Panic", Atom{Key: "stage", Value: "Panic"}, true),
	Entry("stage invalid", Atom{Key: "stage", Value: "abc"}, false),
	Entry("timestamp", Atom{Key: "timestamp", Value: "2019-01-01 10:00:00"}, true),
	Entry("user", Atom{Key: "user", Value: "abc"}, false),
	Entry("user.groups", Atom{Key: "user.groups", Value: "abc"}, true),
	Entry("user.username", Atom{Key: "user.username", Value: "abc"}, true),
	Entry("verb=get", Atom{Key: "verb", Value: "get"}, true),
	Entry("verb=list", Atom{Key: "verb", Value: "list"}, true),
	Entry("verb=watch", Atom{Key: "verb", Value: "watch"}, true),
	Entry("verb=create", Atom{Key: "verb", Value: "create"}, true),
	Entry("verb=update", Atom{Key: "verb", Value: "update"}, true),
	Entry("verb=patch", Atom{Key: "verb", Value: "patch"}, true),
	Entry("verb=delete", Atom{Key: "verb", Value: "delete"}, true),
	Entry("verb invalid", Atom{Key: "verb", Value: "abc"}, false),
	Entry("invalid field", Atom{Key: "fake_field", Value: "abc"}, false),
)
