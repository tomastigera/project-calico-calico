// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Common", func() {
	DescribeTable("Regexp",
		func(re string, input Atom, ok bool) {
			v := RegexpValidator(re)
			actual := input
			err := v(&actual)
			if ok {
				Expect(err).ShouldNot(HaveOccurred())
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("exact match", "foo", Atom{Value: "foo"}, true),
		Entry("no match", "foo", Atom{Value: "bar"}, false),
		Entry("prefix match", "foo", Atom{Value: "foobar"}, true),
		Entry("suffix match", "bar", Atom{Value: "foobar"}, true),
	)

	DescribeTable("Set",
		func(set []string, input Atom, ok bool) {
			v := SetValidator(set...)
			actual := input
			err := v(&actual)
			if ok {
				Expect(err).ShouldNot(HaveOccurred())
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("in set", []string{"foo", "bar"}, Atom{Value: "foo"}, true),
		Entry("not in set", []string{"foo", "bar"}, Atom{Value: "baz"}, false),
	)

	DescribeTable("Date",
		func(input Atom, expected string, ok bool) {
			actual := input
			err := DateValidator(&actual)

			if ok {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(actual.Value).Should(Equal(expected))
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("empty string", Atom{Value: ""}, "", false),
		Entry("invalid input", Atom{Value: "abc"}, "", false),
		Entry("date", Atom{Value: "2015-01-02"}, "2015-01-02", true),
		Entry("invalid month", Atom{Value: "2015-13-01"}, "", false),
		Entry("invalid day", Atom{Value: "2015-09-31"}, "", false),
		Entry("date and time", Atom{Value: "2015-01-02 12:10:30"}, "2015-01-02 12:10:30", true),
		Entry("RFC3339 UTC", Atom{Value: "2019-10-07T14:25:00Z"}, "2019-10-07 14:25:00", true),
		Entry("RFC3339 with zone", Atom{Value: "2019-10-07T14:25:00-01:00"}, "2019-10-07 15:25:00", true),
	)

	DescribeTable("Domain",
		func(input Atom, expected string, ok bool) {
			actual := input
			err := DomainValidator(&actual)
			if ok {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(actual.Value).Should(Equal(expected))
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("lower case", Atom{Value: "foo"}, "foo", true),
		Entry("mixed case", Atom{Value: "foO"}, "foo", true),
		Entry("trailing dot", Atom{Value: "foo."}, "foo", true),
		Entry("leading dot", Atom{Value: ".foo"}, "foo", true),
		Entry("intermediate multiple dots", Atom{Value: "foo..bar"}, "foo.bar", true),
		Entry("mixed case unicode", Atom{Value: "Àfoo"}, "àfoo", true),
		Entry("punycode", Atom{Value: "xn--foo-8ka"}, "àfoo", true),
	)

	DescribeTable("URL",
		func(input Atom, expected string, ok bool) {
			actual := input
			err := URLValidator(&actual)
			if ok {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(actual.Value).Should(Equal(expected))
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("a valid url", Atom{Value: "/api/v1/namespaces/calico-monitoring/endpoints/calico-node-alertmanager"}, "/api/v1/namespaces/calico-monitoring/endpoints/calico-node-alertmanager", true),
	)

	DescribeTable("IP",
		func(input Atom, expected string, ok bool) {
			actual := input
			err := IPValidator(&actual)
			if ok {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(actual.Value).Should(Equal(expected))
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("invalid", Atom{Value: "foo"}, "", false),
		Entry("ipv4", Atom{Value: "127.0.0.1"}, "127.0.0.1", true),
		Entry("ipv6", Atom{Value: "::1"}, "::1", true),
		Entry("ipv6 with leading zeroes", Atom{Value: "0::1"}, "::1", true),
		Entry("invalid ipv6", Atom{Value: "invalid::1"}, "", false),
		Entry("=", Atom{Comparator: CmpEqual, Value: "127.0.0.1"}, "127.0.0.1", true),
		Entry("!=", Atom{Comparator: CmpNotEqual, Value: "127.0.0.1"}, "127.0.0.1", true),
		Entry("<", Atom{Comparator: CmpLt, Value: "127.0.0.1"}, "127.0.0.1", true),
		Entry("<=", Atom{Comparator: CmpLte, Value: "127.0.0.1"}, "127.0.0.1", true),
		Entry(">", Atom{Comparator: CmpGt, Value: "127.0.0.1"}, "127.0.0.1", true),
		Entry(">=", Atom{Comparator: CmpGte, Value: "127.0.0.1"}, "127.0.0.1", true),
		Entry("ipv4 cidr with overlap", Atom{Value: "127.0.0.1/8"}, "127.0.0.0/8", true),
		Entry("ipv6 cidr", Atom{Value: "abc::/64"}, "abc::/64", true),
		Entry("ipv6 cidr with leading zero", Atom{Value: "0abc::/64"}, "abc::/64", true),
		Entry("ipv6 cidr with overlap", Atom{Value: "0abc::1/64"}, "abc::/64", true),
	)

	DescribeTable("IntRange",
		func(low, high int, input Atom, expected string, ok bool) {
			v := IntRangeValidator(int64(low), int64(high))

			actual := input
			err := v(&actual)
			if ok {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(actual.Value).Should(Equal(expected))
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("not an int", 0, 100, Atom{Value: "foo"}, "", false),
		Entry("start of range", 0, 100, Atom{Value: "0"}, "0", true),
		Entry("end of range", 0, 100, Atom{Value: "100"}, "100", true),
		Entry("below range", 0, 100, Atom{Value: "-1"}, "", false),
		Entry("above range", 0, 100, Atom{Value: "101"}, "", false),
	)

	DescribeTable("PositiveInt",
		func(input Atom, expected string, ok bool) {
			actual := input
			err := PositiveIntValidator(&actual)
			if ok {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(actual.Value).Should(Equal(expected))
			} else {
				Expect(err).Should(HaveOccurred())
			}
		},
		Entry("not an int", Atom{Value: "foo"}, "", false),
		Entry("0", Atom{Value: "0"}, "0", true),
		Entry("positive", Atom{Value: "100"}, "100", true),
		Entry("negative", Atom{Value: "-1"}, "", false),
	)
})
