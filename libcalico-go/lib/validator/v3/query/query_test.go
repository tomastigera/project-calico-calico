// Copyright (c) 2019 Tigera, Inc. All rights reserved.

package query

import (
	"github.com/alecthomas/participle"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = DescribeTable("Atom",
	func(input, expected string, ok bool) {
		atom := &Atom{}
		parser := participle.MustBuild(atom)
		err := parser.ParseString(input, atom)

		if !ok {
			Expect(err).Should(HaveOccurred())
		} else {
			Expect(err).ShouldNot(HaveOccurred())
			actual := atom.String()
			Expect(actual).Should(Equal(expected))
		}
	},
	Entry("a = b", "a = b", "a = b", true),
	Entry("a != b", "a != b", "a != b", true),
	Entry("a > b", "a > b", "a > b", true),
	Entry("a >= b", "a >= b", "a >= b", true),
	Entry("a < b", "a < b", "a < b", true),
	Entry("a <= b", "a <= b", "a <= b", true),

	Entry(`"a" = "b"`, `"a" = "b"`, "a = b", true),
	Entry("a = ", "a = ", "", false),
	Entry("a = b.c", "a = b.c", "", false),
	Entry("a.b = c", "a.b = c", "", false),
	Entry("a.b = b.c", "a.b = b.c", "", false),
	Entry(`"a.b" = "b.c"`, `"a.b" = "b.c"`, `"a.b" = "b.c"`, true),
	Entry(`"a.b""" = "b.c"`, `"a.b"" = "b.c"`, "", false),

	Entry("a = 0", "a = 0", `a = "0"`, true),
	Entry("a = 0.1", "a = 0.1", `a = "0.1"`, true),
)

var _ = DescribeTable("In", func(input, expected string, ok bool) {
	set := &SetOpTerm{}
	parser := participle.MustBuild(set)
	err := parser.ParseString(input, set)

	if !ok {
		Expect(err).Should(HaveOccurred())
	} else {
		Expect(err).ShouldNot(HaveOccurred())
		actual := set.String()
		Expect(actual).Should(Equal(expected))
	}
},
	Entry("a IN {b}", "a IN {b}", "a IN {b}", true),
	Entry("a IN {b, c}", "a IN {b, c}", "a IN {b, c}", true),
	Entry(`a IN {"b*", "?c"}`, `a IN {"b*", "?c"}`, "a IN {b*, ?c}", true),
	Entry("a NOTIN {b}", "a NOTIN {b}", "a NOTIN {b}", true),
	Entry("a NOTIN {b, c}", "a NOTIN {b, c}", "a NOTIN {b, c}", true),
	Entry(`a NOTIN {"b*", "?c"}`, `a NOTIN {"b*", "?c"}`, "a NOTIN {b*, ?c}", true),

	Entry("a IN {}", "a IN {}", "a IN {}", false),
	Entry("a IN {,}", "a IN {,}", "a IN {,}", false),
	Entry("a IN {b,,}", "a IN {b,,}", "a IN {b,,}", false),
	Entry("a IN {b, c", "a IN {b, c", "a IN {b, c", false),
	Entry("a IN b, c}", "a IN b, c}", "a IN b, c}", false),
	Entry("a IN b, c", "a IN b, c", "a IN b, c", false),
	Entry("a IN {b,}", "a IN {b,}", "a IN {b,}", false),
	Entry("a IN {b*, ?c}", "a IN {b*, ?c}", "a IN {b*, ?c}", false),
	Entry("a NOTIN {}", "a NOTIN {}", "a NOTIN {}", false),
	Entry("a NOTIN {,}", "a NOTIN {,}", "a NOTIN {,}", false),
	Entry("a NOTIN {b,,}", "a NOTIN {b,,}", "a NOTIN {b,,}", false),
	Entry("a NOTIN {b, c", "a NOTIN {b, c", "a NOTIN {b, c", false),
	Entry("a NOTIN b, c}", "a NOTIN b, c}", "a NOTIN b, c}", false),
	Entry("a NOTIN b, c", "a NOTIN b, c", "a NOTIN b, c", false),
	Entry("a NOTIN {b,}", "a NOTIN {b,}", "a NOTIN {b,}", false),
	Entry("a NOTIN {b*, ?c}", "a NOTIN {b*, ?c}", "a NOTIN {b*, ?c}", false),
)

var _ = DescribeTable("Query", func(input, expected string, ok bool) {
	actual, err := ParseQuery(input)

	if !ok {
		Expect(err).Should(HaveOccurred())
	} else {
		Expect(err).ShouldNot(HaveOccurred())
		Expect(actual.String()).Should(Equal(expected))
	}
},
	Entry(`a = b`,
		`a = b`,
		`a = b`,
		true),
	Entry(`a = b AND b = c`,
		`a = b AND b = c`,
		`a = b AND b = c`,
		true),
	Entry(`a = b OR b = c`,
		`a = b OR b = c`,
		`a = b OR b = c`,
		true),
	Entry(`NOT a = b`,
		`NOT a = b`,
		`NOT a = b`,
		true),
	Entry(`a = b AND NOT b = c`,
		`a = b AND NOT b = c`,
		`a = b AND NOT b = c`,
		true),
	Entry(`a = b AND (NOT b = c)`,
		`a = b AND (NOT b = c)`,
		`a = b AND (NOT b = c)`,
		true),
	Entry(`a = b AND (b = c OR NOT d = e)`,
		`a = b AND (b = c OR NOT d = e)`,
		`a = b AND (b = c OR NOT d = e)`,
		true),
	Entry(`(a = b AND b = c) OR d = e`,
		`(a = b AND b = c) OR d = e`,
		`(a = b AND b = c) OR d = e`,
		true),
	Entry(`(a = b AND b = c) OR "d.e" = "e.f"`,
		`(a = b AND b = c) OR "d.e" = "e.f"`,
		`(a = b AND b = c) OR "d.e" = "e.f"`,
		true),

	Entry(`a IN {b, "*c", "d?"}`,
		`a IN {b, "*c", "d?"}`,
		`a IN {b, *c, d?}`,
		true),
	Entry(`a = b AND b = c AND c IN {d, "*e", "f?"}`,
		`a = b AND b = c AND c IN {d, "*e", "f?"}`,
		`a = b AND b = c AND c IN {d, *e, f?}`,
		true),
	Entry(`a = b OR b = c OR c IN {d, "*e", "f?"}`,
		`a = b OR b = c OR c IN {d, "*e", "f?"}`,
		`a = b OR b = c OR c IN {d, *e, f?}`,
		true),
	Entry(`NOT a IN {b, "*c", "d?"}`,
		`NOT a IN {b, "*c", "d?"}`,
		`NOT a IN {b, *c, d?}`,
		true),
	Entry(`a = b AND NOT c IN {d, "*e", "f?"}`,
		`a = b AND NOT c IN {d, "*e", "f?"}`,
		`a = b AND NOT c IN {d, *e, f?}`,
		true),
	Entry(`a = b AND (NOT c IN {d, "*e", "f?"})`,
		`a = b AND (NOT c IN {d, "*e", "f?"})`,
		`a = b AND (NOT c IN {d, *e, f?})`,
		true),
	Entry(`a = b AND (b = c OR NOT c = d OR d IN {e, "*f", "g?"})`,
		`a = b AND (b = c OR NOT c = d OR d IN {e, "*f", "g?"})`,
		`a = b AND (b = c OR NOT c = d OR d IN {e, *f, g?})`,
		true),
	Entry(`(a = b AND b = c AND c IN {d, "*e", "f?"}) OR d = e`,
		`(a = b AND b = c AND c IN {d, "*e", "f?"}) OR d = e`,
		`(a = b AND b = c AND c IN {d, *e, f?}) OR d = e`,
		true),

	Entry(`a NOTIN {b, "*c", "d?"}`,
		`a NOTIN {b, "*c", "d?"}`,
		`a NOTIN {b, *c, d?}`,
		true),
	Entry(`a = b AND b = c AND c NOTIN {d, "*e", "f?"}`,
		`a = b AND b = c AND c NOTIN {d, "*e", "f?"}`,
		`a = b AND b = c AND c NOTIN {d, *e, f?}`,
		true),
	Entry(`a = b OR b = c OR c NOTIN {d, "*e", "f?"}`,
		`a = b OR b = c OR c NOTIN {d, "*e", "f?"}`,
		`a = b OR b = c OR c NOTIN {d, *e, f?}`,
		true),
	Entry(`a NOTIN {b, "*c", "d?"}`,
		`a NOTIN {b, "*c", "d?"}`,
		`a NOTIN {b, *c, d?}`,
		true),
	Entry(`NOT a NOTIN {b, "*c", "d?"}`,
		`NOT a NOTIN {b, "*c", "d?"}`,
		`NOT a NOTIN {b, *c, d?}`,
		true),
	Entry(`a = b AND NOT c NOTIN {d, "*e", "f?"}`,
		`a = b AND NOT c NOTIN {d, "*e", "f?"}`,
		`a = b AND NOT c NOTIN {d, *e, f?}`,
		true),
	Entry(`a = b AND (NOT c NOTIN {d, "*e", "f?"})`,
		`a = b AND (NOT c NOTIN {d, "*e", "f?"})`,
		`a = b AND (NOT c NOTIN {d, *e, f?})`,
		true),
	Entry(`a = b AND (b = c OR NOT c = d OR d NOTIN {e, "*f", "g?"})`,
		`a = b AND (b = c OR NOT c = d OR d NOTIN {e, "*f", "g?"})`,
		`a = b AND (b = c OR NOT c = d OR d NOTIN {e, *f, g?})`,
		true),
	Entry(`(a = b AND b = c AND c NOTIN {d, "*e", "f?"}) OR d = e`,
		`(a = b AND b = c AND c NOTIN {d, "*e", "f?"}) OR d = e`,
		`(a = b AND b = c AND c NOTIN {d, *e, f?}) OR d = e`,
		true),

	Entry(`a IN NOT {b, "*c", "d?"}`,
		`a IN NOT {b, "*c", "d?"}`,
		`a IN NOT {b, *c, d?}`,
		false),
	Entry(`a NOTIN NOT {b, "*c", "d?"}`,
		`a NOTIN NOT {b, "*c", "d?"}`,
		`a NOTIN NOT {b, *c, d?}`,
		false),

	Entry(`a EMPTY`,
		`a EMPTY`,
		`a EMPTY`,
		true),
	Entry(`NOT a EMPTY`,
		`NOT a EMPTY`,
		`NOT a EMPTY`,
		true),
)
