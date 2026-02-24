// Copyright (c) 2018 Tigera, Inc. All rights reserved.

package ipsec_test

import (
	"fmt"
	"os"
	"path"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/ipsec"
)

var _ = DescribeTable("config tree rendering tests",
	func(items map[string]string, expected string) {
		tree := NewConfigTree(items)
		result := tree.Render("", "")
		Expect(result).To(Equal(expected))
	},
	Entry("no config", map[string]string{}, ""),
	Entry("no dot notation", map[string]string{"a": "v"}, ""),
	Entry("single section", map[string]string{"a.b": "v"}, "a {\n  b = v\n}\n"),
	Entry("embedded sections",
		map[string]string{"a.b.c.d": "vd", "a.b.e.f": "vf"},
		"a {\n"+
			"  b {\n"+
			"    c {\n"+
			"      d = vd\n"+
			"    }\n"+
			"    e {\n"+
			"      f = vf\n"+
			"    }\n"+
			"  }\n"+
			"}\n"),
	Entry("parallel sections",
		map[string]string{"a.b.c.d": "vd", "e.f": "vf"},
		"a {\n"+
			"  b {\n"+
			"    c {\n"+
			"      d = vd\n"+
			"    }\n"+
			"  }\n"+
			"}\n"+
			"e {\n"+
			"  f = vf\n"+
			"}\n"),
)

var _ = DescribeTable("charon config file tests",
	func(felixLogLevel, charonLogLevel string, followRedirects, makeBeforeBreak bool) {
		yesOrNo := map[bool]string{true: "yes", false: "no"}

		//initialise main config
		mainConfig := path.Join(".", "charon.conf")
		err := os.WriteFile(mainConfig, []byte("charon {\n}\n"), 0644)
		Expect(err).NotTo(HaveOccurred())

		c := NewCharonConfig(".", "charon.conf")
		c.SetLogLevel(felixLogLevel)
		c.SetBooleanOption(CharonFollowRedirects, followRedirects)
		c.SetBooleanOption(CharonMakeBeforeBreak, makeBeforeBreak)
		c.RenderToFile()
		format := `charon {
  filelog {
    stderr {
      default = %s
    }
    stdout {
      default = %s
    }
  }
  follow_redirects = %s
  make_before_break = %s
}
`
		expected := fmt.Sprintf(format, charonLogLevel, charonLogLevel,
			yesOrNo[followRedirects],
			yesOrNo[makeBeforeBreak],
		)

		content, err := os.ReadFile(mainConfig)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(content)).To(Equal(expected))

		err = os.Remove(mainConfig)
		Expect(err).NotTo(HaveOccurred())
	},

	Entry("with no log", "none", "-1", true, true),
	Entry("log level notice", "Notice", "0", false, true),
	Entry("log level info", "INFO", "1", true, false),
	Entry("log level debug", "Debug", "2", false, false),
	Entry("log level verbose", "VERBOSE", "4", true, true),
)
