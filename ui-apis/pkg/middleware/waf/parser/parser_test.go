// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package parser

import (
	_ "embed"
	"encoding/json"
	"io/fs"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
)

//go:embed testdata/simple_testdata.conf
var simple_testdata string

//go:embed testdata/simple_testdata_parsed.json
var simple_parsed []byte

var _ = Describe("Waf Ruleset Parser Test", func() {

	It("Parse simple ruleset testdata file", func() {
		rules, err := Parse(simple_testdata)
		Expect(err).To(BeNil())

		Expect(rules).To(Not(BeNil()))

		jsonData, err := json.MarshalIndent(rules, "", "    ")
		Expect(err).To(BeNil())

		format.TruncatedDiff = false
		format.MaxLength = 0
		Expect(jsonData).To(MatchJSON(simple_parsed))
	})

	Describe("Parse sample coreruleset file", func() {
		ruleFile, err := fs.ReadFile(coreruleset.FS, "@owasp_crs/REQUEST-921-PROTOCOL-ATTACK.conf")
		Expect(err).To(BeNil())

		rules, err := Parse(string(ruleFile))
		Expect(err).To(BeNil())

		Expect(rules).To(Not(BeNil()))

		It("the file is not empty", func() {
			Expect(len(rules)).To(BeNumerically(">", 0))
		})

		It("SecMarker at end of file", func() {
			lastRule := rules[len(rules)-1]
			Expect(lastRule.SecRule).To(Equal("SecMarker"))
			Expect(lastRule.Id).To(Equal(""))
			Expect(lastRule.Variables).To(Equal(`"END-REQUEST-921-PROTOCOL-ATTACK"`))
		})

		It("single line SecRule", func() {
			var rule *Rule
			for i := range rules {
				if rules[i].Id == "921018" {
					rule = &rules[i]
					break
				}
			}
			Expect(rule).NotTo(BeNil(), "Rule 921018 not found")
			Expect(rule.SecRule).To(Equal("SecRule"))
			Expect(rule.Variables).To(Equal("TX:DETECTION_PARANOIA_LEVEL"))
			Expect(rule.Message).To(Equal(""))
			// Single-line rules don't contain line continuations
			Expect(rule.Raw).NotTo(ContainSubstring("\\\n"))
			Expect(rule.Raw).To(ContainSubstring("id:921018"))
		})

		It("multi-line SecRule", func() {
			var rule *Rule
			for i := range rules {
				if rules[i].Id == "921220" {
					rule = &rules[i]
					break
				}
			}
			Expect(rule).NotTo(BeNil(), "Rule 921220 not found")
			Expect(rule.SecRule).To(Equal("SecRule"))
			Expect(rule.Message).To(Equal("HTTP Parameter Pollution possible via array notation"))
			// Multi-line rules contain line continuations
			Expect(rule.Raw).To(ContainSubstring("\\\n"))
			Expect(rule.Raw).To(ContainSubstring("id:921220"))
			Expect(rule.Raw).To(ContainSubstring("severity:'CRITICAL'"))
		})

	})
})
