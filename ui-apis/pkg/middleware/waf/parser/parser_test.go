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
			// The file contains 25 SecRule and a SecMarker
			Expect(rules).To(HaveLen(26))
		})

		It("non-SecRule reults", func() {
			Expect(rules[25].SecRule).To(Equal("SecMarker"))
			Expect(rules[25].Id).To(Equal(""))
			Expect(rules[25].Variables).To(Equal(`"END-REQUEST-921-PROTOCOL-ATTACK"`))
		})

		It("single line SecRule", func() {
			rule := rules[23]
			Expect(rule.SecRule).To(Equal("SecRule"))
			Expect(rule.Id).To(Equal("921018"))
			Expect(rule.Variables).To(Equal("TX:DETECTION_PARANOIA_LEVEL"))
			Expect(rule.Message).To(Equal(""))
			Expect(rule.Raw).To(Equal(`SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 4" "id:921018,phase:2,pass,nolog,tag:'OWASP_CRS',ver:'OWASP_CRS/4.11.0',skipAfter:END-REQUEST-921-PROTOCOL-ATTACK"`))
		})

		It("last SecRule in the file", func() {
			rule := rules[24]
			Expect(rule.Id).To(Equal("921220"))
			Expect(rule.SecRule).To(Equal("SecRule"))
			Expect(rule.Message).To(Equal("HTTP Parameter Pollution possible via array notation"))
			Expect(rule.Raw).To(Equal(`SecRule ARGS_NAMES "@rx \[" \
    "id:921220,\
    phase:2,\
    pass,\
    log,\
    msg:'HTTP Parameter Pollution possible via array notation',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-protocol',\
    tag:'paranoia-level/4',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/137/15/460',\
    ver:'OWASP_CRS/4.11.0',\
    severity:'CRITICAL',\
    setvar:'tx.http_violation_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}'"`))
		})

	})
})
