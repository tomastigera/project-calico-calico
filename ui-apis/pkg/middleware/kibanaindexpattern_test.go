package middleware

import (
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Test extracting resource from kibana request", func() {

	DescribeTable("successful extraction",
		func(indexPattern string, expectSuccess bool, expectedFlow string) {

			body := strings.ReplaceAll(kibanaReqBody, "{{.IndexPatternTitle}}", indexPattern)
			bodyReader := strings.NewReader(body)
			req, err := http.NewRequest("POST", ".kibana/_search", bodyReader)
			Expect(err).NotTo(HaveOccurred())

			resultFlow, err := getResourceNameFromKibanaIndexPattern(req)

			if expectSuccess {
				Expect(err).NotTo(HaveOccurred())
				Expect(resultFlow).To(Equal(expectedFlow))
			} else {
				Expect(err).To(HaveOccurred())
			}
		},
		Entry("flows", "tigera_secure_ee_flows", true, "flows"),
		Entry("audit_*", "tigera_secure_ee_audit_*", true, "audit*"),
		Entry("audit*", "tigera_secure_ee_audit*", true, "audit*"),
		Entry("audit_ee", "tigera_secure_ee_audit_ee", true, "audit_ee"),
		Entry("audit_kube", "tigera_secure_ee_audit_kube", true, "audit_kube"),
		Entry("events", "tigera_secure_ee_events", true, "events"),
		Entry("dns*", "tigera_secure_ee_dns*", true, "dns"),
		Entry("fakeindex", "fakeindex", false, ""),
		Entry("badjson", "\"{}", false, ""),
	)

})

const kibanaReqBody = `{"query": { "bool": {	"filter": [{ "match": {	"index-pattern.title": "{{.IndexPatternTitle}}" } }] } } }`
