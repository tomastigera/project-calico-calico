// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package report

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	reportNameEnv  = "TIGERA_COMPLIANCE_REPORT_NAME"
	reportStartEnv = "TIGERA_COMPLIANCE_REPORT_START_TIME"
	reportEndEnv   = "TIGERA_COMPLIANCE_REPORT_END_TIME"
)

var (
	now         = time.Now()
	nowPlusHour = now.Add(time.Hour)
	reportName  = "my-report"
	start       = now.Format(time.RFC3339)
	end         = nowPlusHour.Format(time.RFC3339)
)

var _ = Describe("Load config from environments", func() {
	It("should parse valid configuration", func() {
		By("parsing with valid config")
		_ = os.Setenv(reportNameEnv, reportName)
		_ = os.Setenv(reportStartEnv, start)
		_ = os.Setenv(reportEndEnv, end)

		By("validating the environments parsed correct")
		cfg := mustReadReportConfigFromEnv()
		Expect(cfg).ToNot(BeNil())
		Expect(cfg.ReportName).To(Equal(reportName))
		Expect(cfg.ParsedReportStart.Unix()).To(Equal(now.Unix()))
		Expect(cfg.ParsedReportEnd.Unix()).To(Equal(nowPlusHour.Unix()))
	})

	It("should error with missing configuration", func() {
		By("parsing with no config")
		_ = os.Unsetenv(reportNameEnv)
		Expect(func() { _ = mustReadReportConfigFromEnv() }).To(Panic())
	})
})
