package report

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/projectcalico/calico/compliance/pkg/api"
)

var _ = Describe("ArchivedReportData.UID", func() {
	It("should generate the same UID for a given input", func() {
		// If this test should ever fail it probably means someone changed how we generate UIDs

		Expect(getUID("someReportName", 111309193)).To(Equal("someReportName_someReportNameType_65589e0e-3d01-5692-bcf6-ec1a2bbc15f2"))
		Expect(getUID("someReportName", 832915464)).To(Equal("someReportName_someReportNameType_c55cb8bc-1b9c-5d1b-ac07-d1beeb9b5d15"))
		Expect(getUID("aDifferentReportName", 1000458854)).To(Equal("aDifferentReportName_aDifferentReportNameType_9c9d8355-1ad4-57c7-8d76-4bdca2296c2c"))
	})
})

func getUID(name string, seconds int64) string {
	t := time.Unix(seconds, 0o000).In(time.UTC)

	rd := v3.ReportData{
		ReportName:     name,
		ReportTypeName: name + "Type",
		StartTime:      v1.NewTime(t),
		EndTime:        v1.NewTime(t),
	}
	ard := api.NewArchivedReport(&rd, "UI Summary")
	return ard.UID()
}
