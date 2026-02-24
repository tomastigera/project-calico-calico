package mocks

import (
	"fmt"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/compliance/pkg/api"
	v1 "github.com/projectcalico/calico/linseed/pkg/apis/v1"
)

type MockReportRetriever struct{}

func (c *MockReportRetriever) RetrieveArchivedReport(id string) (*v1.ReportData, error) {
	rd := apiv3.ReportData{}
	rd.ReportName = "Report0"
	rd.ReportSpec = apiv3.ReportSpec{ReportType: "inventory"}
	rd.StartTime = metav1.Now()
	rd.EndTime = metav1.Now()

	rd.ReportSpec.Endpoints.Selector = "EP_selector"

	rd.ReportSpec.Endpoints.Namespaces = &apiv3.NamesAndLabelsMatch{Selector: "NS_selector"}
	rd.ReportSpec.Endpoints.ServiceAccounts = &apiv3.NamesAndLabelsMatch{Selector: "SA_selector"}

	r := api.NewArchivedReport(&rd, "UI summary 0")

	return r, nil
}

func (c *MockReportRetriever) RetrieveArchivedReportSummaries() ([]*v1.ReportData, error) {
	rl := make([]*v1.ReportData, 5)

	for i := range 5 {
		rd := apiv3.ReportData{}
		rd.ReportName = fmt.Sprintf("Report%d", i)
		rd.ReportSpec = apiv3.ReportSpec{ReportType: "inventory"}
		rd.StartTime = metav1.Now()
		rd.EndTime = metav1.Now()
		r := api.NewArchivedReport(&rd, fmt.Sprintf("UI summary %d", i))
		rl[i] = r
	}

	return rl, nil
}
