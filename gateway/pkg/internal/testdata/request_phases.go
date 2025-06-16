package testdata

import (
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/projectcalico/calico/gateway/pkg/internal/testutils"
	"github.com/projectcalico/calico/gateway/pkg/internal/utils"
)

type NamedTestCase struct {
	Name                  string
	RequestBuilderOptions []testutils.ProcessingRequestBuilderOption
	ExpectedResponse      *envoy_service_proc_v3.ProcessingResponse
	ExtraDirectives       []string
	NumExpectedWAFEvents  int
}

var PhasesTestCases = []NamedTestCase{
	{
		Name:                  "inert request",
		RequestBuilderOptions: []testutils.ProcessingRequestBuilderOption{},
		ExpectedResponse:      &envoy_service_proc_v3.ProcessingResponse{},
	},
	{
		Name: "PHASE 1: request with banned bot headers",
		RequestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"User-Agent": "arachni/5.0 - https://github.com/Arachni/arachni",
			}),
		},
		ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
		},
	},
	{
		Name: "PHASE 1+2: request with SQLi payload",
		RequestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
			}),
			testutils.WithPath("/search?q=1%27+OR+1%3D1--"),
			testutils.WithRequestBody([]byte("search=1' OR 1=1--")),
		},
		ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
		},
	},
	{
		Name: "PHASE 2: request with 'badword' in request body",
		RequestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}),
			testutils.WithRequestBody([]byte("data=badword")),
		},
		ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 100001 interrupting request: deny (403)")),
		},
	},
	{
		Name: "PHASE 3: response headers with suspicious content",
		RequestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithResponseHeaders(map[string]string{
				"Content-Type": "text/html",
				"Server":       "Apache/2.4.41 (Ubuntu)",
			}),
		},
		ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 100002 interrupting request: deny (403)")),
		},
	},
	{
		Name: "PHASE 4: response with r57 shell webshell",
		RequestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}),
			testutils.WithResponseBody([]byte("<title>r57 shell</title>")),
		},
		ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 959100 interrupting request: deny (403)")),
		},
	},
	{
		Name: "ALL: combination of all bad stuff above should stop at phase 1 thus will only return the first interruption",
		RequestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"User-Agent": "arachni/5.0 - https://github.com/Arachni/arachni",
			}),
			testutils.WithPath("/search?q=1%27+OR+1%3D1--"),
			testutils.WithRequestHeaders(map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}),
			testutils.WithRequestBody([]byte("search=1' OR 1=1--")),
			testutils.WithResponseHeaders(map[string]string{
				"Content-Type": "text/html",
				"Server":       "Apache/2.4.41 (Ubuntu)",
			}),
			testutils.WithResponseBody([]byte("<title>r57 shell</title>")),
		},
		ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
		},
	},
}
