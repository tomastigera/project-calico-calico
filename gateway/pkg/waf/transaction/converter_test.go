package transaction_test

import (
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/gateway/pkg/internal/testutils"
	"github.com/projectcalico/calico/gateway/pkg/internal/utils"
	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/projectcalico/calico/gateway/pkg/waf/transaction"
)

type testCase struct {
	name                  string
	requestBuilderOptions []testutils.ProcessingRequestBuilderOption
	expectedResponse      *envoy_service_proc_v3.ProcessingResponse
}

var testCases = []testCase{
	{
		name:                  "inert request",
		requestBuilderOptions: []testutils.ProcessingRequestBuilderOption{},
		expectedResponse:      &envoy_service_proc_v3.ProcessingResponse{},
	},
	{
		name: "PHASE 1: request with banned bot headers",
		requestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"User-Agent": "arachni/5.0 - https://github.com/Arachni/arachni",
			}),
		},
		expectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
		},
	},
	{
		name: "PHASE 1+2: request with SQLi payload",
		requestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
			}),
			testutils.WithPath("/search?q=1%27+OR+1%3D1--"),
			testutils.WithRequestBody([]byte("search=1' OR 1=1--")),
		},
		expectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
		},
	},
	{
		name: "PHASE 2: request with 'badword' in request body",
		requestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}),
			testutils.WithRequestBody([]byte("data=badword")),
		},
		expectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 100001 interrupting request: deny (403)")),
		},
	},
	{
		name: "PHASE 3: response headers with suspicious content",
		requestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithResponseHeaders(map[string]string{
				"Content-Type": "text/html",
				"Server":       "Apache/2.4.41 (Ubuntu)",
			}),
		},
		expectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 100002 interrupting request: deny (403)")),
		},
	},
	{
		name: "PHASE 4: response with r57 shell webshell",
		requestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
			testutils.WithRequestHeaders(map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}),
			testutils.WithResponseBody([]byte("<title>r57 shell</title>")),
		},
		expectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 959100 interrupting request: deny (403)")),
		},
	},
	{
		name: "ALL: combination of all bad stuff above should stop at phase 1 thus will only return the first interruption",
		requestBuilderOptions: []testutils.ProcessingRequestBuilderOption{
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
		expectedResponse: &envoy_service_proc_v3.ProcessingResponse{
			Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
		},
	},
}

func TestRequestHandler(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	// Create a new WAF instance
	cfg := coraza.NewWAFConfig().WithRootFS(coreruleset.FS)
	for _, directive := range waf.DefaultDirectives {
		cfg = cfg.WithDirectives(directive)
	}

	// test case for badword in request body
	cfg = cfg.WithDirectives(
		`SecRule REQUEST_BODY "@contains badword" "id:100001,phase:2,deny,status:403,msg:'Blocked badword in request body'"`,
	)

	// test case for preventing application server leaks in response headers
	cfg = cfg.WithDirectives(
		`SecRule RESPONSE_HEADERS:Server "@contains Apache" "id:100002,phase:3,deny,status:403,msg:'Disallowed Server header in response'"`,
	)

	wafInstance, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("Failed to create WAF instance: %v", err)
	}

	// Create a request handler with the WAF instance and x-forwarded-for data
	handler, err := transaction.NewRequestHandler(wafInstance, []string{"93.172.0.2"}, nil)
	if err != nil {
		t.Fatalf("Failed to create request handler: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the request using the provided options
			req := testutils.NewProcessingRequestBuilder(tc.requestBuilderOptions...)

			// Process the request
			resp := handler.ProcessAll(req.Values()...)

			// Check if the response matches the expected response
			assert.NotNil(t, resp, "Response should not be nil for test case: %s", tc.name)
			assert.EqualValues(t, tc.expectedResponse.String(), resp.String(), "Response does not match expected response for test case: %s", tc.name)
		})
	}
}
