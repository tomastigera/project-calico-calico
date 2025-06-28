package service_test

import (
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	envoy_service_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	wevp "github.com/projectcalico/calico/app-policy/waf"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/gateway/pkg/internal/testdata"
	"github.com/projectcalico/calico/gateway/pkg/internal/testutils"
	"github.com/projectcalico/calico/gateway/pkg/internal/utils"
	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/projectcalico/calico/gateway/pkg/waf/service"
	"github.com/projectcalico/calico/gateway/pkg/waf/transaction"
)

func TestRequestHandlerDetectionOnly(t *testing.T) {
	log.SetLevel(log.TraceLevel)

	wafEvents := []*proto.WAFEvent{}
	logger := func(evt *proto.WAFEvent) {
		wafEvents = append(wafEvents, evt)
	}
	wafInstance := service.NewWAFServiceManager(coreruleset.FS, logger)
	wafInstance.OnUpdate(waf.DefaultDirectives)

	rbo := []testutils.ProcessingRequestBuilderOption{
		testutils.WithRequestHeaders(map[string]string{
			"User-Agent": "arachni/5.0 - https://github.com/Arachni/arachni",
		}),
	}
	for _, tc := range []testdata.NamedTestCase{
		{
			Name:                  "default, which is on",
			ExtraDirectives:       []string{},
			RequestBuilderOptions: rbo,
			ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
				Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
			},
			NumExpectedWAFEvents: 1,
		},
		{
			Name:                  "detection only",
			ExtraDirectives:       []string{"SecRuleEngine DetectionOnly"},
			RequestBuilderOptions: rbo,
			ExpectedResponse:      &envoy_service_proc_v3.ProcessingResponse{},
			NumExpectedWAFEvents:  2,
		},
		{
			Name:                  "restore on setting",
			ExtraDirectives:       []string{"SecRuleEngine On"},
			RequestBuilderOptions: rbo,
			ExpectedResponse: &envoy_service_proc_v3.ProcessingResponse{
				Response: utils.NewForbiddenResponse([]byte("WAF rule 949111 interrupting request: deny (403)")),
			},
			NumExpectedWAFEvents: 1,
		},
	} {
		upd := append(waf.DefaultDirectives, tc.ExtraDirectives...)
		wafInstance.OnUpdate(upd)
		t.Run(tc.Name, func(t *testing.T) {
			wafInstance.Read(func(instance coraza.WAF, evp *wevp.WafEventsPipeline) {
				// Create a request handler with the WAF instance and x-forwarded-for data
				handler, err := transaction.NewRequestHandler(
					instance, []string{"93.172.0.2"},
					[]func(*proto.WAFEvent, corazatypes.Transaction){evp.ProcessProtoEvent},
				)
				if err != nil {
					t.Fatalf("Failed to create request handler: %v", err)
				}

				req := testutils.NewProcessingRequestBuilder(tc.RequestBuilderOptions...)
				resp := handler.ProcessAll(req.Values()...)

				assert.NotNil(t, resp, "Response should not be nil for test case: %s", tc.Name)
				assert.EqualValues(t, tc.ExpectedResponse.String(), resp.String(), "Response does not match expected response for test case: %s", tc.Name)
				assert.Greater(t, len(wafEvents), 0, "Expected at least one WAF event to be logged")
				assert.Equal(t, tc.NumExpectedWAFEvents, len(wafEvents), "Expected exactly one WAF event to be logged")

				wafEvents = []*proto.WAFEvent{} // reset for next iteration
			})
		})
	}
}
