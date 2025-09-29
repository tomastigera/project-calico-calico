// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package transaction_test

import (
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/gateway/pkg/internal/testdata"
	"github.com/projectcalico/calico/gateway/pkg/internal/testutils"
	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/projectcalico/calico/gateway/pkg/waf/transaction"
)

func TestRequestHandler(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	// Create a new WAF instance
	cfg := coraza.NewWAFConfig().WithRootFS(coreruleset.FS)
	for _, directive := range waf.DefaultDirectives {
		cfg = cfg.WithDirectives(directive)
	}
	cfg = cfg.WithDirectives("SecRuleEngine On")

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

	for _, tc := range testdata.PhasesTestCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Build the request using the provided options
			req := testutils.NewProcessingRequestBuilder(tc.RequestBuilderOptions...)

			// Process the request
			resp := handler.ProcessAll(req.Values()...)

			// Check if the response matches the expected response
			assert.NotNil(t, resp, "Response should not be nil for test case: %s", tc.Name)
			assert.EqualValues(t, tc.ExpectedResponse.String(), resp.String(), "Response does not match expected response for test case: %s", tc.Name)
		})
	}
}
