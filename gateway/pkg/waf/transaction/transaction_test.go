// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package transaction_test

// WARNING this file requires the build tag 'coraza.rule.multiphase_evaluation' to be set.
// This is because the test uses the Coraza ruleset which requires multiphase evaluation to be enabled.
//
// If you are running into failures on this test, make sure to run it with the correct build tag. (see Makefile for details)
// If someone removed the build tag from Makefile or any steps that involve this test, this test will fail to compile.

import (
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"

	"github.com/projectcalico/calico/gateway/pkg/waf"
	"github.com/projectcalico/calico/gateway/pkg/waf/transaction"
)

func TestNewTransactionWrapper(t *testing.T) {
	cfg := coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS)

	for _, directive := range waf.DefaultDirectives {
		cfg = cfg.WithDirectives(directive)
	}
	cfg = cfg.WithDirectives("SecRuleEngine On")

	instance, err := coraza.NewWAF(cfg)
	if err != nil {
		t.Fatalf("Failed to create WAF instance: %v", err)
		return
	}
	opts := []transaction.TransactionOption{
		transaction.WithHost("example.com"),
		transaction.WithConnectionDetails(
			"93.172.0.2", "127.0.0.1",
			55550, 80,
		),
		transaction.WithURI("/test/path", "GET", "HTTP/1.1"),
		transaction.WithHeaders(map[string]string{
			"User-Agent": "arachni",
		}),
	}
	txw := transaction.NewTransaction(instance, "test-request-id", opts...)

	// verify early blocking works by processing headers that will trigger an interruption
	if it, status, msg := txw.ProcessRequestHeaders(); it == nil {
		t.Fatal("Expected ProcessRequestHeaders to return an interruption, got nil")
	} else {
		if status != 403 {
			t.Errorf("Expected status code 403, got %d", status)
		}
		if !strings.Contains(msg, "deny (403)") {
			t.Errorf("Expected message 'WAF rule 1 interrupting request: deny (403)', got '%s'", msg)
		}
	}
}
