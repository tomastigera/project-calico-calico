//go:build coraza.rule.multiphase_evaluation

package transaction_test

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
