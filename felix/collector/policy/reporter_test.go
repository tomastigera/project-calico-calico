package policy

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/felix/collector/types"
	"github.com/projectcalico/calico/felix/collector/types/metric"
	"github.com/projectcalico/calico/felix/rules"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/health"
)

// MockDispatcher implements types.Reporter for testing purposes.
type MockDispatcher struct {
	mu           sync.Mutex
	ReportedLogs []any
	StartErr     error
	Started      bool
}

func (m *MockDispatcher) Report(u any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReportedLogs = append(m.ReportedLogs, u)
	return nil
}

func (m *MockDispatcher) Start() error {
	m.Started = true
	return m.StartErr
}

// Helper to safely access reported logs
func (m *MockDispatcher) GetLogs() []any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ReportedLogs
}

func TestPolicyActivityReporter_Lifecycle(t *testing.T) {
	mockDisp := &MockDispatcher{}
	dispatchers := map[string]types.Reporter{"mock": mockDisp}

	luc := calc.NewLookupsCache()

	reporter := NewReporter(luc, dispatchers, 100*time.Millisecond, health.NewHealthAggregator())

	err := reporter.Start()
	if err != nil {
		t.Fatalf("Unexpected error starting reporter: %v", err)
	}
	assert.NoError(t, err)
	assert.True(t, mockDisp.Started, "Dispatcher should be started when Reporter starts")
	assert.True(t, reporter.running)

	reporter.Stop()
	assert.False(t, reporter.running)

	_, ok := <-reporter.updateQueue
	assert.False(t, ok, "Update queue should be closed after Stop()")
}

func TestPolicyActivityReporter_ReportFlow_AllRuleTypes(t *testing.T) {
	mockDisp := &MockDispatcher{}
	dispatchers := map[string]types.Reporter{"mock": mockDisp}
	luc := calc.NewLookupsCache()

	flushInterval := 50 * time.Millisecond
	reporter := NewReporter(luc, dispatchers, flushInterval, nil)

	err := reporter.Start()
	if err != nil {
		t.Fatalf("Unexpected error starting reporter: %v", err)
	}
	defer reporter.Stop()

	activeRule := &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      apiv3.KindNetworkPolicy,
			Name:      "active-policy",
			Namespace: "default",
		},
		Direction: rules.RuleDirIngress,
		IndexStr:  "1",
	}
	pendingRule := &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      apiv3.KindNetworkPolicy,
			Name:      "pending-policy",
			Namespace: "default",
		},
		Direction: rules.RuleDirEgress,
		IndexStr:  "2",
	}
	transitRule := &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      apiv3.KindNetworkPolicy,
			Name:      "transit-policy",
			Namespace: "default",
		},
		Direction: rules.RuleDirIngress,
		IndexStr:  "3",
	}
	unknownRule := &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      apiv3.KindNetworkPolicy,
			Name:      "unknown-policy",
			Namespace: "default",
		},
		Direction: rules.RuleDirEgress,
		IndexStr:  "4",
	}

	update := metric.Update{
		RuleIDs:        []*calc.RuleID{activeRule},
		PendingRuleIDs: []*calc.RuleID{pendingRule},
		TransitRuleIDs: []*calc.RuleID{transitRule},
		UnknownRuleID:  unknownRule,
	}

	err = reporter.Report(update)
	if err != nil {
		t.Fatalf("Unexpected error reporting update: %v", err)
	}
	assert.NoError(t, err)

	time.Sleep(flushInterval * 3)

	logs := mockDisp.GetLogs()
	assert.NotEmpty(t, logs, "Dispatcher should have received logs")

	if len(logs) > 0 {
		batch, ok := logs[0].([]*ActivityLog)
		if assert.True(t, ok, "Expected dispatcher to receive slice of ActivityLogs") {
			assert.Equal(t, 4, len(batch), "Should have processed exactly 4 rules")

			foundNames := make(map[string]bool)
			for _, log := range batch {
				foundNames[log.Policy.Name] = true
			}
			assert.True(t, foundNames["active-policy"])
			assert.True(t, foundNames["pending-policy"])
			assert.True(t, foundNames["transit-policy"])
			assert.True(t, foundNames["unknown-policy"])
		}
	}
}

func TestPolicyActivityReporter_Report_InvalidType(t *testing.T) {
	mockDisp := &MockDispatcher{}
	dispatchers := map[string]types.Reporter{"mock": mockDisp}
	luc := calc.NewLookupsCache()
	reporter := NewReporter(luc, dispatchers, time.Second, nil)

	err := reporter.Report("invalid string data")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected type received in Report")
}

func TestPolicyActivityReporter_IgnoreProfileRules(t *testing.T) {
	mockDisp := &MockDispatcher{}
	dispatchers := map[string]types.Reporter{"mock": mockDisp}
	luc := calc.NewLookupsCache()

	flushInterval := 50 * time.Millisecond
	reporter := NewReporter(luc, dispatchers, flushInterval, nil)

	err := reporter.Start()
	if err != nil {
		t.Fatalf("Unexpected error starting reporter: %v", err)
	}
	defer reporter.Stop()

	profileRule := &calc.RuleID{
		PolicyID: calc.PolicyID{
			Kind:      "",
			Name:      "some-profile-rule",
			Namespace: "default",
		},
		Direction: rules.RuleDirIngress,
		IndexStr:  "1",
	}

	update := metric.Update{
		RuleIDs: []*calc.RuleID{profileRule},
	}

	err = reporter.Report(update)
	assert.NoError(t, err)

	time.Sleep(flushInterval * 3)

	logs := mockDisp.GetLogs()

	assert.Empty(t, logs, "Dispatcher should NOT receive logs for profile rules")
}

func TestPolicyActivityReporter_GenerationLookup(t *testing.T) {
	mockDisp := &MockDispatcher{}
	dispatchers := map[string]types.Reporter{"mock": mockDisp}
	luc := calc.NewLookupsCache()

	flushInterval := 50 * time.Millisecond
	reporter := NewReporter(luc, dispatchers, flushInterval, nil)

	err := reporter.Start()
	if err != nil {
		t.Fatalf("Unexpected error starting reporter: %v", err)
	}
	defer reporter.Stop()

	ns, policyName := "test-ns", "test-policy"
	kind := apiv3.KindNetworkPolicy

	ruleID := &calc.RuleID{
		PolicyID:  calc.PolicyID{Kind: kind, Name: policyName, Namespace: ns},
		Direction: rules.RuleDirEgress,
		IndexStr:  "5",
	}

	expectedGen := int64(123)

	mockGen := map[model.PolicyKey]int64{{
		Kind:      kind,
		Namespace: ns,
		Name:      policyName,
	}: expectedGen}

	luc.SetMockData(
		nil, nil, nil, nil, nil,
		mockGen,
	)

	update := metric.Update{
		RuleIDs: []*calc.RuleID{ruleID},
	}

	err = reporter.Report(update)
	assert.NoError(t, err)

	time.Sleep(flushInterval * 3)

	logs := mockDisp.GetLogs()
	if assert.NotEmpty(t, logs, "Dispatcher should have received logs") {
		batch := logs[0].([]*ActivityLog)
		if assert.Len(t, batch, 1) {
			logEntry := batch[0]

			expectedRuleStr := "123-egress-5"

			assert.Equal(t, expectedRuleStr, logEntry.Rule,
				"Rule string should contain the generation retrieved from LookupsCache")
		}
	}
}

func TestPolicyActivityReporter_GracefulStop(t *testing.T) {
	mockDisp := &MockDispatcher{}
	dispatchers := map[string]types.Reporter{"mock": mockDisp}
	luc := calc.NewLookupsCache()

	flushInterval := 10 * time.Millisecond
	reporter := NewReporter(luc, dispatchers, flushInterval, nil)

	err := reporter.Start()
	assert.NoError(t, err)

	ruleID := &calc.RuleID{
		PolicyID:  calc.PolicyID{Kind: apiv3.KindNetworkPolicy, Name: "p", Namespace: "n"},
		Direction: rules.RuleDirIngress,
		IndexStr:  "1",
	}
	err = reporter.Report(metric.Update{RuleIDs: []*calc.RuleID{ruleID}})
	assert.NoError(t, err)

	time.Sleep(flushInterval * 2)

	reporter.Stop()

	select {
	case <-reporter.done:
		// Success: done channel is closed
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for reporter.done to close")
	}

	_, ok := <-reporter.updateQueue
	assert.False(t, ok, "Update queue should be closed")
	assert.False(t, reporter.running, "Reporter should not be marked as running")
}

func TestProcessRule(t *testing.T) {
	luc := calc.NewLookupsCache()
	mockDisp := &MockDispatcher{}
	dispatchers := map[string]types.Reporter{"mock": mockDisp}

	reporter := NewReporter(luc, dispatchers, 100*time.Millisecond, nil)

	tests := []struct {
		name         string
		rule         *calc.RuleID
		mockGenID    int64
		expectLog    bool
		expectedName string
		expectedRule string
	}{
		{
			name: "Skip system rule (rule index -1)",
			rule: &calc.RuleID{
				PolicyID: calc.PolicyID{
					Kind:      apiv3.KindNetworkPolicy,
					Name:      "system-rule",
					Namespace: "default",
				},
				IndexStr: "-1",
			},
			mockGenID: 99,
			expectLog: false,
		},
		{
			name: "Log valid rule with generation",
			rule: &calc.RuleID{
				PolicyID: calc.PolicyID{
					Kind:      apiv3.KindNetworkPolicy,
					Name:      "backend-policy",
					Namespace: "prod",
				},
				Direction: rules.RuleDirIngress,
				IndexStr:  "5",
			},
			mockGenID:    42,
			expectLog:    true,
			expectedName: "backend-policy",
			expectedRule: "42-ingress-5",
		},
		{
			name: "Log unknown index with generation",
			rule: &calc.RuleID{
				PolicyID: calc.PolicyID{
					Kind:      apiv3.KindNetworkPolicy,
					Name:      "catch-all",
					Namespace: "default",
				},
				Direction: rules.RuleDirEgress,
				IndexStr:  "-2",
			},
			mockGenID:    101,
			expectLog:    true,
			expectedName: "catch-all",
			expectedRule: fmt.Sprintf("101-egress-%s", calc.UnknownStr),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGenMap := map[model.PolicyKey]int64{
				{
					Kind:      tt.rule.Kind,
					Name:      tt.rule.Name,
					Namespace: tt.rule.Namespace,
				}: tt.mockGenID,
			}

			luc.SetMockData(nil, nil, nil, nil, nil, mockGenMap)

			reporter.buf.mu.Lock()
			reporter.buf.logs = []*ActivityLog{}
			reporter.buf.mu.Unlock()

			reporter.processRule(tt.rule)

			reporter.buf.mu.Lock()
			defer reporter.buf.mu.Unlock()

			if !tt.expectLog {
				assert.Empty(t, reporter.buf.logs, "Log should be empty for skipped rules")
			} else {
				assert.Len(t, reporter.buf.logs, 1, "Should have exactly 1 log entry")

				logEntry := reporter.buf.logs[0]

				assert.Equal(t, tt.expectedName, logEntry.Policy.Name)
				assert.Equal(t, tt.rule.Namespace, logEntry.Policy.Namespace)
				assert.Equal(t, tt.expectedRule, logEntry.Rule)
			}
		})
	}
}
