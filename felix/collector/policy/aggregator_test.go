package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAggregate(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(1 * time.Minute)
	t2 := t0.Add(2 * time.Minute)

	tests := []struct {
		name     string
		input    []*ActivityLog
		expected []*ActivityLog
	}{
		{
			name:     "Empty input",
			input:    []*ActivityLog{},
			expected: nil,
		},
		{
			name:     "Nil input slice",
			input:    nil,
			expected: nil,
		},
		{
			name: "Single log",
			input: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "kind1"}, Rule: "r1", LastEvaluated: t0},
			},
			expected: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "kind1"}, Rule: "r1", LastEvaluated: t0},
			},
		},
		{
			name: "Multiple distinct logs",
			input: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1"}, Rule: "r1", LastEvaluated: t0},
				{Policy: PolicyInfo{Name: "p2"}, Rule: "r2", LastEvaluated: t0},
			},
			expected: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1"}, Rule: "r1", LastEvaluated: t0},
				{Policy: PolicyInfo{Name: "p2"}, Rule: "r2", LastEvaluated: t0},
			},
		},
		{
			name: "Dedup same key, keep later time",
			input: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "k1"}, Rule: "r1", LastEvaluated: t0},
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "k1"}, Rule: "r1", LastEvaluated: t1},
			},
			expected: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "k1"}, Rule: "r1", LastEvaluated: t1},
			},
		},
		{
			name: "Dedup same key, keep later time (reverse order input)",
			input: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "k1"}, Rule: "r1", LastEvaluated: t1},
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "k1"}, Rule: "r1", LastEvaluated: t0},
			},
			expected: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "k1"}, Rule: "r1", LastEvaluated: t1},
			},
		},
		{
			name: "Normalization check (case/whitespace)",
			input: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1", Namespace: "ns1", Kind: "NetworkPolicy"}, Rule: "r1", LastEvaluated: t0},
				{Policy: PolicyInfo{Name: " P1 ", Namespace: "Ns1", Kind: "networkpolicy"}, Rule: "R1", LastEvaluated: t2},
			},
			expected: []*ActivityLog{
				{Policy: PolicyInfo{Name: " P1 ", Namespace: "Ns1", Kind: "networkpolicy"}, Rule: "R1", LastEvaluated: t2},
			},
		},
		{
			name: "Ignore nil logs in slice",
			input: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1"}, Rule: "r1", LastEvaluated: t0},
				nil,
			},
			expected: []*ActivityLog{
				{Policy: PolicyInfo{Name: "p1"}, Rule: "r1", LastEvaluated: t0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := aggregate(tt.input)
			assert.Len(t, result, len(tt.expected))

			for _, exp := range tt.expected {
				found := false
				for _, res := range result {
					if res.Policy == exp.Policy && res.Rule == exp.Rule && res.LastEvaluated.Equal(exp.LastEvaluated) {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected log not found in result: %+v", exp)
			}
		})
	}
}
