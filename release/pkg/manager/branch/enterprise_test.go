package branch

import (
	"testing"
)

func TestIncrementDevTagIdentifier(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0.dev", "1.dev"},
		{"calient-1.dev", "calient-2.dev"},
	}

	for _, test := range tests {
		result, err := incrementDevTagIdentifier(test.input)
		if err != nil {
			t.Errorf("Unexpected error for input %s: %v", test.input, err)
		}
		if result != test.expected {
			t.Errorf("For input %s, expected %s but got %s", test.input, test.expected, result)
		}
	}
}
