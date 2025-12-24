package query

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidPolicyActivityAtom(t *testing.T) {
	originalKeys := policyActivityKeys
	defer func() {
		policyActivityKeys = originalKeys
	}()

	mockError := fmt.Errorf("mock validation error")

	mockValidatorSuccess := func(a *Atom) error {
		return nil
	}

	mockValidatorFail := func(a *Atom) error {
		return mockError
	}

	policyActivityKeys = map[string]Validator{
		"test_success": mockValidatorSuccess,
		"test_fail":    mockValidatorFail,
	}

	tests := []struct {
		name          string
		atomKey       string
		expectedError error
	}{
		{
			name:          "Valid Key - Validator Returns Success",
			atomKey:       "test_success",
			expectedError: nil,
		},
		{
			name:          "Valid Key - Validator Returns Error",
			atomKey:       "test_fail",
			expectedError: mockError,
		},
		{
			name:          "Invalid Key - Not in Map",
			atomKey:       "unknown_key",
			expectedError: fmt.Errorf("invalid key for policy activity log: unknown_key"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atom := &Atom{Key: tt.atomKey}

			err := IsValidPolicyActivityAtom(atom)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicyActivityKeys_Configuration(t *testing.T) {
	expectedKeys := []string{
		"last_evaluated",
		"policy.kind",
		"policy.name",
		"policy.namespace",
		"rule",
		"cluster",
		"tenant",
	}

	for _, key := range expectedKeys {
		_, ok := policyActivityKeys[key]
		assert.True(t, ok, "Expected key '%s' to be present in policyActivityKeys map", key)
	}
}
