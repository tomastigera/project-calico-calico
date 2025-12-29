// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package query

import "fmt"

var policyActivityKeys = map[string]Validator{
	"last_evaluated":   DateValidator,
	"policy.kind":      NullValidator,
	"policy.name":      NullValidator,
	"policy.namespace": NullValidator,
	"rule":             NullValidator,
	"cluster":          NullValidator,
	"tenant":           NullValidator,
}

func IsValidPolicyActivityAtom(a *Atom) error {
	if validator, ok := policyActivityKeys[a.Key]; ok {
		return validator(a)
	}

	return fmt.Errorf("invalid key for policy activity log: %s", a.Key)
}
