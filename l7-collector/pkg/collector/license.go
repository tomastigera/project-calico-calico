// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package collector

// LicenseChecker is an interface for checking license status.
// This allows consumers (like gateway) to provide their own license checking implementation.
type LicenseChecker interface {
	// IsLicensed returns true if the feature is licensed and enabled.
	IsLicensed() bool
}

// AlwaysLicensed is a stub implementation of LicenseChecker that always returns true.
// This is used as the default when no license checking is needed (e.g., in l7-collector standalone).
type AlwaysLicensed struct{}

// IsLicensed always returns true for the stub implementation.
func (a *AlwaysLicensed) IsLicensed() bool {
	return true
}

// NewAlwaysLicensed creates a new AlwaysLicensed instance.
func NewAlwaysLicensed() LicenseChecker {
	return &AlwaysLicensed{}
}
