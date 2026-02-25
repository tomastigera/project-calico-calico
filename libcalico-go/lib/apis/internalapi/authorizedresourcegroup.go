// Copyright (c) 2021 Tigera, Inc. All rights reserved.

package internalapi

type AuthorizedResourceGroup struct {
	// The tier. This is only valid for tiered policies, and tiers.
	Tier string `json:"tier,omitempty" validate:"omitempty"`
	// The namespace. If this is empty then the user is authorized cluster-wide (i.e. across all
	// namespaces). This willalways be empty for cluster-scoped resources when the user is authorized.
	Namespace string `json:"namespace" validate:"omitempty"`
	// The UISettingsGroup name. This is only valid for uisettingsgroup/data sub resources.
	UISettingsGroup string `json:"uiSettingsGroup" validate:"omitempty"`
}
