// Copyright (c) 2019-2023 Tigera, Inc. All rights reserved.

package clusters

// ManagedCluster contains metadata used to track a specific cluster
type ManagedCluster struct {
	// ID is intended to store the unique resource name for a ManagedCluster resource
	// We have chosen to use the resource name instead of the UID for a resource
	// because (1) we use the resource name to identify the cluster specific ElasticSearch
	// indexes (2) to be consistent we want to use the same cluster identifier across
	// all use cases (i.e. avoid creating overhead of mapping UID to resource name)
	ID string `json:"id"`
	// ActiveFingerprint stores the a hash extracted from the generated client certificate
	// assigned to a managed cluster. Only connections that present the certificate that matches the
	// active fingerprint will be accepted
	ActiveFingerprint string `json:"activeFingerprint,omitempty"`
	// Certificate stores managed cluster certificate.
	Certificate []byte `json:"certificate,omitempty"`
}
