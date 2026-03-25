// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package migration

import (
	"strings"
	"testing"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/runtime"
)

// Types that are intentionally NOT migrated, with the reason why.
var migratorExemptions = map[string]string{
	// Handled directly by the controller via lockDatastore/unlockV3CRDDatastore.
	apiv3.KindClusterInformation: "managed directly by controller",

	// Profile is a system-internal type generated from Kubernetes namespaces
	// and service accounts. It is never user-created and doesn't exist in
	// the v1 datastore as a standalone resource.
	apiv3.KindProfile: "system-generated, not stored as a v1 CRD",

	// AuthorizationReview is a request/response type used by the API server.
	// It is not persisted in etcd and has no v1 CRD.
	apiv3.KindAuthorizationReview: "not a stored resource",
}

// TestMigrators_AllV3TypesCovered verifies that every stored v3 type has a
// corresponding migrator. When a new Calico v3 API type is added, this test
// fails until a migrator is registered or the type is added to the exemption
// list with a documented reason.
func TestMigrators_AllV3TypesCovered(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := apiv3.AddToScheme(scheme); err != nil {
		t.Fatalf("adding v3 types to scheme: %v", err)
	}

	// Build the set of all v3 Kinds from AllKnownTypes.
	allV3Kinds := make(map[string]bool)
	for _, obj := range apiv3.AllKnownTypes {
		gvks, _, err := scheme.ObjectKinds(obj)
		if err != nil {
			t.Fatalf("getting GVK for %T: %v", obj, err)
		}
		for _, gvk := range gvks {
			kind := gvk.Kind
			// Skip List types — they aren't individually migrated.
			if strings.HasSuffix(kind, "List") {
				continue
			}
			allV3Kinds[kind] = true
		}
	}

	// Build the set of kinds covered by migrators.
	coveredKinds := make(map[string]bool)
	for _, m := range NewMigrators(nil, nil) {
		coveredKinds[m.Kind()] = true
	}
	for _, m := range NewEnterpriseMigrators(nil, nil) {
		coveredKinds[m.Kind()] = true
	}

	// Check that every v3 kind is either covered by a migrator or explicitly exempted.
	for kind := range allV3Kinds {
		if coveredKinds[kind] {
			continue
		}
		if reason, ok := migratorExemptions[kind]; ok {
			t.Logf("OK: %s exempted (%s)", kind, reason)
			continue
		}
		t.Errorf("v3 type %s has no migrator and is not in the exemption list — add a migrator in resources.go/resources_enterprise.go or add an exemption with a reason", kind)
	}

	// Also check that exemptions are still valid (no stale entries).
	for kind, reason := range migratorExemptions {
		if !allV3Kinds[kind] {
			t.Errorf("exemption for %s (%s) references a type that no longer exists in AllKnownTypes — remove it", kind, reason)
		}
		if coveredKinds[kind] {
			t.Errorf("exemption for %s (%s) is stale — the type now has a migrator, remove the exemption", kind, reason)
		}
	}
}
