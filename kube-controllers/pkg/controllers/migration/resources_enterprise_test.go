// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package migration

import (
	"testing"

	apiv3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
)

func TestNewEnterpriseMigrators_AllTypesRegistered(t *testing.T) {
	// All enterprise-only types that have v1 CRDs and need migration.
	expectedKinds := map[string]bool{
		apiv3.KindAlertException:             true,
		apiv3.KindBFDConfiguration:           true,
		apiv3.KindDeepPacketInspection:       true,
		apiv3.KindEgressGatewayPolicy:        true,
		apiv3.KindExternalNetwork:            true,
		apiv3.KindGlobalAlert:                true,
		apiv3.KindGlobalAlertTemplate:        true,
		apiv3.KindGlobalReport:               true,
		apiv3.KindGlobalReportType:           true,
		apiv3.KindGlobalThreatFeed:           true,
		apiv3.KindLicenseKey:                 true,
		apiv3.KindManagedCluster:             true,
		apiv3.KindPacketCapture:              true,
		apiv3.KindPolicyRecommendationScope:  true,
		apiv3.KindRemoteClusterConfiguration: true,
		apiv3.KindSecurityEventWebhook:       true,
		apiv3.KindUISettings:                 true,
		apiv3.KindUISettingsGroup:            true,
	}

	migrators := NewEnterpriseMigrators(nil, nil)

	if len(migrators) != len(expectedKinds) {
		t.Fatalf("expected %d enterprise migrators, got %d", len(expectedKinds), len(migrators))
	}

	seen := make(map[string]bool)
	for _, m := range migrators {
		kind := m.Kind()
		if seen[kind] {
			t.Errorf("duplicate migrator for kind %s", kind)
		}
		seen[kind] = true

		if !expectedKinds[kind] {
			t.Errorf("unexpected enterprise migrator kind: %s", kind)
		}
	}

	for kind := range expectedKinds {
		if !seen[kind] {
			t.Errorf("missing enterprise migrator for kind: %s", kind)
		}
	}
}

func TestNewEnterpriseMigrators_OrderingValid(t *testing.T) {
	migrators := NewEnterpriseMigrators(nil, nil)
	for _, m := range migrators {
		if m.Order() <= 0 {
			t.Errorf("migrator %s has invalid order %d", m.Kind(), m.Order())
		}
	}
}

func TestNewEnterpriseMigrators_NoDuplicatesWithOSS(t *testing.T) {
	ossMigrators := NewMigrators(nil, nil)
	enterpriseMigrators := NewEnterpriseMigrators(nil, nil)

	ossKinds := make(map[string]bool)
	for _, m := range ossMigrators {
		ossKinds[m.Kind()] = true
	}

	for _, m := range enterpriseMigrators {
		if ossKinds[m.Kind()] {
			t.Errorf("enterprise migrator %s duplicates an OSS migrator", m.Kind())
		}
	}
}
