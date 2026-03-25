// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package index_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
)

func TestIndex(t *testing.T) {
	type test struct {
		idx                bapi.Index
		info               bapi.ClusterInfo
		expectedName       string
		expectedIndex      string
		expectedWriteAlias string
		expectedILM        string
	}

	tests := []test{
		{
			idx:                index.FlowLogMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1"},
			expectedName:       "flows-cluster1",
			expectedIndex:      "tigera_secure_ee_flows.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_flows.cluster1.",
			expectedILM:        "tigera_secure_ee_flows_policy",
		},
		{
			idx:                index.FlowLogMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "flows-cluster1-tenant1",
			expectedIndex:      "tigera_secure_ee_flows.tenant1.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_flows.tenant1.cluster1.",
			expectedILM:        "tigera_secure_ee_flows_policy",
		},
		{
			idx:                index.FlowLogIndex(),
			info:               bapi.ClusterInfo{Cluster: "cluster1"},
			expectedName:       "calico_flowlogs",
			expectedIndex:      "calico_flowlogs.*",
			expectedWriteAlias: "calico_flowlogs.",
			expectedILM:        "tigera_secure_ee_flows_policy",
		},
		{
			idx:                index.FlowLogIndex(),
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "calico_flowlogs",
			expectedIndex:      "calico_flowlogs.*",
			expectedWriteAlias: "calico_flowlogs.",
			expectedILM:        "tigera_secure_ee_flows_policy",
		},
		{
			idx:                index.AuditLogEEMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1"},
			expectedName:       "audit_ee-cluster1",
			expectedIndex:      "tigera_secure_ee_audit_ee.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_audit_ee.cluster1.",
			expectedILM:        "tigera_secure_ee_audit_ee_policy",
		},
		{
			idx:                index.AuditLogKubeMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1"},
			expectedName:       "audit_kube-cluster1",
			expectedIndex:      "tigera_secure_ee_audit_kube.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_audit_kube.cluster1.",
			expectedILM:        "tigera_secure_ee_audit_kube_policy",
		},
		{
			idx:                index.AuditLogEEMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "audit_ee-cluster1-tenant1",
			expectedIndex:      "tigera_secure_ee_audit_ee.tenant1.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_audit_ee.tenant1.cluster1.",
			expectedILM:        "tigera_secure_ee_audit_ee_policy",
		},
		{
			idx:                index.AuditLogKubeMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "audit_kube-cluster1-tenant1",
			expectedIndex:      "tigera_secure_ee_audit_kube.tenant1.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_audit_kube.tenant1.cluster1.",
			expectedILM:        "tigera_secure_ee_audit_kube_policy",
		},
		{
			idx:                index.AuditLogIndex(),
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "calico_auditlogs",
			expectedIndex:      "calico_auditlogs.*",
			expectedWriteAlias: "calico_auditlogs.",
			expectedILM:        "tigera_secure_ee_audit_ee_policy",
		},
	}

	// Run tests with default tenant suffix behavior (included).
	for _, tc := range tests {
		t.Run(tc.idx.Index(tc.info), func(t *testing.T) {
			require.Equal(t, tc.expectedName, tc.idx.Name(tc.info))
			require.Equal(t, tc.expectedIndex, tc.idx.Index(tc.info))
			require.Equal(t, tc.expectedWriteAlias, tc.idx.Alias(tc.info))
			require.Equal(t, tc.expectedILM, tc.idx.ILMPolicyName())
		})
	}
}

func TestMultiIndexTenantSuffixDisabled(t *testing.T) {
	index.SetMultiIndexTenantSuffixEnabled(false)
	defer index.SetMultiIndexTenantSuffixEnabled(true)

	type test struct {
		name               string
		idx                bapi.Index
		info               bapi.ClusterInfo
		expectedName       string
		expectedIndex      string
		expectedWriteAlias string
	}

	tests := []test{
		{
			name:               "multi-index with tenant omits tenant from name",
			idx:                index.FlowLogMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "flows-cluster1",
			expectedIndex:      "tigera_secure_ee_flows.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_flows.cluster1.",
		},
		{
			name:               "multi-index without tenant unchanged",
			idx:                index.FlowLogMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1"},
			expectedName:       "flows-cluster1",
			expectedIndex:      "tigera_secure_ee_flows.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_flows.cluster1.",
		},
		{
			name:               "audit ee multi-index with tenant omits tenant",
			idx:                index.AuditLogEEMultiIndex,
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "audit_ee-cluster1",
			expectedIndex:      "tigera_secure_ee_audit_ee.cluster1.*",
			expectedWriteAlias: "tigera_secure_ee_audit_ee.cluster1.",
		},
		{
			name:               "single-index unaffected by tenant suffix setting",
			idx:                index.FlowLogIndex(),
			info:               bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"},
			expectedName:       "calico_flowlogs",
			expectedIndex:      "calico_flowlogs.*",
			expectedWriteAlias: "calico_flowlogs.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expectedName, tc.idx.Name(tc.info))
			require.Equal(t, tc.expectedIndex, tc.idx.Index(tc.info))
			require.Equal(t, tc.expectedWriteAlias, tc.idx.Alias(tc.info))
		})
	}
}

func TestNewMultiIndexRespectsTenantSuffixSetting(t *testing.T) {
	info := bapi.ClusterInfo{Cluster: "cluster1", Tenant: "tenant1"}

	// Default: tenant suffix enabled.
	idx := index.NewMultiIndex("tigera_secure_ee_audit_*", bapi.DataType("any"))
	require.Equal(t, "tigera_secure_ee_audit_*.tenant1.cluster1.*", idx.Index(info))

	// Disable tenant suffix.
	index.SetMultiIndexTenantSuffixEnabled(false)
	defer index.SetMultiIndexTenantSuffixEnabled(true)

	// Same index instance now omits tenant since it checks the package-level flag.
	require.Equal(t, "tigera_secure_ee_audit_*.cluster1.*", idx.Index(info))
}
