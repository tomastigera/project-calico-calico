// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package fv_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
)

type ElasticArgs struct {
	index      bapi.Index
	updateArgs *RunConfigureElasticArgs
}

// configureIndicesSetupAndTeardown performs additional setup and teardown for ingestion tests.
func configureIndicesSetupAndTeardown(t *testing.T, idx bapi.Index) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	var err error

	esClient, err = elastic.NewSimpleClient(elastic.SetURL("http://localhost:9200"), elastic.SetInfoLog(logrus.StandardLogger()))
	require.NoError(t, err)

	// Set up context with a timeout.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)

	return func() {
		for _, clusterInfo := range []bapi.ClusterInfo{cluster1Info, cluster2Info, cluster3Info} {
			_ = testutils.CleanupIndices(context.Background(), esClient, idx.IsSingleIndex(), idx, clusterInfo)
		}
		logCancel()
		cancel()
	}
}

func TestFV_ConfigureFlowIndices(t *testing.T) {
	tests := configureElasticArgs("", "", "calico_free")
	testRollIndexForShards := configureElasticArgs("2", "0", "calico_free")
	testRollIndexForReplicas := configureElasticArgs("2", "1", "calico_free")
	testRollIndexForILMPolicy := configureElasticArgs("2", "1", "new_calico_ilm_policy")

	for i, tt := range tests {
		t.Run(fmt.Sprintf("Configure Elastic Indices %s [SingleIndex]", tt.index.DataType()), func(t *testing.T) {
			defer configureIndicesSetupAndTeardown(t, tt.index)()

			// Start a linseed configuration instance.
			RunConfigureElasticLinseed(t, tt.updateArgs)
			testutils.CheckSingleIndexTemplateBootstrapping(t, ctx, esClient, tt.index, bapi.ClusterInfo{}, "000001", "1", "0", "calico_free")

			// Update shards to check index rollover
			RunConfigureElasticLinseed(t, testRollIndexForShards[i].updateArgs)
			testutils.CheckSingleIndexTemplateBootstrapping(t, ctx, esClient, tt.index, bapi.ClusterInfo{}, "000002", "2", "0", "calico_free")

			// Update replicas to check index rollover
			RunConfigureElasticLinseed(t, testRollIndexForReplicas[i].updateArgs)
			testutils.CheckSingleIndexTemplateBootstrapping(t, ctx, esClient, tt.index, bapi.ClusterInfo{}, "000003", "2", "1", "calico_free")

			// Update ILMPolicy to check index rollover
			if tt.index.HasLifecycleEnabled() {
				RunConfigureElasticLinseed(t, testRollIndexForILMPolicy[i].updateArgs)
				testutils.CheckSingleIndexTemplateBootstrapping(t, ctx, esClient, tt.index, bapi.ClusterInfo{}, "000004", "2", "1", "new_calico_ilm_policy")
			}
		})
	}
}

func configureElasticArgs(shards, replicas, ilmpolicy string) []ElasticArgs {
	alertsIndex := index.AlertsIndex(index.WithBaseIndexName("calico_alerts_free"), index.WithILMPolicyName(ilmpolicy))
	auditIndex := index.AuditLogIndex(index.WithBaseIndexName("calico_auditlogs_free"), index.WithILMPolicyName(ilmpolicy))
	bgpIndex := index.BGPLogIndex(index.WithBaseIndexName("calico_bgplogs_free"), index.WithILMPolicyName(ilmpolicy))
	dnsIndex := index.DNSLogIndex(index.WithBaseIndexName("calico_dnslogs_free"), index.WithILMPolicyName(ilmpolicy))
	flowIndex := index.FlowLogIndex(index.WithBaseIndexName("calico_flowlogs_free"), index.WithILMPolicyName(ilmpolicy))
	complianceBenchmarksIndex := index.ComplianceBenchmarksIndex(index.WithBaseIndexName("calico_compliance_benchmarks_free"), index.WithILMPolicyName(ilmpolicy))
	complianceReportsIndex := index.ComplianceReportsIndex(index.WithBaseIndexName("calico_compliance_reports_free"), index.WithILMPolicyName(ilmpolicy))
	complianceSnapshotsIndex := index.ComplianceSnapshotsIndex(index.WithBaseIndexName("calico_compliance_snapshots_free"), index.WithILMPolicyName(ilmpolicy))
	l7Index := index.L7LogIndex(index.WithBaseIndexName("calico_l7logs_free"), index.WithILMPolicyName(ilmpolicy))
	runtimeIndex := index.RuntimeReportsIndex(index.WithBaseIndexName("calico_runtime_reports_free"), index.WithILMPolicyName(ilmpolicy))
	threatFeedsIPSetIndex := index.ThreatFeedsIPSetIndex(index.WithBaseIndexName("calico_thread_feeds_ip_set_free"), index.WithILMPolicyName(ilmpolicy))
	threatFeedsDomainSetIndex := index.ThreatFeedsDomainSetIndex(index.WithBaseIndexName("calico_thread_feeds_domain_set_free"), index.WithILMPolicyName(ilmpolicy))
	wafIndex := index.WAFLogIndex(index.WithBaseIndexName("calico_waf_logs_free"), index.WithILMPolicyName(ilmpolicy))

	return []ElasticArgs{
		{
			index: auditIndex,
			updateArgs: &RunConfigureElasticArgs{
				AuditBaseIndexName: auditIndex.Name(bapi.ClusterInfo{}),
				AuditPolicyName:    auditIndex.ILMPolicyName(),
				AuditShards:        shards,
				AuditReplicas:      replicas,
			},
		},
		{
			index: bgpIndex,
			updateArgs: &RunConfigureElasticArgs{
				BGPBaseIndexName: bgpIndex.Name(bapi.ClusterInfo{}),
				BGPPolicyName:    bgpIndex.ILMPolicyName(),
				BGPShards:        shards,
				BGPReplicas:      replicas,
			},
		},
		{
			index: dnsIndex,
			updateArgs: &RunConfigureElasticArgs{
				DNSBaseIndexName: dnsIndex.Name(bapi.ClusterInfo{}),
				DNSPolicyName:    dnsIndex.ILMPolicyName(),
				DNSShards:        shards,
				DNSReplicas:      replicas,
			},
		},
		{
			index: flowIndex,
			updateArgs: &RunConfigureElasticArgs{
				FlowBaseIndexName: flowIndex.Name(bapi.ClusterInfo{}),
				FlowPolicyName:    flowIndex.ILMPolicyName(),
				FlowShards:        shards,
				FlowReplicas:      replicas,
			},
		},
		{
			index: l7Index,
			updateArgs: &RunConfigureElasticArgs{
				L7BaseIndexName: l7Index.Name(bapi.ClusterInfo{}),
				L7PolicyName:    l7Index.ILMPolicyName(),
				L7Shards:        shards,
				L7Replicas:      replicas,
			},
		},
		{
			index: alertsIndex,
			updateArgs: &RunConfigureElasticArgs{
				AlertBaseIndexName: alertsIndex.Name(bapi.ClusterInfo{}),
				AlertPolicyName:    alertsIndex.ILMPolicyName(),
				ElasticShards:      shards,
				ElasticReplicas:    replicas,
			},
		},
		{
			index: wafIndex,
			updateArgs: &RunConfigureElasticArgs{
				WAFBaseIndexName: wafIndex.Name(bapi.ClusterInfo{}),
				WAFPolicyName:    wafIndex.ILMPolicyName(),
				ElasticShards:    shards,
				ElasticReplicas:  replicas,
			},
		},
		{
			index: runtimeIndex,
			updateArgs: &RunConfigureElasticArgs{
				RuntimeReportsBaseIndexName: runtimeIndex.Name(bapi.ClusterInfo{}),
				RuntimeReportsPolicyName:    runtimeIndex.ILMPolicyName(),
				ElasticShards:               shards,
				ElasticReplicas:             replicas,
			},
		},
		{
			index: complianceBenchmarksIndex,
			updateArgs: &RunConfigureElasticArgs{
				ComplianceBenchmarksBaseIndexName: complianceBenchmarksIndex.Name(bapi.ClusterInfo{}),
				ComplianceBenchmarksPolicyName:    complianceBenchmarksIndex.ILMPolicyName(),
				ElasticShards:                     shards,
				ElasticReplicas:                   replicas,
			},
		},
		{
			index: complianceReportsIndex,
			updateArgs: &RunConfigureElasticArgs{
				ComplianceReportsBaseIndexName: complianceReportsIndex.Name(bapi.ClusterInfo{}),
				ComplianceReportsPolicyName:    complianceReportsIndex.ILMPolicyName(),
				ElasticShards:                  shards,
				ElasticReplicas:                replicas,
			},
		},
		{
			index: complianceSnapshotsIndex,
			updateArgs: &RunConfigureElasticArgs{
				ComplianceSnapshotsBaseIndexName: complianceSnapshotsIndex.Name(bapi.ClusterInfo{}),
				ComplianceSnapshotsPolicyName:    complianceSnapshotsIndex.ILMPolicyName(),
				ElasticShards:                    shards,
				ElasticReplicas:                  replicas,
			},
		},
		{
			index: threatFeedsDomainSetIndex,
			updateArgs: &RunConfigureElasticArgs{
				ThreatFeedsDomainSetBaseIndexName: threatFeedsDomainSetIndex.Name(bapi.ClusterInfo{}),
				ThreatFeedsDomainSetPolicyName:    threatFeedsDomainSetIndex.ILMPolicyName(),
				ElasticShards:                     shards,
				ElasticReplicas:                   replicas,
			},
		},
		{
			index: threatFeedsIPSetIndex,
			updateArgs: &RunConfigureElasticArgs{
				ThreatFeedsIPSetBaseIndexName: threatFeedsIPSetIndex.Name(bapi.ClusterInfo{}),
				ThreatFeedsIPSetPolicyName:    threatFeedsIPSetIndex.ILMPolicyName(),
				ElasticShards:                 shards,
				ElasticReplicas:               replicas,
			},
		},
	}
}
