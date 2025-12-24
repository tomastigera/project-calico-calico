// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package main

import (
	"context"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/linseed/pkg/backend"
	"github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	"github.com/projectcalico/calico/linseed/pkg/config"
	lmaelastic "github.com/projectcalico/calico/lma/pkg/elastic"
)

func boostrapElasticIndices() {
	// Read and reconcile configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}
	if cfg.Backend != config.BackendTypeSingleIndex {
		panic("Invalid configuration. Configuration job needs to run in single index mode")
	}

	// Configure logging
	config.ConfigureLogging(cfg.LogLevel)
	logrus.Debugf("Starting with %#v", cfg)

	esClient := backend.MustGetElasticClient(*cfg.ElasticClientConfig, cfg.LogLevel, "")
	createSingleIndexIndices(cfg, esClient)

	os.Exit(0)
}

type indexInitializer struct {
	index       api.Index
	initializer api.IndexInitializer
}

func createSingleIndexIndices(cfg *config.Config, esClient lmaelastic.Client) {
	// We are only configuring indices and there is no need to start the HTTP server
	logrus.Info("Configuring Elastic indices")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create template caches for indices with special shards / replicas configuration
	defaultInitializer := templates.NewCachedInitializer(esClient, cfg.ElasticClientConfig.ElasticShards, cfg.ElasticClientConfig.ElasticReplicas)
	flowInitializer := templates.NewCachedInitializer(esClient, cfg.ElasticClientConfig.ElasticFlowShards, cfg.ElasticClientConfig.ElasticFlowReplicas)
	dnsInitializer := templates.NewCachedInitializer(esClient, cfg.ElasticClientConfig.ElasticDNSShards, cfg.ElasticClientConfig.ElasticDNSReplicas)
	l7Initializer := templates.NewCachedInitializer(esClient, cfg.ElasticClientConfig.ElasticL7Shards, cfg.ElasticClientConfig.ElasticL7Replicas)
	auditInitializer := templates.NewCachedInitializer(esClient, cfg.ElasticClientConfig.ElasticAuditShards, cfg.ElasticClientConfig.ElasticAuditReplicas)
	bgpInitializer := templates.NewCachedInitializer(esClient, cfg.ElasticClientConfig.ElasticBGPShards, cfg.ElasticClientConfig.ElasticBGPReplicas)
	policyInitializer := templates.NewCachedInitializer(esClient, cfg.ElasticClientConfig.ElasticPolicyActivityShards, cfg.ElasticClientConfig.ElasticPolicyActivityReplicas)

	// Create all indices with the given configurations (name and ilm policy)
	alertIndex := index.AlertsIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticAlertsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticAlertsPolicyName))
	auditIndex := index.AuditLogIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticAuditLogsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticAuditLogsPolicyName))
	bgpIndex := index.BGPLogIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticBGPLogsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticBGPLogsPolicyName))
	dnsIndex := index.DNSLogIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticDNSLogsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticDNSLogsPolicyName))
	flowIndex := index.FlowLogIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticFlowLogsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticFlowLogsPolicyName))
	complianceBenchmarksIndex := index.ComplianceBenchmarksIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticComplianceBenchmarksBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticComplianceBenchmarksPolicyName))
	complianceReportsIndex := index.ComplianceReportsIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticComplianceReportsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticComplianceReportsPolicyName))
	complianceSnapshotsIndex := index.ComplianceSnapshotsIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticComplianceSnapshotsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticComplianceSnapshotsPolicyName))
	l7Index := index.L7LogIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticL7LogsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticL7LogsPolicyName))
	runtimeIndex := index.RuntimeReportsIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticRuntimeReportsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticRuntimeReportsPolicyName))
	threatFeedsIPSetIndex := index.ThreatFeedsIPSetIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticThreatFeedsIPSetBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticThreatFeedsIPSetIPolicyName))
	threatFeedsDomainSetIndex := index.ThreatFeedsDomainSetIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticThreatFeedsDomainSetBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticThreatFeedsDomainSetPolicyName))
	wafIndex := index.WAFLogIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticWAFLogsBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticWAFLogsPolicyName))
	policyActivityIndex := index.PolicyActivityIndex(index.WithBaseIndexName(cfg.ElasticClientConfig.ElasticPolicyActivityBaseIndexName), index.WithILMPolicyName(cfg.ElasticClientConfig.ElasticPolicyActivityPolicyName))

	initialization := []indexInitializer{
		// Indices defined below share the same configuration for shards / replicas
		{index: alertIndex, initializer: defaultInitializer},
		{index: complianceBenchmarksIndex, initializer: defaultInitializer},
		{index: complianceReportsIndex, initializer: defaultInitializer},
		{index: complianceSnapshotsIndex, initializer: defaultInitializer},
		{index: runtimeIndex, initializer: defaultInitializer},
		{index: threatFeedsDomainSetIndex, initializer: defaultInitializer},
		{index: threatFeedsIPSetIndex, initializer: defaultInitializer},
		{index: wafIndex, initializer: defaultInitializer},
		// Indices below can have replicas / shards user configured
		{index: auditIndex, initializer: auditInitializer},
		{index: bgpIndex, initializer: bgpInitializer},
		{index: dnsIndex, initializer: dnsInitializer},
		{index: flowIndex, initializer: flowInitializer},
		{index: l7Index, initializer: l7Initializer},
		{index: policyActivityIndex, initializer: policyInitializer},
	}

	for _, idx := range initialization {
		configureIndex(ctx, idx.index, idx.initializer)
	}

	logrus.Info("Finished configuring Elastic indices")
}

func configureIndex(ctx context.Context, idx api.Index, cache api.IndexInitializer) {
	var emptyClusterInfo api.ClusterInfo
	indexName := idx.Name(emptyClusterInfo)
	policyName := idx.ILMPolicyName()
	if len(indexName) == 0 {
		logrus.Warnf("Skipping index configuration as no name was provided for data type %s", idx.DataType())
		return
	}
	if idx.HasLifecycleEnabled() && len(policyName) == 0 {
		logrus.Warnf("Skipping index configuration as no policy name was provided for data type %s", idx.DataType())
		return
	}

	logrus.Infof("Configure index %s for data type %s", indexName, idx.DataType())
	err := cache.Initialize(ctx, idx, emptyClusterInfo)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to configure elastic index %s", indexName)
	}
}
