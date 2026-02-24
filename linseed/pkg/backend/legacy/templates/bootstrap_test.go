// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package templates_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/logutils"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/index"
	"github.com/projectcalico/calico/linseed/pkg/backend/legacy/templates"
	"github.com/projectcalico/calico/linseed/pkg/backend/testutils"
	"github.com/projectcalico/calico/linseed/pkg/config"
)

var (
	client  *elastic.Client
	ctx     context.Context
	cluster string
)

func setupTest(t *testing.T, indices ...bapi.Index) func() {
	// Hook logrus into testing.T
	config.ConfigureLogging("DEBUG")
	logCancel := logutils.RedirectLogrusToTestingT(t)

	var err error

	// Create an elasticsearch client to use for the test. For this suite, we use a real
	// elasticsearch instance created via "make run-elastic".
	client, err = elastic.NewSimpleClient(elastic.SetURL("http://localhost:9200"), elastic.SetInfoLog(logrus.StandardLogger()))

	require.NoError(t, err)

	// Create a random cluster name for each test to make sure we don't
	// interfere between tests.
	cluster = testutils.RandomClusterName()
	info := bapi.ClusterInfo{Cluster: cluster}

	// Each test should take less than 60 seconds.
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)

	return func() {
		// Cleanup after ourselves.
		for _, idx := range indices {
			err = testutils.CleanupIndices(context.Background(), client, idx.IsSingleIndex(), idx, info)
			require.NoError(t, err)
		}

		// Cancel the context
		cancel()
		logCancel()
	}
}

func TestBootstrapLegacyFlowTemplate(t *testing.T) {
	defer setupTest(t, index.FlowLogMultiIndex)()

	// Check that the template returned has the correct
	// index_patterns, ILM policy, mappings and shards and replicas
	templateConfig := templates.NewTemplateConfig(index.FlowLogMultiIndex, bapi.ClusterInfo{Cluster: cluster})

	templ, err := templates.DefaultBootstrapper(ctx, client, templateConfig)
	require.NoError(t, err)
	require.NotNil(t, templ)
	require.Len(t, templ.IndexPatterns, 1)

	checkMultiIndexTemplateBootstrapping(t, "tigera_secure_ee_flows", "fluentd", cluster, "000001", 1, true)
}

func TestBootstrapFlowTemplate(t *testing.T) {
	defer setupTest(t, index.FlowLogIndex())()

	info := bapi.ClusterInfo{Cluster: cluster}
	idx := index.FlowLogIndex()

	// Check that the template returned has the correct
	// index_patterns, ILM policy, mappings and shards and replicas
	templateConfig := templates.NewTemplateConfig(idx, info)
	templ, err := templates.DefaultBootstrapper(ctx, client, templateConfig)
	require.NoError(t, err)
	require.NotNil(t, templ)
	require.Len(t, templ.IndexPatterns, 1)
	testutils.CheckSingleIndexTemplateBootstrapping(t, ctx, client, idx, info, "000001", "1", "0", "tigera_secure_ee_flows_policy")
}

func TestBootstrapFlowTemplateAsync(t *testing.T) {
	defer setupTest(t, index.FlowLogIndex())()

	info := bapi.ClusterInfo{Cluster: cluster}
	idx := index.FlowLogIndex()

	// Check that the template returned has the correct
	// index_patterns, ILM policy, mappings and shards and replicas
	templateConfig := templates.NewTemplateConfig(idx, info)
	errs := make(chan error, 5)
	templs := make(chan *templates.Template, 5)
	numRoutines := 10
	for range numRoutines {
		go func() {
			templ, err := templates.DefaultBootstrapper(ctx, client, templateConfig)
			if err != nil {
				errs <- err
			} else {
				templs <- templ
			}
		}()
	}

	for range numRoutines {
		select {
		case err := <-errs:
			require.NoError(t, err, "error received from DefaultBootstrapper")
		case templ := <-templs:
			require.NotNil(t, templ)
			require.Len(t, templ.IndexPatterns, 1)
		case <-time.After(10 * time.Second):
			require.Fail(t, "timed out waiting for template")
		}
	}

	// Check that the resulting template in ES is correct.
	testutils.CheckSingleIndexTemplateBootstrapping(t, ctx, client, idx, info, "000001", "1", "0", "tigera_secure_ee_flows_policy")
}

func checkMultiIndexTemplateBootstrapping(t *testing.T, indexPrefix, application, cluster, indexNumber string, expectedNumberIndices int, templateNameEndsInDot bool) {
	// Check that the template was created
	templateName := fmt.Sprintf("%s.%s", indexPrefix, cluster)
	// Some template names do not end with a dot, like the template name for events
	if templateNameEndsInDot {
		templateName = fmt.Sprintf("%s.%s.", indexPrefix, cluster)
	}
	templateExists, err := client.IndexTemplateExists(templateName).Do(ctx)
	require.NoError(t, err)
	require.True(t, templateExists)

	// Check that the bootstrap index exists
	index := fmt.Sprintf("%s.%s.%s-%s-%s", indexPrefix, cluster, application, time.Now().UTC().Format("20060102"), indexNumber)
	indexExists, err := client.IndexExists(index).Do(ctx)
	require.NoError(t, err)
	require.True(t, indexExists, "index doesn't exist: %s", index)

	// Check that write alias exists.
	responseAlias, err := client.CatAliases().Do(ctx)
	require.NoError(t, err)
	require.Greater(t, len(responseAlias), 0)
	hasAlias := false
	numWriteIndex := 0
	numNonWriteIndex := 0
	for _, row := range responseAlias {
		if row.Alias == fmt.Sprintf("%s.%s.", indexPrefix, cluster) {
			hasAlias = true
			if row.IsWriteIndex == "true" {
				require.Equal(t, index, row.Index)
				numWriteIndex++
			} else {
				require.NotEqual(t, index, row.Index)
				numNonWriteIndex++
			}
		}
	}
	require.True(t, hasAlias)

	// We always only want 1 write index
	require.Equal(t, 1, numWriteIndex)
	// We may have some non-write index (if we rollover)
	require.Equal(t, expectedNumberIndices-1, numNonWriteIndex)

	responseSettings, err := client.IndexGetSettings(index).Do(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, responseSettings)
	require.Contains(t, responseSettings, index)
	require.NotEmpty(t, responseSettings[index].Settings)
	require.Contains(t, responseSettings[index].Settings, "index")
	settings, _ := responseSettings[index].Settings["index"].(map[string]any)
	// Check lifecycle section
	require.Contains(t, settings, "lifecycle")
	lifecycle, _ := settings["lifecycle"].(map[string]any)
	require.Contains(t, lifecycle, "name")
	require.EqualValues(t, lifecycle["name"], fmt.Sprintf("%s_policy", indexPrefix))
	require.EqualValues(t, lifecycle["rollover_alias"], fmt.Sprintf("%s.%s.", indexPrefix, cluster))
	// Check shards and replicas
	require.Contains(t, settings, "number_of_replicas")
	require.EqualValues(t, settings["number_of_replicas"], "0")
	require.Contains(t, settings, "number_of_shards")
	require.EqualValues(t, settings["number_of_shards"], "1")
	// Check template for index name
	require.Contains(t, settings, "provided_name")
	require.EqualValues(t, settings["provided_name"], fmt.Sprintf("<%s.%s.%s-{now/s{yyyyMMdd}}-%s>", indexPrefix, cluster, application, indexNumber))
}

func TestBootstrapAuditTemplates(t *testing.T) {
	defer setupTest(t, index.AuditLogEEMultiIndex, index.AuditLogKubeMultiIndex)()

	auditKubeTemplateConfig := templates.NewTemplateConfig(index.AuditLogKubeMultiIndex, bapi.ClusterInfo{Cluster: cluster})
	auditEETemplateConfig := templates.NewTemplateConfig(index.AuditLogEEMultiIndex, bapi.ClusterInfo{Cluster: cluster})

	templKubeAudit, err := templates.DefaultBootstrapper(ctx, client, auditKubeTemplateConfig)
	require.NoError(t, err)
	require.NotNil(t, templKubeAudit)
	require.Len(t, templKubeAudit.IndexPatterns, 1)

	templEEAudit, err := templates.DefaultBootstrapper(ctx, client, auditEETemplateConfig)
	require.NoError(t, err)
	require.NotNil(t, templEEAudit)
	require.Len(t, templEEAudit.IndexPatterns, 1)

	// Check that the template returned has the correct
	// index_patterns, ILM policy, mappings and shards and replicas
	checkMultiIndexTemplateBootstrapping(t, "tigera_secure_ee_audit_kube", "fluentd", cluster, "000001", 1, true)
	checkMultiIndexTemplateBootstrapping(t, "tigera_secure_ee_audit_ee", "fluentd", cluster, "000001", 1, true)
}

func TestBootstrapEventsBackwardsCompatibility(t *testing.T) {
	defer setupTest(t, index.EventsMultiIndex)()

	// Create an old index that has the same name as the one defined in 3.16
	oldIndexName := fmt.Sprintf("tigera_secure_ee_events.%s.lma", cluster)
	resultIndex, err := client.CreateIndex(oldIndexName).Do(ctx)
	require.NoError(t, err)
	require.True(t, resultIndex.Acknowledged)

	aliasName := fmt.Sprintf("tigera_secure_ee_events.%s.", cluster)
	resultAlias, err := client.Alias().Action(elastic.NewAliasAddAction(aliasName).
		Index(oldIndexName).IsWriteIndex(true)).Do(ctx)
	require.NoError(t, err)
	require.True(t, resultAlias.Acknowledged)

	eventsTemplateConfig := templates.NewTemplateConfig(index.EventsMultiIndex, bapi.ClusterInfo{Cluster: cluster})
	templEvents, err := templates.DefaultBootstrapper(ctx, client, eventsTemplateConfig)
	require.NoError(t, err)
	require.NotNil(t, templEvents)
	require.Len(t, templEvents.IndexPatterns, 1)

	// Check that the template returned has the correct
	// index_patterns, ILM policy, mappings and shards and replicas
	checkMultiIndexTemplateBootstrapping(t, "tigera_secure_ee_events", "lma", cluster, "000000", 2, false)
}

func TestBootstrapTemplateMultipleTimes(t *testing.T) {
	defer setupTest(t, index.FlowLogMultiIndex)()

	templateConfig := templates.NewTemplateConfig(index.FlowLogMultiIndex, bapi.ClusterInfo{Cluster: cluster})

	for range 10 {
		_, err := templates.DefaultBootstrapper(ctx, client, templateConfig)
		require.NoError(t, err)
		checkMultiIndexTemplateBootstrapping(t, "tigera_secure_ee_flows", "fluentd", cluster, "000001", 1, true)
	}
}

func TestBootstrapTemplateNewMappings(t *testing.T) {
	defer setupTest(t, index.FlowLogMultiIndex)()

	// Let's keep track of the original EventsMappings and restore them after this test
	originalFlowLogMappings := templates.FlowLogMappings
	defer func() { templates.FlowLogMappings = originalFlowLogMappings }()

	// Let's modify them to remove an entry - simulate an earlier version
	logrus.Warn(templates.FlowLogMappings)
	var mappings map[string]any
	err := json.Unmarshal([]byte(templates.FlowLogMappings), &mappings)
	require.NoError(t, err)

	properties, ok := mappings["properties"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, properties, "dest_domains")
	delete(properties, "dest_domains")
	require.NotContains(t, properties, "dest_domains")

	mappings["properties"] = properties
	mappingsBytes, err := json.Marshal(mappings)
	require.NoError(t, err)
	templates.FlowLogMappings = string(mappingsBytes)

	// Check that the template returned has the correct
	// index_patterns, ILM policy, mappings and shards and replicas
	templateConfig := templates.NewTemplateConfig(index.FlowLogMultiIndex, bapi.ClusterInfo{Cluster: cluster})

	// Simulate 10 restarts and make sure we end up with 1 index (no rollover)
	for range 10 {
		templ, err := templates.DefaultBootstrapper(ctx, client, templateConfig)
		require.NoError(t, err)
		require.NotNil(t, templ)
		require.Len(t, templ.IndexPatterns, 1)

		checkMultiIndexTemplateBootstrapping(t, "tigera_secure_ee_flows", "fluentd", cluster, "000001", 1, true)
	}

	// We now have an older index (without "dest_domains")
	is, err := client.IndexGet(templateConfig.Alias()).Do(ctx)
	require.NoError(t, err)

	indexName := fmt.Sprintf("%s.%s.%s-%s-%s", "tigera_secure_ee_flows", cluster, "fluentd", time.Now().UTC().Format("20060102"), "000001")

	indexData := is[indexName]
	require.NotNil(t, indexData)

	indexMappings := indexData.Mappings
	indexProperties, ok := indexMappings["properties"].(map[string]any)
	require.True(t, ok)
	// We can retrieve a mapping
	_, ok = indexProperties["dest_name"].(map[string]any)
	require.True(t, ok)
	// But dest_domains is missing
	_, ok = indexProperties["dest_domains"].(map[string]any)
	require.False(t, ok)

	// Let's update the mapping (to simulate a version change of Linseed)
	templates.FlowLogMappings = originalFlowLogMappings
	templateConfig = templates.NewTemplateConfig(index.FlowLogMultiIndex, bapi.ClusterInfo{Cluster: cluster})

	// Simulate 10 restarts and make sure we end up with 2 indices (rolled-over only once)
	for range 10 {
		templ, err := templates.DefaultBootstrapper(ctx, client, templateConfig)
		require.NoError(t, err)
		require.NotNil(t, templ)
		require.Len(t, templ.IndexPatterns, 1)

		checkMultiIndexTemplateBootstrapping(t, "tigera_secure_ee_flows", "fluentd", cluster, "000002", 2, true)
	}
}

// This test checks that the mappings are well formed on disk
// by comparing them to the index mapping after applying them.
// This test typically fails when the mappings file encodes a value using the wrong data type
// (e.g. `"null_value": "0"` instead of `"null_value": 0`)
// While an incorrect type works (ES understands it), it messes up bootstrapping logic
// that compares the mappings defined in the file vs the current mappings used by the index.
func TestMappingsValidity(t *testing.T) {
	indices := []bapi.Index{
		index.FlowLogMultiIndex,
		index.DNSLogMultiIndex,
		index.L7LogMultiIndex,
		index.AuditLogEEMultiIndex,
		index.AuditLogKubeMultiIndex,
		index.BGPLogMultiIndex,
		index.EventsMultiIndex,
		index.WAFLogMultiIndex,
		index.ComplianceReportMultiIndex,
		index.ComplianceSnapshotMultiIndex,
		index.ComplianceBenchmarkMultiIndex,
		index.ThreatfeedsIPSetMultiIndex,
		index.ThreatfeedsDomainMultiIndex,
	}
	defer setupTest(t, indices...)()

	testMappingsValidity := func(t *testing.T, idx bapi.Index) {
		t.Run(fmt.Sprintf("%s-%s", t.Name(), idx.DataType()), func(t *testing.T) {
			clusterInfo := bapi.ClusterInfo{Cluster: cluster}

			// Create a template so that new index has the correct mappings
			config := templates.NewTemplateConfig(idx, clusterInfo)
			template, err := config.Template()
			require.NoError(t, err)

			_, err = client.IndexPutTemplate(config.TemplateName()).BodyJson(template).Do(ctx)
			require.NoError(t, err)

			// Get initial indexInfo
			indexInfo, err := templates.GetIndexInfo(ctx, client, config)
			require.NoError(t, err)

			// Sanity check that the index does not exists
			require.NoError(t, err)
			require.False(t, indexInfo.IndexExists)

			// Create the bootstrap index and mark it to be used for writes
			err = templates.CreateIndexAndAlias(ctx, client, config)
			require.NoError(t, err)

			// Update indexInfo following index creation
			indexInfo, err = templates.GetIndexInfo(ctx, client, config)
			require.NoError(t, err)

			require.True(t, indexInfo.WriteIndexDeclared)

			// If this fails, need to update mappings file
			require.Equal(t, indexInfo.Mappings, template.Mappings)
		})
	}

	for _, idx := range indices {
		testMappingsValidity(t, idx)
	}
}
