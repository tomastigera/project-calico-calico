// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package templates

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/json"
	bapi "github.com/projectcalico/calico/linseed/pkg/backend/api"
)

// Template is the internal representation of an Elastic template
type Template struct {
	IndexPatterns []string               `json:"index_patterns,omitempty"`
	Settings      map[string]interface{} `json:"settings,omitempty"`
	Mappings      map[string]interface{} `json:"mappings,omitempty"`
}

// TemplateConfig is the configuration used to create a template
// in Elastic. A template has associated an ILM policy, index patterns
// mappings, settings and a bootstrap index to perform rollover
type TemplateConfig struct {
	Index    bapi.Index
	info     bapi.ClusterInfo
	shards   int
	replicas int
}

// NewTemplateConfig will build a TemplateConfig based on the logs type, cluster information
// and provided Option(s)
func NewTemplateConfig(index bapi.Index, info bapi.ClusterInfo, opts ...Option) *TemplateConfig {
	defaultConfig := &TemplateConfig{Index: index, info: info, shards: 1, replicas: 0}

	for _, opt := range opts {
		defaultConfig = opt(defaultConfig)
	}

	return defaultConfig
}

// Option will customize different values for a TemplateConfig
type Option func(config *TemplateConfig) *TemplateConfig

// WithReplicas will set the number of replicas to be used
// for an index template
func WithReplicas(replicas int) Option {
	return func(config *TemplateConfig) *TemplateConfig {
		config.replicas = replicas
		return config
	}
}

// WithShards will set the number of shards to be used
// for an index template
func WithShards(shards int) Option {
	return func(config *TemplateConfig) *TemplateConfig {
		config.shards = shards
		return config
	}
}

// TemplateName will provide the name of the template
func (c *TemplateConfig) TemplateName() string {
	return c.Index.IndexTemplateName(c.info)
}

func (c *TemplateConfig) Alias() string {
	return c.Index.Alias(c.info)
}

func (c *TemplateConfig) indexPatterns() string {
	return c.Index.Index(c.info)
}

func (c *TemplateConfig) mappings() string {
	switch c.Index.DataType() {
	case bapi.FlowLogs:
		return FlowLogMappings
	case bapi.DNSLogs:
		return DNSLogMappings
	case bapi.L7Logs:
		return L7LogMappings
	case bapi.AuditKubeLogs, bapi.AuditEELogs:
		return AuditMappings
	case bapi.BGPLogs:
		return BGPMappings
	case bapi.Events:
		return EventsMappings
	case bapi.WAFLogs:
		return WAFMappings
	case bapi.ReportData:
		return ReportMappings
	case bapi.Benchmarks:
		return BenchmarksMappings
	case bapi.Snapshots:
		return SnapshotMappings
	case bapi.RuntimeReports:
		return RuntimeReportsMappings
	case bapi.IPSet:
		return IPSetMappings
	case bapi.DomainNameSet:
		return DomainSetMappings
	case bapi.PolicyActivity:
		return PolicyActivityMappings

	default:
		panic("data type not implemented")
	}
}

// BootstrapIndexName will construct the bootstrap index name
// to be used for rollover
func (c *TemplateConfig) BootstrapIndexName() string {
	return c.Index.BootstrapIndexName(c.info)
}

func (c *TemplateConfig) settings() map[string]interface{} {
	// DNS logs requires additional settings to
	// number of shards and replicas
	indexSettings := c.initIndexSettings()
	indexSettings["number_of_shards"] = c.shards
	indexSettings["number_of_replicas"] = c.replicas

	lifeCycleEnabled := c.hasLifecycleEnabled()
	if lifeCycleEnabled {
		lifeCycle := make(map[string]interface{})
		// ILM policy is created by the operator and only referenced by the template
		lifeCycle["name"] = c.Index.ILMPolicyName()
		lifeCycle["rollover_alias"] = c.Index.Alias(c.info)
		indexSettings["lifecycle"] = lifeCycle
	}

	return indexSettings
}

// initIndexSettings will unmarshal other indexSettings for the index
// (that do not cover number of shards and replicas) if they have been
// defined in SettingsLookup or an empty map otherwise
func (c *TemplateConfig) initIndexSettings() map[string]interface{} {
	settingsName, ok := SettingsLookup[c.Index.DataType()]
	if !ok {
		return make(map[string]interface{})
	}

	indexSettings, err := unmarshal(settingsName)
	if err != nil {
		logrus.WithError(err).Fatal("failed to parse dns settings from embedded file")
	}

	return indexSettings
}

// Template will create an internal representation of the
// template to be created in Elastic
func (c *TemplateConfig) Template() (*Template, error) {
	mappings := c.mappings()
	settings := c.settings()
	indexPatterns := c.indexPatterns()

	// Convert mapping to map[string]interface{}
	indexMappings, err := unmarshal(mappings)
	if err != nil {
		return nil, err
	}

	// For single-index templates, the mappings must include keywords for tenant.
	if c.Index.IsSingleIndex() {
		properties := indexMappings["properties"].(map[string]interface{})
		properties["tenant"] = map[string]string{"type": "keyword"}
	}

	return &Template{
		IndexPatterns: []string{indexPatterns},
		Settings:      settings,
		Mappings:      indexMappings,
	}, nil
}

func (c *TemplateConfig) hasLifecycleEnabled() bool {
	enabled, ok := LifeCycleEnabledLookup[c.Index.DataType()]
	if !ok {
		panic(fmt.Sprintf("ILM policies need to be defined for %s", c.Index.DataType()))
	}

	return enabled
}

func unmarshal(source string) (map[string]interface{}, error) {
	var value map[string]interface{}
	if err := json.Unmarshal([]byte(source), &value); err != nil {
		return nil, err
	}
	return value, nil
}
