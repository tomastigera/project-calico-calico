// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package templates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/olivere/elastic/v7"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/linseed/pkg/backend/api"
	lmaelastic "github.com/projectcalico/calico/linseed/pkg/internal/lma/elastic"
)

// Event indices prior to 3.17 were created to match the pattern tigera_secure_ee_events.{$managed_cluster}.lma
// or tigera_secure_ee_events.{$tenant_id}.{$managed_cluster}.lma. This constant matches the legacy index structure.
const legacyEventsFormat = "^(tigera_secure_ee_events.).+(.lma)$"

type IndexInfo struct {
	WriteIndexDeclared bool
	IndexExists        bool
	WriteIndexName     string
	Mappings           map[string]any
	Shards             int
	Replicas           int
	ILMPolicy          string
}

func (index IndexInfo) HasMappings(mappings map[string]any) bool {
	// We need to compare the mappings as JSON strings because deep equal
	// doesn't work well with maps that have interface{} values, as field types may be
	// slightly different even if the values are the same.
	liveMappings, err := json.Marshal(index.Mappings)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal live mappings")
		return false
	}

	expectedMappings, err := json.Marshal(mappings)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal expected mappings")
		return false
	}

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		logrus.Debugf("Actual mappings:   %s", liveMappings)
		logrus.Debugf("Expected mappings: %s", expectedMappings)
	}

	return reflect.DeepEqual(liveMappings, expectedMappings)
}

func (index IndexInfo) HasSettingsUpToDate(config *TemplateConfig) bool {
	if !index.IndexExists {
		// Index does not exist to compare the settings
		return false
	}

	// Compare the saved settings with the recently fetched setting
	settings := config.settings()
	expectedShards, foundShards := settings["number_of_shards"]
	expectedReplicas, foundReplicas := settings["number_of_replicas"]
	lifeCycleEnabled := config.hasLifecycleEnabled()
	var expectedILMPolicyName string
	if lifeCycleEnabled {
		// ILM policy is created by the operator and only referenced by the template
		expectedILMPolicyName = config.Index.ILMPolicyName()
	}

	logrus.Debugf("Actual Settings, shard:%d , replica:%d, ILMPolicyName:%s", index.Shards, index.Replicas, index.ILMPolicy)
	logrus.Debugf("Expected Settings, shard:%d , replica:%d, ILMPolicyName:%s", expectedShards, expectedReplicas, expectedILMPolicyName)

	// Config does not have shards but the latest index have shards or
	// Config have shards, and it does not match the current index setting
	if (!foundShards && index.Shards != 0) || (foundShards && expectedShards != index.Shards) {
		return false
	}

	if (!foundReplicas && index.Replicas != 0) || (foundReplicas && expectedReplicas != index.Replicas) {
		return false
	}

	if len(expectedILMPolicyName) > 0 && index.ILMPolicy != expectedILMPolicyName {
		return false
	}
	return true
}

// DefaultBootstrapper creates an index template for the give log type and cluster information
// pairing and create a bootstrap index that uses that template
var DefaultBootstrapper Bootstrapper = func(ctx context.Context, client *elastic.Client, config *TemplateConfig) (*Template, error) {
	// Get some info about the index in ES
	indexInfo, err := GetIndexInfo(ctx, client, config)
	if err != nil {
		return nil, err
	}

	// Get template for the index
	templateName := config.TemplateName()
	template, err := config.Template()
	if err != nil {
		return nil, err
	}

	isSettingsUpToDate := indexInfo.HasSettingsUpToDate(config)

	// Check if the index mappings are up to date.
	// Please note that we only compare the mappings.
	// One could argue that similar logic should be done to detect settings changes.
	// This is possible, but we would need to ignore the following fields: provided_name, creation_date, uuid, version.
	// To keep things simple, we'll ignore this and assume that we're unlikely to update the settings without updating the mappings...
	if indexInfo.HasMappings(template.Mappings) && isSettingsUpToDate {
		logrus.Debug("Existing index already uses the latest mappings")
		return template, nil
	}
	// Mappings are out of date or do not exist.

	// Create/Update the index template in Elastic. This is idempotent, so we can call it every time.
	logrus.WithField("name", templateName).Info("Creating index template")
	_, err = client.IndexPutTemplate(templateName).BodyJson(template).Do(ctx)
	if err != nil {
		logrus.WithError(err).Error("failed to create/update index template")
		return nil, err
	}

	if indexInfo.WriteIndexDeclared {
		if shouldRollover(indexInfo, config) || !isSettingsUpToDate {
			// Rollover index to get latest mappings
			err = RolloverIndex(ctx, client, config, indexInfo.WriteIndexName)
			if err != nil {
				logrus.WithError(err).Error("failed to roll over index")
				return nil, err
			}
		}
	} else if !indexInfo.IndexExists {
		// data comes in for the first time
		// The alias doesn't exist, and neither does the index - create both the index and alias
		err = CreateIndexAndAlias(ctx, client, config)
		if lmaelastic.IsAlreadyExists(err) {
			// If we get an already exists error, it means we conflicted with another client.
			// We can safely ignore this and continue, but make sure we log it out.
			logrus.WithError(err).Info("Index and alias already exist, continuing")
		} else if err != nil {
			logrus.WithError(err).Error("failed to create index and alias")
			return nil, err
		}
	} else if !indexInfo.WriteIndexDeclared {
		// Alias doesn't exist, but the index does
		err = CreateAliasForIndex(ctx, client, config)
		if lmaelastic.IsAlreadyExists(err) {
			// If we get an already exists error, it means we conflicted with another client.
			// We can safely ignore this and continue, but make sure we log it out.
			logrus.WithError(err).Info("Alias already exists, continuing")
		} else if err != nil {
			logrus.WithError(err).Error("Failed to create alias for index")
			return nil, err
		}
	}

	return template, nil
}

// getIndexSettings retrieves the Index settings for an index.
func (index *IndexInfo) getIndexSettings(settings map[string]any) error {
	indexSettings, ok := settings["index"].(map[string]any)
	if !ok {
		return errors.New("index settings not found")
	}

	// Extract properties from settings
	shards, err := extractPropertyFromSettings(indexSettings, "number_of_shards")
	if err != nil {
		return fmt.Errorf("failed to extract shards property: %v", err)
	}

	replicas, err := extractPropertyFromSettings(indexSettings, "number_of_replicas")
	if err != nil {
		return fmt.Errorf("failed to extract replicas property: %v", err)
	}

	// ILM policy will be part of lifecycle map
	// Some index may not have ILM policy eg: tigera_secure_ee_threatfeeds_ipset , tigera_secure_ee_threatfeeds_domainnameset
	indexSettings, ok = indexSettings["lifecycle"].(map[string]any)
	if ok {
		ilmPolicy, err := extractPropertyFromSettings(indexSettings, "name")
		if err != nil {
			return fmt.Errorf("failed to extract ilm_policy property: %v", err)
		}
		index.ILMPolicy = ilmPolicy
	}

	// Set values in the IndexInfo struct
	index.Shards, err = strconv.Atoi(shards)
	if err != nil {
		return fmt.Errorf("failed to convert shards to integer: %v", err)
	}

	index.Replicas, err = strconv.Atoi(replicas)
	if err != nil {
		return fmt.Errorf("failed to convert replicas to integer: %v", err)
	}

	return nil
}

func extractPropertyFromSettings(settings map[string]any, propertyName string) (string, error) {
	propertyValue, ok := settings[propertyName].(string)
	if !ok {
		return "", fmt.Errorf("property '%s' not found", propertyName)
	}

	return propertyValue, nil
}

// shouldRollover returns whether or not an index with out-of-date mappings should be rolled over.
// For most indices, we want to rollover the index if the mappings are out of date. There are exceptions:
//   - If the index is ReportData or Events, it is expected that the mappings won't match and so we shouldn't
//     roll over the index unless other indicators suggest that we should.
func shouldRollover(indexInfo IndexInfo, config *TemplateConfig) bool {
	// Skip rollover for these types since the mappings for this index are not fully
	// specified in the Linseed code, and so we can't be sure that the mappings are out of date.
	switch config.Index.DataType() {
	case api.ReportData:
		return false
	case api.AuditEELogs:
		return false
	case api.AuditKubeLogs:
		return false
	}

	// If we reach this point, it means that the index and alias exist, don't match any of the above exceptions,
	// and have mappings that are out of date. Thus, we should rollover the index.
	return true
}

func GetIndexInfo(ctx context.Context, client *elastic.Client, config *TemplateConfig) (index IndexInfo, err error) {
	// Check if the alias already exists
	logrus.WithField("name", config.Alias()).Debug("Checking if alias exists")
	response, err := client.CatAliases().Alias(config.Alias()).Do(ctx)
	if err != nil {
		return index, err
	}
	logrus.WithField("response", response).Debug("CatAliases response")

	for _, row := range response {
		logrus.WithField("row", row).Debug("Checking if row is a matching write index")
		if row.Alias == config.Alias() && row.IsWriteIndex == "true" {
			logrus.WithField("row", row).Debug("Found matching write index")
			index.WriteIndexDeclared = true
			index.WriteIndexName = row.Index
			break
		}
	}

	if index.WriteIndexDeclared {
		// Alias exists. This means that the index was setup previously.
		log := logrus.WithFields(logrus.Fields{"alias": config.Alias(), "index": index.WriteIndexName})
		log.Info("Alias exists for index")

		ir, err := client.IndexGet(index.WriteIndexName).Do(ctx)
		if err != nil {
			return index, err
		}
		index.IndexExists = true
		log.WithField("response", ir).Debug("IndexGet response")

		// Get mappings
		index.Mappings = ir[index.WriteIndexName].Mappings
		if index.Mappings == nil {
			return index, fmt.Errorf("failed to get index mappings")
		}
		log.WithField("mappings", index.Mappings).Debug("Loaded mappings")

		// Deal with odd "dynamic" property
		err = updateMappingsDynamicProperty(index.Mappings)
		if err != nil {
			return index, err
		}

		// Get settings
		err = index.getIndexSettings(ir[index.WriteIndexName].Settings)
		if err != nil {
			return index, err
		}

	} else {
		// Check if index exists even though it's not aliased
		logrus.WithField("index", config.BootstrapIndexName()).Info("No alias exists for index")
		index.IndexExists, err = client.IndexExists(config.BootstrapIndexName()).Do(ctx)
		if err != nil {
			return index, err
		}
	}

	return index, nil
}

// The "dynamic" property is an odd one. We typically use `"dynamic": false` in our mapping files
// and the docs suggest that's correct: https://www.elastic.co/guide/en/elasticsearch/reference/7.17/dynamic-field-mapping.html
// However when reading the mappings from the index, we get `"dynamic": "false"`, probably because
// the "dynamic" property can accept multiple types, and is just serialized as a string for some reason...
func updateMappingsDynamicProperty(mappings map[string]any) error {
	if mappings["dynamic"] != nil {
		if reflect.TypeOf(mappings["dynamic"]) == reflect.TypeFor[string]() {
			s, ok := mappings["dynamic"].(string)
			if !ok {
				return fmt.Errorf("dynamic property in not a string (%v)", mappings["dynamic"])
			}

			if s == "false" {
				mappings["dynamic"] = false
			}
			if s == "true" {
				mappings["dynamic"] = true
			}
		}
	}
	return nil
}

func CreateIndexAndAlias(ctx context.Context, client *elastic.Client, config *TemplateConfig) error {
	logrus.WithField("name", config.BootstrapIndexName()).Infof("Creating bootstrap index")
	aliasJson := fmt.Sprintf(`{"%s": {"is_write_index": true}}`, config.Alias())

	// Create the bootstrap index and mark it to be used for writes
	response, err := client.
		CreateIndex(config.BootstrapIndexName()).
		BodyJson(map[string]any{"aliases": json.RawMessage(aliasJson)}).
		Do(ctx)
	if err != nil {
		return err
	}
	if !response.Acknowledged {
		return fmt.Errorf("failed to acknowledge index creation")
	}
	logrus.WithField("name", response.Index).Info("Bootstrap index created")
	return nil
}

func CreateAliasForIndex(ctx context.Context, client *elastic.Client, config *TemplateConfig) error {
	logrus.WithField("name", config.BootstrapIndexName()).Infof("Creating alias for index")
	_, err := client.Alias().Add(config.BootstrapIndexName(), config.Alias()).Do(ctx)
	return err
}

func RolloverIndex(ctx context.Context, client *elastic.Client, config *TemplateConfig, oldIndex string) error {
	logrus.Info("Existing index does not use the latest mappings or shards or replicas or ILM policy, let's rollover the index so that it uses the latest")
	rolloverReq := client.RolloverIndex(config.Alias())

	// Event indices prior to 3.17 were created to match the pattern tigera_secure_ee_events.{$managed_cluster}.lma
	// or tigera_secure_ee_events.{$tenant_id}.{$managed_cluster}.lma. Because the index does
	// not have a suffix like `-000000` or `-0`, which will result in an error when trying to perform a roll-over request.
	// We need to specify an index that ends in a number as a target-index on the Elastic API calls
	match, err := regexp.MatchString(legacyEventsFormat, oldIndex)
	if err != nil {
		return err
	}
	if match {
		logrus.Infof("Existing index %s does not end in an number. Will need to specify a index that ends with a number", oldIndex)
		rolloverReq.NewIndex(config.BootstrapIndexName())
	}

	// Perform the rollover.
	response, err := rolloverReq.Do(ctx)
	if err != nil {
		return err
	}
	if !response.Acknowledged {
		return fmt.Errorf("failed to acknowledge index rollover")
	}
	if response.RolledOver {
		logrus.Infof("Rolled over index %s to index %s", response.OldIndex, response.NewIndex)
	} else {
		logrus.Infof("Did not rollover index %s", response.OldIndex)
	}
	return nil
}
