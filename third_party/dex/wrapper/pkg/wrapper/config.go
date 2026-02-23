// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package wrapper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/projectcalico/calico/third_party/dex/wrapper/pkg/types"
)

// BuildDexRuntimeConfig reads secrets from files and sets env vars accordingly. It also writes a runtime Dex config,
// setting connector fields based on env/WATCH_DIR
func (d *DexWrapper) BuildDexRuntimeConfig() error {
	log.Infof("setting up environment variables from files in %s...", d.watchDir)

	if content, ok := readFileContent(filepath.Join(d.watchDir, types.FileClientID), types.EnvClientID); ok {
		if err := os.Setenv(types.EnvClientID, content); err != nil {
			return err
		}
		log.Infof("%q set from file", types.EnvClientID)
	}
	if content, ok := readFileContent(filepath.Join(d.watchDir, types.FileClientSecret), types.EnvClientSecret); ok {
		if err := os.Setenv(types.EnvClientSecret, content); err != nil {
			return err
		}
		log.Infof("%q set from file", types.EnvClientSecret)
	}
	if content, ok := readFileContent(filepath.Join(d.watchDir, types.FileBindDN), types.EnvBindDN); ok {
		if err := os.Setenv(types.EnvBindDN, content); err != nil {
			return err
		}
		log.Infof("%q set from file", types.EnvBindDN)
	}
	if content, ok := readFileContent(filepath.Join(d.watchDir, types.FileBindPW), types.EnvBindPW); ok {
		if err := os.Setenv(types.EnvBindPW, content); err != nil {
			return err
		}
		log.Infof("%q set from file", types.EnvBindPW)
	}
	if content, ok := readFileContent(filepath.Join(d.watchDir, types.FileAdminEmail), types.EnvAdminEmail); ok {
		if err := os.Setenv(types.EnvAdminEmail, content); err != nil {
			return err
		}
		log.Infof("%q set from file", types.EnvAdminEmail)
	}

	log.Info("environment variables setup completed")

	base, err := os.ReadFile(d.dexBaseConfigPath)
	if err != nil {
		return fmt.Errorf("reading base config: %w", err)
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(base, &cfg); err != nil {
		return fmt.Errorf("parsing base config: %w", err)
	}

	connectorFields := d.parseExtraConnectorFields()
	applyConnectorFields(cfg, connectorFields)

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("serializing runtime config: %w", err)
	}
	if err := os.WriteFile(types.RuntimeDexConfigPath, out, 0o644); err != nil {
		return fmt.Errorf("writing runtime config: %w", err)
	}
	d.dexRuntimeConfigPath = types.RuntimeDexConfigPath
	return nil
}

func readFileContent(path, varName string) (content string, ok bool) {
	info, err := os.Stat(path)
	if err != nil {
		log.Warnf("file not found, skipping: %s (for %q)", path, varName)
		return
	}
	if info.IsDir() {
		log.Warnf("path is a directory, skipping: %s (for %q)", path, varName)
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		log.Warnf("cannot read file, skipping: %s (for %q)", path, varName)
		return
	}
	content = strings.TrimRight(string(b), "\r\n")
	if content == "" {
		log.Warnf("file is empty, skipping: %s (for %q)", path, varName)
		return
	}
	ok = true
	return
}

// applyConnectorFields sets connector fields on cfg.connectors[*].config without OS/file interactions.
// It is a pure function suitable for unit testing.
func applyConnectorFields(cfg, connectorFields map[string]any) {
	m := cfg
	conns, ok := m["connectors"].([]map[string]any)
	if !ok {
		return
	}
	for _, cm := range conns {
		conf, ok := cm["config"].(map[string]any)
		if !ok {
			continue
		}
		if adminEmail, ok := connectorFields[types.ConnectorFieldAdminEmail]; adminEmail != "" && ok {
			conf[types.ConnectorFieldAdminEmail] = adminEmail
		}
		if serviceAccountFilePath, ok := connectorFields[types.ConnectorFieldServiceAccountFile]; serviceAccountFilePath != "" && ok {
			conf[types.ConnectorFieldServiceAccountFile] = serviceAccountFilePath
		}
		if rootCAPath, ok := connectorFields[types.ConnectorFieldRootCA]; rootCAPath != "" && ok {
			conf[types.ConnectorFieldRootCA] = rootCAPath
		}
	}
}

// parseExtraConnectorFields collects extra connector fields based on environment and files under watch dir.
func (d *DexWrapper) parseExtraConnectorFields() map[string]any {
	admin := os.Getenv(types.EnvAdminEmail)
	extraCfg := map[string]any{}
	if admin != "" {
		extraCfg[types.ConnectorFieldAdminEmail] = admin
	}
	if d.watchDir != "" {
		if _, err := os.Stat(filepath.Join(d.watchDir, types.FileServiceAccountSecret)); err == nil {
			extraCfg[types.ConnectorFieldServiceAccountFile] = filepath.Join(d.watchDir, types.FileServiceAccountSecret)
		}
		if _, err := os.Stat(filepath.Join(d.watchDir, types.FileRootCA)); err == nil {
			extraCfg[types.ConnectorFieldRootCA] = filepath.Join(d.watchDir, types.FileRootCA)
		}
	}
	return extraCfg
}
