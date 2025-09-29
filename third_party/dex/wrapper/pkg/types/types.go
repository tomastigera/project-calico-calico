// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package types

import "time"

// Environment variable names used by the wrapper
const (
	EnvClientID     = "CLIENT_ID"
	EnvClientSecret = "CLIENT_SECRET"
	EnvBindDN       = "BIND_DN"
	EnvBindPW       = "BIND_PW"
	EnvAdminEmail   = "ADMIN_EMAIL"
	EnvWatchDir     = "WATCH_DIR"
)

// Filenames used within WATCH_DIR
const (
	FileClientID             = "clientID"
	FileClientSecret         = "clientSecret"
	FileBindDN               = "bindDN"
	FileBindPW               = "bindPW"
	FileAdminEmail           = "adminEmail"
	FileServiceAccountSecret = "serviceAccountSecret"
	FileRootCA               = "rootCA"
)

// Connector config field keys
const (
	ConnectorFieldAdminEmail         = "adminEmail"
	ConnectorFieldServiceAccountFile = "serviceAccountFilePath"
	ConnectorFieldRootCA             = "rootCA"
)

// WatchedFilenames lists the filenames under WATCH_DIR that should trigger dex restarts
var WatchedFilenames = []string{
	FileClientID,
	FileClientSecret,
	FileServiceAccountSecret,
	FileAdminEmail,
	FileRootCA,
	FileBindDN,
	FileBindPW,
}

// Paths and process-related constants
const (
	DexBinary            = "/usr/bin/dex"
	BaseConfigPath       = "/etc/dex/baseCfg/config.yaml"
	RuntimeDexConfigPath = "/tmp/dex-config.yaml"
)

const DexStartupWaitTime = 2 * time.Second

const GracefulShutdownTimeout = 10 * time.Second

// DebounceRestartDelay is the delay window to coalesce multiple file change events
const DebounceRestartDelay = 10 * time.Second
