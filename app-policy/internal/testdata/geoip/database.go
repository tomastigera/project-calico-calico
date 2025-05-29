package geoip

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

//go:embed dbip-city-lite.mmdb
var DBIPCityLite []byte

const (
	// DatabaseTypeCity is the type of the database that contains city information.
	DatabaseTypeCity = "city"
)

func isCityDatabaseAvailable() bool {
	return len(DBIPCityLite) > 0
}

func SetupGeoIPDBTempDirFile(t *testing.T) (string, string, error) {
	if !isCityDatabaseAvailable() {
		return "", "", errors.New("dbip City Lite database is not available")
	}
	tempDir := t.TempDir()
	databaseFilePath := filepath.Join(tempDir, "dbip-city-lite.mmdb")
	databaseFileType := DatabaseTypeCity
	if err := os.WriteFile(databaseFilePath, DBIPCityLite, 0644); err != nil {
		return "", "", fmt.Errorf("failed to write file: %s", err)
	}
	return databaseFilePath, databaseFileType, nil
}
