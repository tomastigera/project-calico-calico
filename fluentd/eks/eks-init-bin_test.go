// Copyright (c) 2019-2026 Tigera Inc. All rights reserved.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEksInitBin(t *testing.T) {
	testDir := t.TempDir() + "/"
	testFile := "test-state"
	testStateTokens := map[string]string{
		testFile: "test-token",
	}

	err := generateStateFile(testDir, testStateTokens)
	require.NoError(t, err)
	assert.True(t, fileExists(testDir+testFile))
	assert.Equal(t, "test-token", matchesToken(testDir+testFile))
}

func TestGenerateStateFileMultipleEntries(t *testing.T) {
	testDir := t.TempDir() + "/"
	testStateTokens := map[string]string{
		"state-a": "token-a",
		"state-b": "token-b",
	}

	err := generateStateFile(testDir, testStateTokens)
	require.NoError(t, err)

	for file, token := range testStateTokens {
		assert.True(t, fileExists(testDir+file))
		assert.Equal(t, token, matchesToken(testDir+file))
	}
}

func TestWriteStateFileTruncatesExistingContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state-file")

	// Write a long token first.
	err := writeStateFile(path, "this-is-a-long-token-value")
	require.NoError(t, err)
	assert.Equal(t, "this-is-a-long-token-value", matchesToken(path))

	// Overwrite with a shorter token; old content must not remain.
	err = writeStateFile(path, "short")
	require.NoError(t, err)
	assert.Equal(t, "short", matchesToken(path))
}

func TestWriteStateFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state-file")

	err := writeStateFile(path, "token")
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestGenerateStateFileEmptyMap(t *testing.T) {
	testDir := t.TempDir() + "/"

	err := generateStateFile(testDir, map[string]string{})
	require.NoError(t, err)

	// Directory should remain empty — no files created.
	entries, err := os.ReadDir(testDir)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestWriteStateFileEmptyToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state-file")

	err := writeStateFile(path, "")
	require.NoError(t, err)
	assert.Equal(t, "", matchesToken(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(0), info.Size())
}

func TestGenerateStateFileInvalidDir(t *testing.T) {
	err := generateStateFile("/nonexistent/path/", map[string]string{
		"file": "token",
	})
	require.Error(t, err)
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

func matchesToken(filePath string) string {
	token, err := os.ReadFile(filePath)
	if err == nil {
		return string(token)
	}

	return ""
}
