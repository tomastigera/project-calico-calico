// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package testutils

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func MustUnmarshalToMap(t *testing.T, source string) map[string]any {
	var val map[string]any
	err := json.Unmarshal([]byte(source), &val)
	require.NoError(t, err)
	return val
}

func Marshal(t *testing.T, response any) string {
	newData, err := json.Marshal(response)
	require.NoError(t, err)

	return string(newData)
}

func MarshalBulkParams[T any](bulkParams []T) string {
	var logs []string

	for _, p := range bulkParams {
		newData, err := json.Marshal(p)
		if err != nil {
			panic(err)
		}
		logs = append(logs, string(newData))
	}

	return strings.Join(logs, "\n")
}
