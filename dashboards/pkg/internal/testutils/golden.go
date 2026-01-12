package testutils

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func ExpectMatchesGoldenYaml(t *testing.T, filename string, actual any) {
	var err error
	goldenPath := fmt.Sprintf("testdata/%s-golden.yaml", filename)
	actualPath := fmt.Sprintf("testdata/%s-actual.yaml", filename)

	actualBytes, err := yaml.Marshal(actual)
	require.NoError(t, err)

	expectedBytes, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	actualString := string(actualBytes)
	expectedString := string(expectedBytes)

	// write the actual file only if it is different to the expected, otherwise remove it
	if actualString != expectedString {
		require.NoError(t, os.WriteFile(actualPath, actualBytes, 0755))
	} else {
		_ = os.Remove(actualPath)
	}

	require.Equal(t, expectedString, actualString,
		fmt.Sprintf("goldenFile: %s, actualFile: %s", goldenPath, actualPath),
	)
}
