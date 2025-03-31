package main

import (
	"io"
	"os"
	"testing"

	"github.com/buger/jsonparser"
	"github.com/stretchr/testify/require"
)

func TestGenerateBentoConfigSchema(t *testing.T) {
	// temporary directory will be automatically removed when the test complete.
	tempFile, err := os.CreateTemp(t.TempDir(), "test-output-*.json")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer func() {
		require.NoError(t, tempFile.Close())
	}()

	err = generateBentoConfigSchema(tempFile.Name())
	require.NoError(t, err)

	file, err := os.Open(tempFile.Name())
	require.NoError(t, err)

	data, err := io.ReadAll(file)
	require.NoError(t, err)

	var definitionKinds = []string{"input", "output"}
	for _, definitionKind := range definitionKinds {
		for _, source := range supportedSources {
			_, _, _, err = jsonparser.Get(data, "definitions", definitionKind, "properties", source)
			require.NoError(t, err)
		}
	}
}
