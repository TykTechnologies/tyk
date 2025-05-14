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

	err = generateBentoConfigSchema(tempFile.Name(), []customValidationRule{})
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

func TestAddURIFormatToHTTPClient(t *testing.T) {
	// temporary directory will be automatically removed when the test complete.
	tempFile, err := os.CreateTemp(t.TempDir(), "test-output-*.json")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer func() {
		require.NoError(t, tempFile.Close())
	}()

	err = generateBentoConfigSchema(tempFile.Name(), []customValidationRule{
		&addURIFormatToHTTPClient{},
	})
	require.NoError(t, err)

	file, err := os.Open(tempFile.Name())
	require.NoError(t, err)

	input, err := io.ReadAll(file)
	require.NoError(t, err)

	for _, kind := range []string{"input", "output"} {
		data, dataType, _, err := jsonparser.Get(input, "definitions", kind, "properties", "http_client", "properties", "url", "format")
		require.NoError(t, err)
		require.Equal(t, jsonparser.String, dataType)
		require.Equal(t, "uri", string(data))
	}
}
