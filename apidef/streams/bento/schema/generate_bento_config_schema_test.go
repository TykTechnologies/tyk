//go:build ee || dev

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
		&addURIFormatToHTTPClientRule{},
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

func TestAddURIFormatToHTTPClient_Malformed_input(t *testing.T) {
	rule := &addURIFormatToHTTPClientRule{}

	t.Run("Key path not found", func(t *testing.T) {
		_, err := rule.Apply([]byte(`{}`))
		require.Errorf(t, err, "error while applying add_uri_format_to_http_client rule, getting URL property returned: Key path not found")
	})

	t.Run("Unknown value type", func(t *testing.T) {
		var err error
		input := []byte(`{}`)
		for _, kind := range []string{"input", "output"} {
			// Value type must be an object.
			input, err = jsonparser.Set(input, []byte("some-string"), "definitions", kind, "properties", "http_client", "properties", "url")
			require.NoError(t, err)
		}

		_, err = rule.Apply(input)
		require.ErrorContains(t, err, "error while applying add_uri_format_to_http_client rule, getting URL property returned: Unknown value type")
	})

	t.Run("URL property is not an object", func(t *testing.T) {
		var err error
		input := []byte(`{}`)
		for _, kind := range []string{"input", "output"} {
			// Value type must be an object.
			input, err = jsonparser.Set(input, []byte("\"some-string\""), "definitions", kind, "properties", "http_client", "properties", "url")
			require.NoError(t, err)
		}

		_, err = rule.Apply(input)
		require.ErrorContains(t, err, "error while applying add_uri_format_to_http_client rule, URL property is not an object")
	})

	t.Run("Malformed url object", func(t *testing.T) {
		input := []byte(`{}`)
		data := "some-string"
		_, err := rule.setModifiedURLSection(input, []byte(data), "some", "path")
		require.ErrorIs(t, err, jsonparser.KeyPathNotFoundError)
	})
}
