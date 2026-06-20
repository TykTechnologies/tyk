package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/buger/jsonparser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reqproofFailingRule struct{}

func (r reqproofFailingRule) Name() string {
	return "reqproof_failing_rule"
}

func (r reqproofFailingRule) Apply([]byte) ([]byte, error) {
	return nil, errors.New("rule failed")
}

func resetReqProofGeneratorResult(t *testing.T) {
	t.Helper()

	original := result
	result = []byte(`{}`)
	t.Cleanup(func() {
		result = original
	})
}

// Verifies: SYS-REQ-104, SW-REQ-094
// SW-REQ-094:nominal:nominal
// SW-REQ-094:boundary:nominal
// SW-REQ-094:error_handling:negative
// SW-REQ-094:determinism:nominal
func TestBentoConfigSchemaGeneratorPreservesSupportBehavior(t *testing.T) {
	sampleSchema := []byte(`{
		"properties": {
			"http": {"type": "object"},
			"input": {"type": "object"},
			"output": {"type": "object"},
			"ignored": {"type": "object"}
		},
		"definitions": {
			"processor": {"type": "object", "description": "processor"},
			"scanner": {"type": "object", "description": "scanner"},
			"input": {
				"allOf": [
					{"properties": {"input_base": {"type": "object"}}},
					{"anyOf": [
						{"properties": {
							"broker": {"type": "object"},
							"http_client": {"properties": {"url": {"type": "string"}}},
							"unsupported": {"type": "object"}
						}}
					]}
				]
			},
			"output": {
				"allOf": [
					{"properties": {"output_base": {"type": "object"}}},
					{"anyOf": [
						{"properties": {
							"kafka": {"type": "object"},
							"http_client": {"properties": {"url": {"type": "string"}}}
						}}
					]}
				]
			}
		}
	}`)

	t.Run("helper extraction preserves selected properties and supported definitions", func(t *testing.T) {
		resetReqProofGeneratorResult(t)

		propertiesData, _, _, err := jsonparser.Get(sampleSchema, "properties")
		require.NoError(t, err)
		require.NoError(t, scanProperties(propertiesData))

		_, _, _, err = jsonparser.Get(result, "properties", "http")
		require.NoError(t, err)
		_, _, _, err = jsonparser.Get(result, "properties", "input")
		require.NoError(t, err)
		_, _, _, err = jsonparser.Get(result, "properties", "ignored")
		assert.ErrorIs(t, err, jsonparser.KeyPathNotFoundError)

		definitionsData, _, _, err := jsonparser.Get(sampleSchema, "definitions")
		require.NoError(t, err)
		require.NoError(t, scanDefinitions(definitionsData))

		for _, path := range [][]string{
			{"definitions", "processor"},
			{"definitions", "scanner"},
			{"definitions", "input", "properties", "broker"},
			{"definitions", "input", "properties", "http_client"},
			{"definitions", "output", "properties", "kafka"},
			{"definitions", "output", "properties", "http_client"},
		} {
			_, _, _, err = jsonparser.Get(result, path...)
			assert.NoError(t, err)
		}
		_, _, _, err = jsonparser.Get(result, "definitions", "input", "properties", "unsupported")
		assert.ErrorIs(t, err, jsonparser.KeyPathNotFoundError)
	})

	t.Run("malformed helper inputs return explicit errors", func(t *testing.T) {
		_, err := findTemplate("input", []byte(`{"input":{"allOf":[{"description":"missing properties"}]}}`))
		assert.NoError(t, err)

		_, err = findTemplate("missing", []byte(`{}`))
		assert.ErrorIs(t, err, jsonparser.KeyPathNotFoundError)

		err = scanDefinitionsForKind("input", []byte(`{"input":{"allOf":{}}}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expected array but got object")

		err = scanDefinitionsForKind("input", []byte(`{}`))
		assert.ErrorIs(t, err, jsonparser.KeyPathNotFoundError)
	})

	t.Run("custom uri rule applies to input and output http client URL sections", func(t *testing.T) {
		input := []byte(`{
			"definitions": {
				"input": {"properties": {"http_client": {"properties": {"url": {"type": "string"}}}}},
				"output": {"properties": {"http_client": {"properties": {"url": {"type": "string"}}}}}
			}
		}`)

		modified, err := (&addURIFormatToHTTPClientRule{}).Apply(input)
		require.NoError(t, err)

		for _, kind := range []string{"input", "output"} {
			value, dataType, _, err := jsonparser.Get(modified, "definitions", kind, "properties", "http_client", "properties", "url", "format")
			require.NoError(t, err)
			assert.Equal(t, jsonparser.String, dataType)
			assert.Equal(t, "uri", string(value))
		}
	})

	t.Run("custom uri rule reports missing and non-object URL sections", func(t *testing.T) {
		rule := &addURIFormatToHTTPClientRule{}

		_, err := rule.Apply([]byte(`{}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "getting URL property returned")

		input := []byte(`{
			"definitions": {
				"input": {"properties": {"http_client": {"properties": {"url": "not-object"}}}},
				"output": {"properties": {"http_client": {"properties": {"url": {"type": "string"}}}}}
			}
		}`)
		_, err = rule.Apply(input)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL property is not an object")

		_, err = rule.setModifiedURLSection([]byte(`{}`), []byte(`"not-object"`), "missing")
		assert.ErrorIs(t, err, jsonparser.KeyPathNotFoundError)
	})

	t.Run("full generation writes supported source definitions and wraps rule failures", func(t *testing.T) {
		resetReqProofGeneratorResult(t)

		output := filepath.Join(t.TempDir(), "schema.json")
		require.NoError(t, generateBentoConfigSchema(output, []customValidationRule{&addURIFormatToHTTPClientRule{}}))

		data, err := os.ReadFile(output)
		require.NoError(t, err)
		for _, kind := range []string{"input", "output"} {
			for _, source := range supportedSources {
				_, _, _, err = jsonparser.Get(data, "definitions", kind, "properties", source)
				assert.NoError(t, err)
			}
			format, _, _, err := jsonparser.Get(data, "definitions", kind, "properties", "http_client", "properties", "url", "format")
			require.NoError(t, err)
			assert.Equal(t, "uri", string(format))
		}

		resetReqProofGeneratorResult(t)
		err = generateBentoConfigSchema(filepath.Join(t.TempDir(), "failed.json"), []customValidationRule{reqproofFailingRule{}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error applying rule reqproof_failing_rule")
	})

	t.Run("save file returns controlled errors for invalid JSON and bad output path", func(t *testing.T) {
		resetReqProofGeneratorResult(t)

		result = []byte(`{not-json`)
		err := saveFile(filepath.Join(t.TempDir(), "schema.json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error indenting bento configuration validator")

		result = []byte(`{}`)
		err = saveFile(t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error creating file on the disk")
	})

	t.Run("command entrypoint writes selected output path and status message", func(t *testing.T) {
		resetReqProofGeneratorResult(t)

		output := filepath.Join(t.TempDir(), "schema.json")
		oldArgs := os.Args
		oldStdout := os.Stdout
		reader, writer, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			os.Args = oldArgs
			os.Stdout = oldStdout
			_ = reader.Close()
		})

		os.Args = []string{"generate_bento_config_schema", "-o", output}
		os.Stdout = writer
		main()
		require.NoError(t, writer.Close())
		os.Stdout = oldStdout

		message, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Contains(t, string(message), "Bento schema generated in '"+output+"'")
		_, err = os.Stat(output)
		assert.NoError(t, err)
	})

	t.Run("command help prints usage without writing output", func(t *testing.T) {
		oldArgs := os.Args
		oldStdout := os.Stdout
		reader, writer, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			os.Args = oldArgs
			os.Stdout = oldStdout
			_ = reader.Close()
		})

		os.Args = []string{"generate_bento_config_schema", "-h"}
		os.Stdout = writer
		main()
		require.NoError(t, writer.Close())
		os.Stdout = oldStdout

		message, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Contains(t, string(message), "Usage: generate_bent_config_schema")
		assert.Contains(t, string(message), defaultOutput)
	})

	t.Run("command error exit writes message", func(t *testing.T) {
		if os.Getenv("REQPROOF_PRINT_ERROR_EXIT") == "1" {
			printErrorAndExit(errors.New("boom"))
		}

		cmd := exec.Command(os.Args[0], "-test.run", "^TestBentoConfigSchemaGeneratorPreservesSupportBehavior$/^command_error_exit_writes_message$")
		cmd.Env = append(os.Environ(), "REQPROOF_PRINT_ERROR_EXIT=1")
		output, err := cmd.CombinedOutput()
		require.Error(t, err)
		assert.Contains(t, string(output), "boom")
	})
}
