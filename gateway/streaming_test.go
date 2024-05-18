package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v2"

	"github.com/TykTechnologies/tyk/apidef/oas"
	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"
)

// ConvertYAMLToJSON converts a YAML byte slice to a JSON byte slice
func ConvertYAMLToJSON(yamlData []byte) ([]byte, error) {
	var rawData interface{}
	if err := yaml.Unmarshal(yamlData, &rawData); err != nil {
		return nil, fmt.Errorf("error unmarshaling YAML: %w", err)
	}

	// Convert map[interface{}]interface{} to map[string]interface{}
	data := convertToStringKeyMap(rawData)

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling to JSON: %w", err)
	}

	return jsonData, nil
}

// convertToStringKeyMap recursively converts map[interface{}]interface{} to map[string]interface{}
func convertToStringKeyMap(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, v := range x {
			m[fmt.Sprintf("%v", k)] = convertToStringKeyMap(v)
		}
		return m
	case []interface{}:
		for i, v := range x {
			x[i] = convertToStringKeyMap(v)
		}
	}
	return i
}

func TestAsyncAPI(t *testing.T) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Streaming.Enabled = true
	})

	defer ts.Close()

	const (
		oldAPIID    = "old-api-id"
		oasAPIID    = "oas-api-id"
		oasBasePath = "/tyk/apis/oas"
	)

	tempFile, err := os.CreateTemp("", "test-output-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	tempFile.Close()
	defer os.Remove(tempFile.Name()) // clean up
	tempFilePath := tempFile.Name()

	streamingConfig := `
streams:
  test:
    input:
      label: "in"
      generate:
        count: 3
        interval: ""
        mapping: root = "hello world"

    output:
      label: "out"
      file:
        path: "%s"
        codec: lines`

	streamingConfig = fmt.Sprintf(streamingConfig, tempFilePath)

	streamingConfigJSON, err := ConvertYAMLToJSON([]byte(streamingConfig))
	if err != nil {
		t.Fatalf("Failed to convert YAML to JSON: %v", err)
	}

	var parsedStreamingConfig map[string]interface{}
	if err := json.Unmarshal(streamingConfigJSON, &parsedStreamingConfig); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	tykExtension := oas.XTykAPIGateway{
		Info: oas.Info{
			Name: "oas api",
			ID:   oasAPIID,
			State: oas.State{
				Active: true,
			},
		},
		Upstream: oas.Upstream{
			URL: TestHttpAny,
		},
		Server: oas.Server{
			ListenPath: oas.ListenPath{
				Value: "/streaming-api/",
				Strip: false,
			},
		},
	}

	oasAPI := openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "oas doc",
			Version: "1",
		},
		Paths: make(openapi3.Paths),
	}

	oasAPI.Extensions = map[string]interface{}{
		oas.ExtensionTykStreaming:  parsedStreamingConfig,
		oas.ExtensionTykAPIGateway: tykExtension,
	}

	// Create OAS API
	_, _ = ts.Run(t, test.TestCase{AdminAuth: true, Method: http.MethodPost, Path: oasBasePath, Data: &oasAPI,
		BodyMatch: `"action":"added"`, Code: http.StatusOK})

	ts.Gw.DoReload()

	streams, err := ts.Gw.StreamingServer.Streams()
	if err != nil {
		t.Fatalf("Failed to get streams: %v", err)
	}

	if len(streams) != 1 {
		t.Fatalf("Expected 1 stream, got %d", len(streams))
	}

	time.Sleep(500 * time.Millisecond)

	content, err := os.ReadFile(tempFilePath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	lines := strings.Split(string(content), "\n")

	// Adjust for the trailing new line which results in an extra empty element in the slice
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines, got %d", len(lines))
	}

	for _, line := range lines {
		if line != "hello world" {
			t.Fatalf("Expected 'hello world', got '%s'", line)
		}
	}
}
