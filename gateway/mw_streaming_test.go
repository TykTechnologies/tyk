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
	"github.com/gorilla/websocket"
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
	t.SkipNow()

	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Labs = map[string]interface{}{
			"streaming": map[string]interface{}{
				"enabled": true,
			},
		}
	})

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = true
	})

	// Check that standard API works
	_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Method: http.MethodGet, Path: "/test"})

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

	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "oas doc",
				Version: "1",
			},
			Paths: make(openapi3.Paths),
		},
	}

	oasAPI.Extensions = map[string]interface{}{
		ExtensionTykStreaming: parsedStreamingConfig,
		// oas.ExtensionTykAPIGateway: tykExtension,
	}

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/test"
		spec.UseKeylessAccess = true
	}, func(spec *APISpec) {
		spec.SetDisabledFlags()
		spec.APIID = "base-api-id"
		spec.VersionDefinition.Enabled = false
		spec.VersionDefinition.Key = ""
		spec.VersionDefinition.Location = ""

		spec.IsOAS = true
		spec.OAS = oasAPI
		spec.OAS.Fill(*spec.APIDefinition)
	})

	// Check that standard API still works
	_, _ = ts.Run(t, test.TestCase{Code: http.StatusOK, Method: http.MethodGet, Path: "/test"})

	if globalStreamCounter.Load() != 1 {
		t.Fatalf("Expected 1 stream, got %d", globalStreamCounter.Load())
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

func TestAsyncAPIHttp(t *testing.T) {
	// t.SkipNow()
	tests := []struct {
		name             string
		consumerGroup    string
		expectedMessages int
	}{
		{"DynamicConsumerGroup", "$tyk_context.request_id", 2},
		{"StaticConsumerGroup", "static-group", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testAsyncAPIHttp(t, tc.consumerGroup, tc.expectedMessages)
		})
	}
}

func testAsyncAPIHttp(t *testing.T, consumerGroup string, expectedMessages int) {
	ts := StartTest(func(globalConf *config.Config) {
		globalConf.Labs = map[string]interface{}{
			"streaming": map[string]interface{}{
				"enabled": true,
			},
		}
	})

	defer ts.Close()

	const (
		oasAPIID      = "oas-api-id"
		messageToSend = "hello websocket"
	)

	streamingConfigTemplate := `
logger:
 level: ALL
 format: logfmt
 add_timestamp: true
 static_fields:
  '@service': benthos

streams:
 test:
  input:
   http_server:
    path: /post
    timeout: 1s

  output:
   http_server:
    consumer_group: "%s"
    path: /get`

	streamingConfig := fmt.Sprintf(streamingConfigTemplate, consumerGroup)

	streamingConfigJSON, err := ConvertYAMLToJSON([]byte(streamingConfig))
	if err != nil {
		t.Fatalf("Failed to convert YAML to JSON: %v", err)
	}

	var parsedStreamingConfig map[string]interface{}
	if err := json.Unmarshal(streamingConfigJSON, &parsedStreamingConfig); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	oasAPI := oas.OAS{
		T: openapi3.T{
			OpenAPI: "3.0.3",
			Info: &openapi3.Info{
				Title:   "oas doc",
				Version: "1",
			},
			Paths: make(openapi3.Paths),
		},
	}

	oasAPI.Extensions = map[string]interface{}{
		ExtensionTykStreaming: parsedStreamingConfig,
	}

	ts.Gw.BuildAndLoadAPI(func(spec *APISpec) {
		spec.Proxy.ListenPath = "/streaming-api"
		spec.UseKeylessAccess = true
		spec.IsOAS = true
		spec.OAS = oasAPI
		spec.OAS.Fill(*spec.APIDefinition)
	})

	if globalStreamCounter.Load() != 1 {
		t.Fatalf("Expected 1 stream, got %d", globalStreamCounter.Load())
	}

	time.Sleep(500 * time.Millisecond)

	// Create first websocket client
	dialer := websocket.Dialer{}
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/streaming-api/get/ws"
	wsConn1, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to websocket: %v", err)
	}
	wsConn1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer wsConn1.Close()

	// Create second websocket client
	wsConn2, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to websocket: %v", err)
	}
	wsConn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer wsConn2.Close()

	// Send message to HTTP input
	httpClient := &http.Client{}
	reqBody := strings.NewReader(messageToSend)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/streaming-api/post", reqBody)
	if err != nil {
		t.Fatalf("Failed to create new HTTP request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to send message to /post: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
	}

	messagesReceived := 0

	// Read message from first websocket
	if _, p1, err := wsConn1.ReadMessage(); err == nil {
		receivedMessage1 := string(p1)
		if receivedMessage1 == messageToSend {
			messagesReceived++
		}
	}

	// Read message from second websocket if expected
	if expectedMessages > 1 {
		if _, p2, err := wsConn2.ReadMessage(); err == nil {
			receivedMessage2 := string(p2)
			if receivedMessage2 == messageToSend {
				messagesReceived++
			}
		}
	}

	if messagesReceived != expectedMessages {
		t.Fatalf("Expected %d messages, but received %d", expectedMessages, messagesReceived)
	}
}
