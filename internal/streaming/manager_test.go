package streaming

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestStreamingServer(t *testing.T) {
	s := NewStreamManager(nil)
	// Do not call Stop because it cause os.Exit(0), instead Reset ensure that streams will be cleaned up in the end of test
	defer s.Reset()

	streamID := "test-stream"
	configPayload := []byte(`input:
  type: generate
  generate:
    count: 1
    interval: ""
    mapping: |
      root.content = "test message"

pipeline:
  processors:
    - type: log
      log:
        level: INFO
        message: |
          Content: ${!content()}
          Metadata: ${!meta()}

output:
  label: ""
  drop: {}`)

	var config map[string]interface{}
	if err := yaml.Unmarshal(configPayload, &config); err != nil {
		t.Fatalf("Failed to unmarshal config payload: %v", err)
	}

	err := s.AddStream(streamID, config, nil)
	if err != nil {
		t.Fatalf("Failed to add stream: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	streams := s.Streams()

	if _, exists := streams[streamID]; !exists {
		t.Fatalf("Stream %s was not found after being added, %v", streamID, streams)
	}

	// Test RemoveStream
	err = s.RemoveStream(streamID)
	if err != nil {
		t.Fatalf("Failed to remove stream: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	streams = s.Streams()

	if len(streams) != 0 {
		t.Fatalf("Expected 0 streams after removal, got %d", len(streams))
	}
}

func TestGetHTTPPaths(t *testing.T) {
	s := NewStreamManager(nil, nil)
	defer s.Reset()

	streamID := "test-stream"
	configPayload := []byte(`input:
  http_server:
    path: "/custom/post"

output:
  http_server:
    path: "/custom/get"
`)

	var config map[string]interface{}
	if err := yaml.Unmarshal(configPayload, &config); err != nil {
		t.Fatalf("Failed to unmarshal config payload: %v", err)
	}

	err := s.AddStream(streamID, config, nil)
	if err != nil {
		t.Fatalf("Failed to add stream: %v", err)
	}

	expectedInputPaths := map[string]string{
		"path":    "/custom/post",
		"ws_path": "/post/ws",
	}

	inputPaths, err := s.GetHTTPPaths("input", streamID)
	if err != nil {
		t.Fatalf("Failed to get input HTTP paths: %v", err)
	}
	for key, expected := range expectedInputPaths {
		if inputPaths[key] != expected {
			t.Errorf("Expected input %s to be %s, got %s", key, expected, inputPaths[key])
		}
	}

	expectedOutputPaths := map[string]string{
		"path":        "/custom/get",
		"stream_path": "/get/stream",
		"ws_path":     "/get/ws",
	}

	outputPaths, err := s.GetHTTPPaths("output", streamID)
	if err != nil {
		t.Fatalf("Failed to get output HTTP paths: %v", err)
	}
	for key, expected := range expectedOutputPaths {
		if outputPaths[key] != expected {
			t.Errorf("Expected output %s to be %s, got %s", key, expected, outputPaths[key])
		}
	}
}

func TestConsumerGroup(t *testing.T) {
	s := NewStreamManager(nil, nil)
	defer s.Reset()

	streamID := "test-stream"
	consumerGroup := "test-group"
	configPayload := []byte(`input:
  type: generate
  generate:
    count: 1
    interval: ""
    mapping: |
      root.content = "test message"

output:
  http_server:
    consumer_group: "` + consumerGroup + `"`)

	var config map[string]interface{}
	if err := yaml.Unmarshal(configPayload, &config); err != nil {
		t.Fatalf("Failed to unmarshal config payload: %v", err)
	}

	err := s.AddStream(streamID, config, nil)
	if err != nil {
		t.Fatalf("Failed to add stream: %v", err)
	}

	cg, exists := s.ConsumerGroup(streamID)
	if !exists {
		t.Fatalf("Consumer group for stream %s was not found", streamID)
	}

	if cg != consumerGroup {
		t.Errorf("Expected consumer group to be %s, got %s", consumerGroup, cg)
	}
}

func TestRemoveAndWhitelistUnsafeComponents(t *testing.T) {
	t.Run("Remove Unsafe Components", func(t *testing.T) {
		// Initialize StreamManager without any allowed unsafe components
		sm := NewStreamManager(nil, []string{})
		defer sm.Reset()

		unsafeConfig := map[string]interface{}{
			"input": map[string]interface{}{
				"type": "file",
				"file": map[string]interface{}{
					"paths": []string{"test.txt"},
				},
			},
			"output": map[string]interface{}{
				"type": "socket",
				"socket": map[string]interface{}{
					"network": "tcp",
					"address": "localhost:1234",
				},
			},
		}

		configPayload, err := yaml.Marshal(unsafeConfig)
		if err != nil {
			t.Fatalf("Failed to marshal unsafe config: %v", err)
		}

		sanitizedConfig := sm.removeUnsafe(configPayload)
		if containsUnsafeComponent(sanitizedConfig) {
			t.Fatalf("Unsafe components were not removed: \n%s", string(sanitizedConfig))
		}
	})

	t.Run("Whitelist Components", func(t *testing.T) {
		// Initialize StreamManager with whitelisted unsafe components
		sm := NewStreamManager(nil, []string{"file", "socket"})
		defer sm.Reset()

		streamID := "test-stream"

		unsafeConfig := map[string]interface{}{
			"input": map[string]interface{}{
				"file": map[string]interface{}{
					"paths": []string{"test.txt"},
				},
			},
			"output": map[string]interface{}{
				"socket": map[string]interface{}{
					"network": "tcp",
					"address": "localhost:1234",
				},
			},
		}

		err := sm.AddStream(streamID, unsafeConfig, nil)
		if err != nil {
			t.Fatalf("Failed to add stream with whitelisted components: %v", err)
		}

		configPayload, err := yaml.Marshal(unsafeConfig)
		if err != nil {
			t.Fatalf("Failed to marshal unsafe config: %v", err)
		}

		sanitizedConfig := sm.removeUnsafe(configPayload)
		if !containsUnsafeComponent(sanitizedConfig) {
			t.Fatalf("Whitelisted components were removed: \n%s", string(sanitizedConfig))
		}
	})
}

// Helper function to check if the config contains any unsafe component
func containsUnsafeComponent(configPayload []byte) bool {
	yamlString := string(configPayload)
	for _, key := range unsafeComponents {
		if strings.Contains(yamlString, key+":") {
			return true
		}
	}
	return false
}
