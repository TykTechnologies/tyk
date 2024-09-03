package streaming

import (
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	"strings"
	"testing"
)

func TestStreamStart(t *testing.T) {
	str := NewStream(nil)
	require.NotNil(t, str)

	t.Run("success", func(t *testing.T) {
		err := str.Start(map[string]interface{}{
			"input": map[string]interface{}{
				"http_server": map[string]interface{}{
					"path": "/post",
				},
			},
			"output": map[string]interface{}{
				"http_server": map[string]interface{}{
					"ws_path": "/subscribe",
				},
			},
		}, nil)
		require.NoError(t, err)
	})

	t.Run("fail due to bad schema", func(t *testing.T) {
		err := str.Start(map[string]interface{}{
			"input": map[string]interface{}{
				"http_server": map[string]interface{}{
					"path": "/post",
				},
			},
			"output": map[string]interface{}{
				"http_server": map[string]interface{}{
					"ws_pat": "/subscribe",
				},
			},
		}, nil)
		require.Error(t, err)
	})
}

func TestStreamStop(t *testing.T) {
	validConfig := map[string]interface{}{
		"input": map[string]interface{}{
			"http_server": map[string]interface{}{
				"path": "/post",
			},
		},
		"output": map[string]interface{}{
			"http_server": map[string]interface{}{
				"ws_path": "/subscribe",
			},
		},
	}
	t.Run("successfully stop", func(t *testing.T) {
		str := NewStream(nil)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		err = str.Stop()
		require.NoError(t, err)
	})

	t.Run("no error stopping cause no stream", func(t *testing.T) {
		str := NewStream(nil)
		require.NotNil(t, str)

		err := str.Start(validConfig, nil)
		require.NoError(t, err)

		str.stream = nil
		require.NoError(t, str.Stop())
	})
}

//	func TestStreamingServer(t *testing.T) {
//		s := NewStreamManager(nil)
//		// Do not call Stop because it cause os.Exit(0), instead Reset ensure that streams will be cleaned up in the end of test
//		defer s.Reset()
//
//		streamID := "test-stream"
//		configPayload := []byte(`input:
//	 type: generate
//	 generate:
//	   count: 1
//	   interval: ""
//	   mapping: |
//	     root.content = "test message"
//
// pipeline:
//
//	processors:
//	  - type: log
//	    log:
//	      level: INFO
//	      message: |
//	        Content: ${!content()}
//	        Metadata: ${!meta()}
//
// output:
//
//	 label: ""
//	 drop: {}`)
//
//		var config map[string]interface{}
//		if err := yaml.Unmarshal(configPayload, &config); err != nil {
//			t.Fatalf("Failed to unmarshal config payload: %v", err)
//		}
//
//		err := s.AddStream(streamID, config, nil)
//		if err != nil {
//			t.Fatalf("Failed to add stream: %v", err)
//		}
//
//		time.Sleep(500 * time.Millisecond)
//
//		streams := s.Streams()
//
//		if _, exists := streams[streamID]; !exists {
//			t.Fatalf("Stream %s was not found after being added, %v", streamID, streams)
//		}
//
//		// Test RemoveStream
//		err = s.RemoveStream(streamID)
//		if err != nil {
//			t.Fatalf("Failed to remove stream: %v", err)
//		}
//
//		time.Sleep(500 * time.Millisecond)
//
//		streams = s.Streams()
//
//		if len(streams) != 0 {
//			t.Fatalf("Expected 0 streams after removal, got %d", len(streams))
//		}
//	}
//
//	func TestGetHTTPPaths(t *testing.T) {
//		s := NewStreamManager(nil, nil)
//		defer s.Reset()
//
//		streamID := "test-stream"
//		configPayload := []byte(`input:
//	 http_server:
//	   path: "/custom/post"
//
// output:
//
//	http_server:
//	  path: "/custom/get"
//
// `)
//
//		var config map[string]interface{}
//		if err := yaml.Unmarshal(configPayload, &config); err != nil {
//			t.Fatalf("Failed to unmarshal config payload: %v", err)
//		}
//
//		err := s.AddStream(streamID, config, nil)
//		if err != nil {
//			t.Fatalf("Failed to add stream: %v", err)
//		}
//
//		expectedInputPaths := map[string]string{
//			"path":    "/custom/post",
//			"ws_path": "/post/ws",
//		}
//
//		inputPaths, err := s.GetHTTPPaths("input", streamID)
//		if err != nil {
//			t.Fatalf("Failed to get input HTTP paths: %v", err)
//		}
//		for key, expected := range expectedInputPaths {
//			if inputPaths[key] != expected {
//				t.Errorf("Expected input %s to be %s, got %s", key, expected, inputPaths[key])
//			}
//		}
//
//		expectedOutputPaths := map[string]string{
//			"path":        "/custom/get",
//			"stream_path": "/get/stream",
//			"ws_path":     "/get/ws",
//		}
//
//		outputPaths, err := s.GetHTTPPaths("output", streamID)
//		if err != nil {
//			t.Fatalf("Failed to get output HTTP paths: %v", err)
//		}
//		for key, expected := range expectedOutputPaths {
//			if outputPaths[key] != expected {
//				t.Errorf("Expected output %s to be %s, got %s", key, expected, outputPaths[key])
//			}
//		}
//	}
//
//	func TestConsumerGroup(t *testing.T) {
//		s := NewStreamManager(nil, nil)
//		defer s.Reset()
//
//		streamID := "test-stream"
//		consumerGroup := "test-group"
//		configPayload := []byte(`input:
//	 type: generate
//	 generate:
//	   count: 1
//	   interval: ""
//	   mapping: |
//	     root.content = "test message"
//
// output:
//
//	 http_server:
//	   consumer_group: "` + consumerGroup + `"`)
//
//		var config map[string]interface{}
//		if err := yaml.Unmarshal(configPayload, &config); err != nil {
//			t.Fatalf("Failed to unmarshal config payload: %v", err)
//		}
//
//		err := s.AddStream(streamID, config, nil)
//		if err != nil {
//			t.Fatalf("Failed to add stream: %v", err)
//		}
//
//		cg, exists := s.ConsumerGroup(streamID)
//		if !exists {
//			t.Fatalf("Consumer group for stream %s was not found", streamID)
//		}
//
//		if cg != consumerGroup {
//			t.Errorf("Expected consumer group to be %s, got %s", consumerGroup, cg)
//		}
//	}
func TestRemoveAndWhitelistUnsafeComponents(t *testing.T) {
	t.Run("Remove Unsafe Components", func(t *testing.T) {
		stream := NewStream(nil)
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

		sanitizedConfig := stream.removeUnsafe(configPayload)
		if containsUnsafeComponent(sanitizedConfig) {
			t.Fatalf("Unsafe components were not removed: \n%s", string(sanitizedConfig))
		}
	})

	t.Run("Whitelist Components", func(t *testing.T) {
		stream := NewStream([]string{"file", "socket"})

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

		configPayload, err := yaml.Marshal(unsafeConfig)
		if err != nil {
			t.Fatalf("Failed to marshal unsafe config: %v", err)
		}

		sanitizedConfig := stream.removeUnsafe(configPayload)
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
