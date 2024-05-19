package streaming

import (
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestStreamingServer(t *testing.T) {
	s := NewStreamManager()
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

output:
  label: ""
  drop: {}`)

	var config map[string]interface{}
	if err := yaml.Unmarshal(configPayload, &config); err != nil {
		t.Fatalf("Failed to unmarshal config payload: %v", err)
	}

	err := s.AddStream(streamID, config)
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
