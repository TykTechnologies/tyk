package streaming

import (
	"testing"
)

func TestStreamingServer(t *testing.T) {
	s := New()
	// Do not call Stop because it cause os.Exit(0), instead Reset ensure that streams will be cleaned up in the end of test
	defer s.Reset()

	if err := s.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

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

	err := s.AddStream(streamID, configPayload)
	if err != nil {
		t.Fatalf("Failed to add stream: %v", err)
	}

	streams, err := s.Streams()
	if err != nil {
		t.Fatalf("Failed to get streams: %v", err)
	}

	if _, exists := streams[streamID]; !exists {
		t.Fatalf("Stream %s was not found after being added, %v", streamID, streams)
	}

	// Test RemoveStream
	err = s.RemoveStream(streamID)
	if err != nil {
		t.Fatalf("Failed to remove stream: %v", err)
	}

	streams, err = s.Streams()
	if err != nil {
		t.Fatalf("Failed to get streams after removal: %v", err)
	}

	if len(streams) != 0 {
		t.Fatalf("Expected 0 streams after removal, got %d", len(streams))
	}
}
