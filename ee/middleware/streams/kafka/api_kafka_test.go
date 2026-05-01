package kafka

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKafkaOffsetResetHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/streams/kafka/offset/reset", bytes.NewBufferString("{invalid json}"))
	w := httptest.NewRecorder()

	KafkaOffsetResetHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestKafkaOffsetResetHandler_NoBrokers(t *testing.T) {
	payload := KafkaOffsetResetRequest{
		Brokers:       []string{"invalid-broker:9092"},
		ConsumerGroup: "test-group",
		Topic:         "test-topic",
		Partition:     0,
		Offset:        100,
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/streams/kafka/offset/reset", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	KafkaOffsetResetHandler(w, req)

	// Should fail because broker is invalid
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// Note: A full integration test would require a running Kafka cluster.
// For now, we test the basic validation and error handling.
