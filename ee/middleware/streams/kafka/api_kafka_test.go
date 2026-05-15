package kafka

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/kafka"
)

func TestKafkaOffsetResetHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/streams/kafka/offset/reset", bytes.NewBufferString("{invalid json}"))
	w := httptest.NewRecorder()

	handler := NewKafkaOffsetResetHandler(nil, "test-group", "test-topic")
	handler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestKafkaOffsetResetHandler_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	kafkaContainer, err := kafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err, "Failed to start Kafka container")
	t.Cleanup(func() {
		if err := kafkaContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate Kafka container: %v", err)
		}
	})

	brokers, err := kafkaContainer.Brokers(ctx)
	require.NoError(t, err, "Failed to get Kafka brokers")

	topic := "test-topic"
	consumerGroup := "test-group"

	// Produce a message
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Version = sarama.V2_0_0_0

	producer, err := sarama.NewSyncProducer(brokers, config)
	require.NoError(t, err, "Failed to create producer")
	defer producer.Close()
	msg := &sarama.ProducerMessage{
		Topic:     topic,
		Value:     sarama.StringEncoder("test-message"),
		Timestamp: time.Now().Add(-1 * time.Hour),
	}
	partition, offset, err := producer.SendMessage(msg)
	require.NoError(t, err, "Failed to send message")

	client, err := sarama.NewClient(brokers, config)
	require.NoError(t, err)
	defer client.Close()

	// Test commit offset
	handler := NewKafkaOffsetResetHandler(client, consumerGroup, topic)

	commitPayload := KafkaOffsetResetRequest{
		Partition: partition,
		Offset:    offset + 1,
	}
	body, _ := json.Marshal(commitPayload)
	req := httptest.NewRequest("POST", "/streams/kafka/offset/commit", bytes.NewBuffer(body))
	w := httptest.NewRecorder()

	handler(w, req)
	require.Equal(t, http.StatusOK, w.Code, "Commit failed: %s", w.Body.String())

	// Verify the offset was committed
	coordinator, err := client.Coordinator(consumerGroup)
	require.NoError(t, err)

	fetchReq := &sarama.OffsetFetchRequest{
		ConsumerGroup: consumerGroup,
		Version:       1,
	}
	fetchReq.AddPartition(topic, partition)

	fetchResp, err := coordinator.FetchOffset(fetchReq)
	require.NoError(t, err)

	block := fetchResp.GetBlock(topic, partition)
	require.NotNil(t, block)
	assert.Equal(t, offset+1, block.Offset)

	// Test reset offset by timestamp
	// We need to produce another message to have a different timestamp
	timestamp := time.Now().UnixMilli()

	msg2 := &sarama.ProducerMessage{
		Topic:     topic,
		Value:     sarama.StringEncoder("test-message-2"),
		Timestamp: time.UnixMilli(timestamp),
	}
	_, offset2, err := producer.SendMessage(msg2)
	require.NoError(t, err)

	resetPayload := KafkaOffsetResetRequest{
		Partition: partition,
		Timestamp: &timestamp,
	}
	body2, _ := json.Marshal(resetPayload)
	req2 := httptest.NewRequest("POST", "/streams/kafka/offset/reset", bytes.NewBuffer(body2))
	w2 := httptest.NewRecorder()

	handler(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code, "Reset failed: %s", w2.Body.String())

	// Verify the offset was reset
	fetchResp2, err := coordinator.FetchOffset(fetchReq)
	require.NoError(t, err)

	block2 := fetchResp2.GetBlock(topic, partition)
	require.NotNil(t, block2)
	assert.Equal(t, offset2, block2.Offset)
}
