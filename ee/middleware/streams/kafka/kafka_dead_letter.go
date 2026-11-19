package kafka

import (
	"context"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type synchronousKafkaProducer interface {
	ProduceSync(context.Context, ...*kgo.Record) kgo.ProduceResults
}

// KafkaDeadLetterWriter durably publishes failed deliveries using the active
// consumer's Kafka client. ProduceSync only succeeds after the client's
// configured broker acknowledgements have completed.
type KafkaDeadLetterWriter struct {
	producer synchronousKafkaProducer
	topic    string
}

func NewKafkaDeadLetterWriter(producer synchronousKafkaProducer, topic string) *KafkaDeadLetterWriter {
	return &KafkaDeadLetterWriter{producer: producer, topic: topic}
}

func (w *KafkaDeadLetterWriter) WriteDeadLetter(ctx context.Context, dead DeadLetterRecord) error {
	source := dead.Record
	record := &kgo.Record{
		Topic:     w.topic,
		Key:       append([]byte(nil), source.Key...),
		Value:     append([]byte(nil), source.Value...),
		Timestamp: time.Now(),
		Headers:   cloneHeaders(source.Headers),
	}
	record.Headers = append(record.Headers,
		kgo.RecordHeader{Key: "tyk_dlq_source_topic", Value: []byte(source.Topic)},
		kgo.RecordHeader{Key: "tyk_dlq_source_partition", Value: []byte(strconv.FormatInt(int64(source.Partition), 10))},
		kgo.RecordHeader{Key: "tyk_dlq_source_offset", Value: []byte(strconv.FormatInt(source.Offset, 10))},
		kgo.RecordHeader{Key: "tyk_dlq_scope", Value: []byte(dead.Scope)},
		kgo.RecordHeader{Key: "tyk_dlq_replay_id", Value: []byte(dead.ReplayID)},
		kgo.RecordHeader{Key: "tyk_dlq_deadline_unix_ms", Value: []byte(strconv.FormatInt(dead.Deadline.UnixMilli(), 10))},
	)
	return w.producer.ProduceSync(ctx, record).FirstErr()
}

func cloneHeaders(headers []kgo.RecordHeader) []kgo.RecordHeader {
	result := make([]kgo.RecordHeader, len(headers))
	for i, header := range headers {
		result[i] = kgo.RecordHeader{Key: header.Key, Value: append([]byte(nil), header.Value...)}
	}
	return result
}
