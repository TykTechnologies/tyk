package kafka

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

type fakeSyncProducer struct {
	record *kgo.Record
	err    error
}

func TestKafkaDeadLetterWriterRealKafka(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	topic := fmt.Sprintf("deadline-dlq-%d", time.Now().UnixNano())
	client, err := kgo.NewClient(kgo.SeedBrokers(brokers...))
	require.NoError(t, err)
	t.Cleanup(client.Close)
	created, err := kadm.NewClient(client).CreateTopics(ctx, 1, 1, nil, topic)
	require.NoError(t, err)
	require.NoError(t, created.Error())

	writer := NewKafkaDeadLetterWriter(client, topic)
	produceCtx, produceCancel := context.WithTimeout(ctx, 15*time.Second)
	defer produceCancel()
	require.NoError(t, writer.WriteDeadLetter(produceCtx, DeadLetterRecord{Scope: "api/stream", ReplayID: "r1", Record: &kgo.Record{Topic: "source", Partition: 1, Offset: 9, Value: []byte("failed")}}))
	consumer, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.ConsumeTopics(topic), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	require.NoError(t, err)
	t.Cleanup(consumer.Close)
	fetchCtx, fetchCancel := context.WithTimeout(ctx, 15*time.Second)
	defer fetchCancel()
	fetches := consumer.PollRecords(fetchCtx, 1)
	require.NoError(t, fetches.Err())
	require.Len(t, fetches.Records(), 1)
	record := fetches.Records()[0]
	require.Equal(t, []byte("failed"), record.Value)
	require.Equal(t, "tyk_dlq_source_topic", record.Headers[0].Key)

}

func (f *fakeSyncProducer) ProduceSync(_ context.Context, records ...*kgo.Record) kgo.ProduceResults {
	f.record = records[0]
	return kgo.ProduceResults{{Record: records[0], Err: f.err}}
}

func TestKafkaDeadLetterWriter(t *testing.T) {
	producer := &fakeSyncProducer{}
	writer := NewKafkaDeadLetterWriter(producer, "orders-dlq")
	source := &kgo.Record{Topic: "orders", Partition: 2, Offset: 41, Key: []byte("k"), Value: []byte("v"), Headers: []kgo.RecordHeader{{Key: "existing", Value: []byte("yes")}}}
	err := writer.WriteDeadLetter(context.Background(), DeadLetterRecord{Scope: "api/stream", ReplayID: "r1", Record: source, Deadline: time.UnixMilli(1234)})
	require.NoError(t, err)
	require.Equal(t, "orders-dlq", producer.record.Topic)
	require.Equal(t, []byte("v"), producer.record.Value)
	require.Equal(t, "tyk_dlq_source_topic", producer.record.Headers[1].Key)
	require.Equal(t, []byte("orders"), producer.record.Headers[1].Value)

	producer.err = errors.New("broker unavailable")
	require.Error(t, writer.WriteDeadLetter(context.Background(), DeadLetterRecord{Record: source}))
}
