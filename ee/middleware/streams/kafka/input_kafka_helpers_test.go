package kafka

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"
)

func TestRecordToMessageMetadataHeadersAndBodyRelease(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "last_header", true: "multi_header"}[multi], func(t *testing.T) {
			reader := &franzKafkaReader{multiHeader: multi}
			record := &kgo.Record{Topic: "employees", Partition: 2, Offset: 41, Key: []byte("employee-1"), Value: []byte("update"), Timestamp: time.Unix(123, 0), Headers: []kgo.RecordHeader{{Key: "trace", Value: []byte("one")}, {Key: "trace", Value: []byte("two")}}}
			converted, err := reader.recordToMessage(record)
			require.NoError(t, err)
			body, err := converted.msg.AsBytes()
			require.NoError(t, err)
			require.Equal(t, []byte("update"), body)
			for key, expected := range map[string]string{"kafka_key": "employee-1", "kafka_topic": "employees", "kafka_partition": "2", "kafka_offset": "41", "kafka_timestamp_unix": "123", "kafka_tombstone_message": "false"} {
				actual, ok := converted.msg.MetaGet(key)
				require.True(t, ok, key)
				require.Equal(t, expected, actual, key)
			}
			trace, ok := converted.msg.MetaGetMut("trace")
			require.True(t, ok)
			if multi {
				require.Equal(t, []any{"one", "two"}, trace)
			} else {
				require.Equal(t, "two", trace)
			}
			require.Nil(t, converted.r.Key)
			require.Nil(t, converted.r.Value, "checkpoint copy must release payload after message/controller retention")
		})
	}
}

func TestRecordToMessageExternalAckAdmissionFailurePreservesRecord(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	controller.config.MaxInFlightBytes = 1
	reader := &franzKafkaReader{ackController: controller}
	record := &kgo.Record{Topic: "employees", Partition: 0, Offset: 0, Value: []byte("too-large")}
	_, err := reader.recordToMessage(record)
	require.ErrorIs(t, err, ErrWindowFull)
	require.Equal(t, []byte("too-large"), record.Value, "failed admission must leave the fetched record available for bounded pending/recovery policy")
}

func TestKafkaErrorReconnectClassification(t *testing.T) {
	reader := &franzKafkaReader{}
	require.True(t, reader.isRetriableError(context.DeadlineExceeded))
	require.True(t, reader.isRetriableError(context.Canceled))
	require.True(t, reader.isRetriableError(kerr.BrokerNotAvailable))
	require.True(t, reader.isRetriableError(kerr.UnknownTopicOrPartition))
	reader.reconnectOnUnknownTopic = true
	require.False(t, reader.isRetriableError(kerr.UnknownTopicOrPartition), "configured unknown-topic handling must close and reconstruct the client")
	require.False(t, reader.isRetriableError(kerr.UnknownTopicID))
}

func TestExternalAckShouldPauseDeadlineAndCapacity(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.MissingAckPolicy = "pause"
	controller.config.AckDeadline = time.Second
	trackForTest(t, controller, 0)
	require.False(t, controller.ShouldPause("employees", 99))
	require.False(t, controller.ShouldPause("topic", 0))
	now = now.Add(time.Second)
	require.True(t, controller.ShouldPause("topic", 0))
}
