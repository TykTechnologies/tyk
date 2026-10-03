package kafka

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

func TestExternalAckStatusSnapshotIsBoundedAndStructured(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	controller.config.MaxInFlight = 1000
	for i := 0; i < defaultStatusPartitionLimit+7; i++ {
		topic := fmt.Sprintf("topic-%03d", i)
		message := service.NewMessage(nil)
		require.NoError(t, controller.Track(&kgo.Record{Topic: topic, Partition: 0, Offset: 10, Value: []byte("event")}, message))
	}

	status := controller.StatusSnapshot(defaultStatusPartitionLimit + 1000)
	assert.Equal(t, "api", status.APIID)
	assert.Equal(t, "stream", status.StreamID)
	assert.Equal(t, "input", status.ComponentID)
	assert.NotEmpty(t, status.ClusterIDHash)
	assert.NotContains(t, status.ClusterIDHash, "cluster")
	assert.Equal(t, defaultStatusPartitionLimit+7, status.InFlight)
	assert.Len(t, status.Partitions, defaultStatusPartitionLimit)
	assert.Equal(t, 7, status.TruncatedPartitions)
	assert.Equal(t, "topic-000", status.Partitions[0].Topic)
	assert.Equal(t, int64(10), status.Partitions[0].NextOffset)
	assert.Equal(t, 1, status.Partitions[0].InFlight)
	assert.Equal(t, uint64(defaultStatusPartitionLimit+7), status.Metrics.Delivered)

	// A small caller-selected limit remains deterministic and reports omissions.
	small := controller.StatusSnapshot(2)
	assert.Len(t, small.Partitions, 2)
	assert.Equal(t, defaultStatusPartitionLimit+5, small.TruncatedPartitions)
	assert.Equal(t, "topic-000", small.Partitions[0].Topic)
	assert.Equal(t, "topic-001", small.Partitions[1].Topic)
}

func TestExternalAckMetricsRecordOutcomesAndCommitFailure(t *testing.T) {
	controller, committer := externalControllerForTest(t, 1)
	token := trackForTest(t, controller, 0)
	committer.err = errors.New("Kafka unavailable")
	results, err := controller.Acknowledge(context.Background(), []string{token, token + "tampered"})
	require.NoError(t, err)
	assert.Equal(t, AckUnavailable, results[0].Disposition)
	assert.Equal(t, AckInvalid, results[1].Disposition)

	status := controller.StatusSnapshot(1)
	assert.Equal(t, 1, status.PendingCommits)
	assert.Equal(t, uint64(1), status.Metrics.Delivered)
	assert.Equal(t, uint64(1), status.Metrics.AckUnavailable)
	assert.Equal(t, uint64(1), status.Metrics.AckInvalid)
	assert.Equal(t, uint64(1), status.Metrics.CommitAttempts)
	assert.Equal(t, uint64(1), status.Metrics.CommitFailures)

	committer.err = nil
	results, err = controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	assert.Equal(t, AckDuplicate, results[0].Disposition)
	metrics := controller.StatusSnapshot(1).Metrics
	assert.Equal(t, uint64(1), metrics.AckDuplicate)
	assert.Equal(t, uint64(2), metrics.CommitAttempts)
	assert.Equal(t, uint64(1), metrics.CommitFailures)
}

func TestExternalAckStatusAfterClose(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	trackForTest(t, controller, 0)
	controller.Close()
	status := controller.StatusSnapshot(1)
	assert.True(t, status.Closed)
	assert.Zero(t, status.InFlight)
	assert.Empty(t, status.Partitions)
	assert.Equal(t, uint64(1), status.Metrics.Delivered)
}
