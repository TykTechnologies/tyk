package kafka

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

func newExternalAckEdgeController(t *testing.T, mutate func(*AcknowledgmentConfig)) *ExternalAckController {
	t.Helper()
	codec, err := NewAckTokenCodec("test", map[string][]byte{"test": []byte("a sufficiently long unit test key")})
	require.NoError(t, err)
	config := defaultAcknowledgmentConfig()
	config.Mode = AcknowledgmentModeExternal
	config.CheckpointLimit, config.MaxInFlight, config.MaxInFlightBytes = 2, 2, 16
	config.AckDeadline, config.TokenTTL = time.Minute, time.Hour
	if mutate != nil {
		mutate(&config)
	}
	controller, err := NewExternalAckController(ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}, "", "", codec, config)
	require.NoError(t, err)
	return controller
}

func TestExternalAckControllerAdmissionAndClosedEdges(t *testing.T) {
	controller := newExternalAckEdgeController(t, nil)
	require.False(t, controller.CanTrack(nil))
	require.False(t, controller.RecordExceedsLimit(nil))
	require.True(t, controller.CanTrack(&kgo.Record{Topic: "events", Value: []byte("small")}))
	require.True(t, controller.RecordExceedsLimit(&kgo.Record{Value: make([]byte, 17)}))
	require.Contains(t, controller.String(), "api/stream/input")

	require.NoError(t, controller.CloseContext(context.Background()))
	require.False(t, controller.HasCapacity())
	require.False(t, controller.CanTrack(&kgo.Record{}))
	require.Error(t, controller.Track(&kgo.Record{}, service.NewMessage(nil)))
	controller.AssignPartitions(map[string][]int32{"events": {0}})
	require.NoError(t, controller.CloseContext(context.Background()), "close must be idempotent")
}

func TestExternalAckControllerMissingCommitterLifecycleErrors(t *testing.T) {
	controller := newExternalAckEdgeController(t, nil)
	token := trackPartitionForTest(t, controller, 0, 0)
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err, "per-token commit failures are represented by disposition")
	require.Equal(t, AckUnavailable, results[0].Disposition)
	require.ErrorContains(t, controller.RevokePartitions(context.Background(), map[string][]int32{"topic": {0}}), "committer")
	require.NoError(t, controller.CloseContext(context.Background()))
}

func TestExternalAckControllerBackoffCapsWithoutOverflow(t *testing.T) {
	controller := newExternalAckEdgeController(t, func(config *AcknowledgmentConfig) {
		config.RedeliveryBackoff = 8 * time.Second
		config.RedeliveryMaxBackoff = 10 * time.Second
	})
	tp := topicPartition{topic: "events", partition: 0}
	controller.redeliveries[tp] = redeliveryAttempt{Attempts: 3}
	require.Equal(t, 10*time.Second, controller.redeliveryDelayLocked(tp))
	controller.redeliveries[tp] = redeliveryAttempt{Attempts: 0}
	require.Zero(t, controller.redeliveryDelayLocked(tp))
	require.NoError(t, controller.CloseContext(context.Background()))
}
