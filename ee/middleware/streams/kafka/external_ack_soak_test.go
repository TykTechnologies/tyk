package kafka

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

type soakCommitter struct{ fail bool }

func (c *soakCommitter) CommitRecords(context.Context, ...*kgo.Record) error {
	if c.fail {
		return errors.New("injected broker outage")
	}
	return nil
}

// TestExternalAckBoundedSoak is short and deterministic by default. Set
// TYK_KAFKA_CONTROLLER_SOAK_DURATION=24h (or another Go duration) for an
// opt-in controller-only soak run. This is deliberately distinct from the
// real Gateway topology soak environment variable.
func TestExternalAckBoundedSoak(t *testing.T) {
	duration := 300 * time.Millisecond
	if configured := os.Getenv("TYK_KAFKA_CONTROLLER_SOAK_DURATION"); configured != "" {
		parsed, err := time.ParseDuration(configured)
		require.NoError(t, err)
		require.Positive(t, parsed)
		duration = parsed
	}
	codec, err := NewAckTokenCodec("soak", map[string][]byte{"soak": []byte("a sufficiently long soak signing key")})
	require.NoError(t, err)
	config := defaultAcknowledgmentConfig()
	config.Mode, config.CheckpointLimit = AcknowledgmentModeExternal, 32
	config.MaxInFlight, config.MaxInFlightBytes = 32, 32*128
	config.CommitInterval, config.CommitBatchSize = time.Millisecond, 1
	controller, err := NewExternalAckController(ControllerKey{APIID: "soak", StreamID: "stream", ComponentID: "input"}, "cluster", "replay", codec, config)
	require.NoError(t, err)
	t.Cleanup(controller.Close)
	committer := &soakCommitter{}
	controller.SetCommitter(committer)
	deadline := time.Now().Add(duration)
	var offset int64
	for cycle := 0; time.Now().Before(deadline); cycle++ {
		tokens := make([]string, 32)
		for i := range tokens {
			message := service.NewMessage(make([]byte, 64))
			require.NoError(t, controller.Track(&kgo.Record{Topic: "employees", Partition: 0, Offset: offset, Value: make([]byte, 64)}, message))
			tokens[i], _ = message.MetaGet("tyk_kafka_ack_token")
			offset++
		}
		peak := controller.StatusSnapshot(8)
		require.LessOrEqual(t, peak.InFlight, config.MaxInFlight)
		require.LessOrEqual(t, peak.InFlightBytes, int64(config.MaxInFlightBytes))
		committer.fail = cycle%17 == 0
		reversed := make([]string, len(tokens))
		for i := range tokens {
			reversed[i] = tokens[len(tokens)-1-i]
		}
		results, err := controller.Acknowledge(context.Background(), reversed)
		require.NoError(t, err)
		if committer.fail {
			committer.fail = false
			results, err = controller.Acknowledge(context.Background(), reversed)
			require.NoError(t, err)
		}
		for _, result := range results {
			require.NotEqual(t, AckInvalid, result.Disposition)
		}
		status := controller.StatusSnapshot(8)
		require.LessOrEqual(t, status.InFlight, config.MaxInFlight)
		require.LessOrEqual(t, status.InFlightBytes, int64(config.MaxInFlightBytes))
		if cycle > 0 && cycle%101 == 0 {
			controller.LosePartitions(map[string][]int32{"employees": {0}})
			controller.AssignPartitions(map[string][]int32{"employees": {0}})
		}
	}
}
