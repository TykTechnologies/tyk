package kafka

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

type recordingCommitter struct {
	records []*kgo.Record
	err     error
	calls   int
}

type recordingDeadLetterWriter struct {
	records []DeadLetterRecord
	err     error
}

type blockingCommitter struct {
	started chan struct{}
	release chan struct{}
}

type recordingBlockingCommitter struct {
	started chan struct{}
	release chan struct{}
	records []*kgo.Record
}

func (c *recordingBlockingCommitter) CommitRecords(ctx context.Context, records ...*kgo.Record) error {
	for _, record := range records {
		copyRecord := *record
		c.records = append(c.records, &copyRecord)
	}
	select {
	case c.started <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type blockingDeadLetterWriter struct {
	started chan struct{}
	release chan struct{}
}

func (w *blockingDeadLetterWriter) WriteDeadLetter(ctx context.Context, _ DeadLetterRecord) error {
	select {
	case w.started <- struct{}{}:
	default:
	}
	select {
	case <-w.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *blockingCommitter) CommitRecords(ctx context.Context, _ ...*kgo.Record) error {
	select {
	case c.started <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *recordingDeadLetterWriter) WriteDeadLetter(_ context.Context, record DeadLetterRecord) error {
	if w.err != nil {
		return w.err
	}
	w.records = append(w.records, record)
	return nil
}

func (c *recordingCommitter) CommitRecords(_ context.Context, records ...*kgo.Record) error {
	c.calls++
	for _, record := range records {
		copyRecord := *record
		c.records = append(c.records, &copyRecord)
	}
	return c.err
}

func TestExternalAckControllerBatchesConcurrentCommitRequests(t *testing.T) {
	codec, err := NewAckTokenCodec("test", map[string][]byte{"test": []byte("a sufficiently long unit test key")})
	require.NoError(t, err)
	config := defaultAcknowledgmentConfig()
	config.Mode, config.CheckpointLimit, config.MaxInFlight = AcknowledgmentModeExternal, 2, 100
	config.MaxInFlightBytes, config.AckDeadline, config.TokenTTL = 1024, time.Minute, time.Hour
	config.CommitInterval, config.CommitBatchSize = 100*time.Millisecond, 2
	controller, err := NewExternalAckController(ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}, "cluster", "replay", codec, config)
	require.NoError(t, err)
	t.Cleanup(controller.Close)
	committer := &recordingCommitter{}
	controller.SetCommitter(committer)
	tokens := []string{
		trackPartitionForTest(t, controller, 0, 0),
		trackPartitionForTest(t, controller, 1, 0),
	}
	start := make(chan struct{})
	done := make(chan error, 2)
	for _, token := range tokens {
		token := token
		go func() {
			<-start
			_, err := controller.Acknowledge(context.Background(), []string{token})
			done <- err
		}()
	}
	close(start)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.Equal(t, 1, committer.calls)
	require.Len(t, committer.records, 2)
}

func externalControllerForTest(t *testing.T, limit int) (*ExternalAckController, *recordingCommitter) {
	t.Helper()
	codec, err := NewAckTokenCodec("test", map[string][]byte{"test": []byte("a sufficiently long unit test key")})
	require.NoError(t, err)
	config := defaultAcknowledgmentConfig()
	config.Mode = AcknowledgmentModeExternal
	config.CheckpointLimit = limit
	config.MaxInFlight = 100
	config.MaxInFlightBytes = 1024
	config.AckDeadline = time.Minute
	config.TokenTTL = time.Hour
	config.CommitInterval = time.Millisecond
	controller, err := NewExternalAckController(
		ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"},
		"cluster", "replay-0", codec, config,
	)
	require.NoError(t, err)
	t.Cleanup(controller.Close)
	committer := &recordingCommitter{}
	controller.SetCommitter(committer)
	return controller, committer
}

func trackForTest(t *testing.T, controller *ExternalAckController, offset int64) string {
	return trackPartitionForTest(t, controller, 0, offset)
}

func trackPartitionForTest(t *testing.T, controller *ExternalAckController, partition int32, offset int64) string {
	t.Helper()
	message := service.NewMessage([]byte("event"))
	require.NoError(t, controller.Track(&kgo.Record{Topic: "topic", Partition: partition, Offset: offset, LeaderEpoch: 7, Value: []byte("event")}, message))
	token, ok := message.MetaGet("tyk_kafka_ack_token")
	require.True(t, ok)
	_, ok = message.MetaGet("tyk_kafka_message_id")
	require.True(t, ok)
	_, ok = message.MetaGet("tyk_kafka_delivery_id")
	require.True(t, ok)
	return token
}

func TestExternalAckControllerCapacityIsHardBounded(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	controller.config.MaxInFlight = 1
	controller.config.MaxInFlightBytes = 5
	assert.True(t, controller.HasCapacity())
	message := service.NewMessage([]byte("12345"))
	require.NoError(t, controller.Track(&kgo.Record{Topic: "topic", Partition: 0, Offset: 0, Value: []byte("12345")}, message))
	assert.False(t, controller.HasCapacity())
	pending := &kgo.Record{Topic: "other", Partition: 0, Offset: 0, Value: []byte("x")}
	assert.False(t, controller.CanTrack(pending))
	assert.ErrorIs(t, controller.Track(pending, service.NewMessage(nil)), ErrWindowFull)
	assert.Equal(t, 1, controller.totalRecords)
	assert.Equal(t, int64(5), controller.totalBytes)
}

func TestExternalAckControllerRejectsOversizedRecordWithoutReservation(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	controller.config.MaxInFlightBytes = 4
	err := controller.Track(&kgo.Record{Topic: "topic", Partition: 0, Offset: 0, Value: []byte("oversized")}, service.NewMessage(nil))
	assert.ErrorIs(t, err, ErrWindowFull)
	assert.True(t, controller.HasCapacity(), "failed admission must not consume controller capacity")
	assert.Zero(t, controller.totalRecords)
	assert.Zero(t, controller.totalBytes)
	assert.True(t, controller.RecordExceedsLimit(&kgo.Record{Value: []byte("oversized")}))
}

func TestExternalAckControllerPartitionScopedRebalance(t *testing.T) {
	controller, committer := externalControllerForTest(t, 2)
	controller.AssignPartitions(map[string][]int32{"topic": {0, 1}})
	zero := trackPartitionForTest(t, controller, 0, 10)
	one := trackPartitionForTest(t, controller, 1, 20)

	zeroClaims, err := controller.codec.Verify(zero, controller.scope)
	require.NoError(t, err)
	oneClaims, err := controller.codec.Verify(one, controller.scope)
	require.NoError(t, err)
	assert.NotEqual(t, zeroClaims.Epoch, oneClaims.Epoch)

	committer.err = errors.New("temporary commit failure")
	results, err := controller.Acknowledge(context.Background(), []string{zero})
	require.NoError(t, err)
	assert.Equal(t, AckUnavailable, results[0].Disposition)
	committer.err = nil
	require.NoError(t, controller.RevokePartitions(context.Background(), map[string][]int32{"topic": {0}}))
	require.Len(t, committer.records, 2, "revocation retries the safe pending watermark")

	results, err = controller.Acknowledge(context.Background(), []string{zero, one})
	require.NoError(t, err)
	assert.Equal(t, AckStale, results[0].Disposition)
	assert.Equal(t, AckApplied, results[1].Disposition, "an unrelated partition remains active")
	assert.NotNil(t, controller.windows[topicPartition{"topic", 1}])
	assert.Nil(t, controller.windows[topicPartition{"topic", 0}])
}

func TestExternalAckControllerRejectsTokenFromRecreatedTopicIdentity(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	controller.SetKafkaIdentity("cluster-a", map[string]string{"topic": "topic-id-old"})
	token := trackPartitionForTest(t, controller, 0, 10)

	controller.SetKafkaIdentity("cluster-a", map[string]string{"topic": "topic-id-new"})
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckStale, results[0].Disposition)
	require.Equal(t, int64(-1), func() int64 {
		if point := controller.pending[topicPartition{"topic", 0}]; point != nil {
			return point.NextOffset
		}
		return -1
	}(), "an old-log capability must not advance the recreated topic")
}

func TestExternalAckControllerLostPartitionDoesNotCommit(t *testing.T) {
	controller, committer := externalControllerForTest(t, 2)
	controller.AssignPartitions(map[string][]int32{"topic": {0, 1}})
	lost := trackPartitionForTest(t, controller, 0, 10)
	retained := trackPartitionForTest(t, controller, 1, 20)

	controller.LosePartitions(map[string][]int32{"topic": {0}})
	assert.Empty(t, committer.records)
	results, err := controller.Acknowledge(context.Background(), []string{lost, retained})
	require.NoError(t, err)
	assert.Equal(t, AckStale, results[0].Disposition)
	assert.Equal(t, AckApplied, results[1].Disposition)
}

type barrierCommitter struct {
	started chan struct{}
	release chan struct{}
}

func (c *barrierCommitter) CommitRecords(ctx context.Context, _ ...*kgo.Record) error {
	select {
	case c.started <- struct{}{}:
	default:
	}
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestExternalAckControllerRevocationWaitsForInProgressAck(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	controller.AssignPartitions(map[string][]int32{"topic": {0}})
	token := trackForTest(t, controller, 1)
	committer := &barrierCommitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetCommitter(committer)

	ackDone := make(chan struct{})
	go func() {
		_, _ = controller.Acknowledge(context.Background(), []string{token})
		close(ackDone)
	}()
	<-committer.started
	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- controller.RevokePartitions(context.Background(), map[string][]int32{"topic": {0}})
	}()
	select {
	case <-revokeDone:
		t.Fatal("revocation crossed an in-progress acknowledgment barrier")
	case <-time.After(20 * time.Millisecond):
	}
	close(committer.release)
	<-ackDone
	require.NoError(t, <-revokeDone)
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	assert.Equal(t, AckStale, results[0].Disposition)
}

func TestExternalAckControllerRevocationDoesNotHoldStateLockDuringBrokerIO(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	controller.AssignPartitions(map[string][]int32{"topic": {0, 1}})
	token := trackPartitionForTest(t, controller, 0, 1)
	failing := &recordingCommitter{err: errors.New("temporary")}
	controller.SetCommitter(failing)
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckUnavailable, results[0].Disposition)
	committer := &blockingCommitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetCommitter(committer)

	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- controller.RevokePartitions(context.Background(), map[string][]int32{"topic": {0}})
	}()
	<-committer.started
	trackDone := make(chan error, 1)
	go func() {
		trackDone <- controller.Track(&kgo.Record{Topic: "topic", Partition: 1, Offset: 2, Value: []byte("other")}, service.NewMessage(nil))
	}()
	select {
	case err := <-trackDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("revocation held the controller state lock during broker I/O")
	}
	close(committer.release)
	require.NoError(t, <-revokeDone)
}

func TestExternalAckControllerRevocationUsesBoundedCallerContext(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	controller.AssignPartitions(map[string][]int32{"topic": {0}})
	token := trackForTest(t, controller, 1)
	failing := &recordingCommitter{err: errors.New("temporary")}
	controller.SetCommitter(failing)
	_, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	controller.SetCommitter(&blockingCommitter{started: make(chan struct{}, 1), release: make(chan struct{})})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = controller.RevokePartitions(ctx, map[string][]int32{"topic": {0}})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	controller.mu.Lock()
	require.Nil(t, controller.windows[topicPartition{"topic", 0}], "failed final commit must still discard revoked state for safe redelivery")
	controller.mu.Unlock()
}

func TestExternalAckControllerRevocationFencesNewerWatermarkDuringFinalCommit(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	controller.AssignPartitions(map[string][]int32{"topic": {0}})
	first := trackForTest(t, controller, 0)
	second := trackForTest(t, controller, 1)
	failing := &recordingCommitter{err: errors.New("temporary")}
	controller.SetCommitter(failing)
	_, err := controller.Acknowledge(context.Background(), []string{first})
	require.NoError(t, err)
	committer := &recordingBlockingCommitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetCommitter(committer)

	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- controller.RevokePartitions(context.Background(), map[string][]int32{"topic": {0}})
	}()
	<-committer.started
	ackDone := make(chan []AckResult, 1)
	go func() {
		results, _ := controller.Acknowledge(context.Background(), []string{second})
		ackDone <- results
	}()
	require.Eventually(t, func() bool {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		point := controller.pending[topicPartition{"topic", 0}]
		return point != nil && point.RecordOffset == 1
	}, time.Second, time.Millisecond)
	close(committer.release)
	require.NoError(t, <-revokeDone)
	results := <-ackDone
	require.Equal(t, AckApplied, results[0].Disposition)
	require.Len(t, committer.records, 1, "newer watermark must be discarded for redelivery, not committed after revocation")
	require.Equal(t, int64(0), committer.records[0].Offset)
}

func TestExternalAckControllerOutOfOrderCommit(t *testing.T) {
	controller, committer := externalControllerForTest(t, 3)
	tokens := []string{trackForTest(t, controller, 10), trackForTest(t, controller, 12), trackForTest(t, controller, 15)}

	results, err := controller.Acknowledge(context.Background(), []string{tokens[2]})
	require.NoError(t, err)
	assert.Equal(t, AckApplied, results[0].Disposition)
	assert.Empty(t, committer.records)

	results, err = controller.Acknowledge(context.Background(), []string{tokens[0]})
	require.NoError(t, err)
	assert.Equal(t, AckApplied, results[0].Disposition)
	require.Len(t, committer.records, 1)
	assert.Equal(t, int64(10), committer.records[0].Offset)

	results, err = controller.Acknowledge(context.Background(), []string{tokens[1]})
	require.NoError(t, err)
	assert.Equal(t, AckApplied, results[0].Disposition)
	require.Len(t, committer.records, 2)
	assert.Equal(t, int64(15), committer.records[1].Offset)
	assert.Equal(t, int32(7), committer.records[1].LeaderEpoch)
}

func TestExternalAckControllerRetriesFailedCommit(t *testing.T) {
	controller, committer := externalControllerForTest(t, 1)
	token := trackForTest(t, controller, 4)
	committer.err = errors.New("coordinator unavailable")
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	assert.Equal(t, AckUnavailable, results[0].Disposition)

	committer.err = nil
	results, err = controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	assert.Equal(t, AckDuplicate, results[0].Disposition)
	require.Len(t, committer.records, 2)
	assert.Equal(t, int64(4), committer.records[1].Offset)
}

func TestExternalAckControllerDoesNotHoldStateLockDuringCommit(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	committer := &blockingCommitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetCommitter(committer)
	token := trackForTest(t, controller, 0)

	ackDone := make(chan error, 1)
	go func() {
		_, err := controller.Acknowledge(context.Background(), []string{token})
		ackDone <- err
	}()
	select {
	case <-committer.started:
	case <-time.After(time.Second):
		t.Fatal("Kafka commit did not start")
	}

	trackDone := make(chan error, 1)
	go func() {
		message := service.NewMessage([]byte("other partition"))
		trackDone <- controller.Track(&kgo.Record{Topic: "topic", Partition: 1, Offset: 0, Value: []byte("other partition")}, message)
	}()
	select {
	case err := <-trackDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("tracking was blocked by Kafka commit I/O")
	}

	close(committer.release)
	require.NoError(t, <-ackDone)
}

func TestExternalAckControllerResetWaitsForInFlightCommit(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	committer := &blockingCommitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetCommitter(committer)
	token := trackForTest(t, controller, 0)

	ackDone := make(chan struct{})
	go func() {
		_, _ = controller.Acknowledge(context.Background(), []string{token})
		close(ackDone)
	}()
	select {
	case <-committer.started:
	case <-time.After(time.Second):
		t.Fatal("Kafka commit did not start")
	}

	resetDone := make(chan struct{})
	go func() {
		controller.InvalidateForReset()
		close(resetDone)
	}()
	select {
	case <-resetDone:
		t.Fatal("reset crossed an in-flight Kafka commit")
	case <-time.After(25 * time.Millisecond):
	}
	close(committer.release)
	select {
	case <-ackDone:
	case <-time.After(time.Second):
		t.Fatal("acknowledgment did not finish")
	}
	select {
	case <-resetDone:
	case <-time.After(time.Second):
		t.Fatal("reset did not resume after commit")
	}

	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckStale, results[0].Disposition)
}

func TestExternalAckControllerBoundsAndTokenValidation(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	valid := trackForTest(t, controller, 0)
	message := service.NewMessage([]byte("second"))
	assert.ErrorIs(t, controller.Track(&kgo.Record{Topic: "topic", Partition: 0, Offset: 1, Value: []byte("second")}, message), ErrWindowFull)

	results, err := controller.Acknowledge(context.Background(), []string{valid + "tampered"})
	require.NoError(t, err)
	assert.Equal(t, AckInvalid, results[0].Disposition)

	controller.Close()
	results, err = controller.Acknowledge(context.Background(), []string{valid})
	require.NoError(t, err)
	assert.Equal(t, AckUnavailable, results[0].Disposition)
}

func TestExternalAckControllerCloseMakesBoundedFinalCommit(t *testing.T) {
	controller, _ := externalControllerForTest(t, 1)
	token := trackForTest(t, controller, 4)
	failing := &recordingCommitter{err: errors.New("temporary")}
	controller.SetCommitter(failing)
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckUnavailable, results[0].Disposition)
	committer := &blockingCommitter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetCommitter(committer)
	closeDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		closeDone <- controller.CloseContext(ctx)
	}()
	<-committer.started
	results, err = controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckUnavailable, results[0].Disposition, "close must fence new acknowledgements before final commit")
	close(committer.release)
	require.NoError(t, <-closeDone)
	controller.mu.Lock()
	require.Empty(t, controller.pending)
	require.Nil(t, controller.committer)
	controller.mu.Unlock()
}

func TestExternalAckControllerAmbiguousCommitRetryIsIdempotent(t *testing.T) {
	controller, committer := externalControllerForTest(t, 1)
	token := trackForTest(t, controller, 4)
	committer.err = errors.New("broker committed but response was lost")
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckUnavailable, results[0].Disposition)
	require.Len(t, controller.pending, 1, "ambiguous outcome must retain the safe watermark")

	committer.err = nil
	results, err = controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckDuplicate, results[0].Disposition)
	require.Empty(t, controller.pending, "duplicate retry must flush the retained watermark")
	require.Equal(t, int64(4), committer.records[len(committer.records)-1].Offset)

	results, err = controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckDuplicate, results[0].Disposition)
}

func TestExternalAckControllerKafkaUnavailableAtShutdownFailsBoundedly(t *testing.T) {
	controller, committer := externalControllerForTest(t, 1)
	token := trackForTest(t, controller, 4)
	committer.err = errors.New("Kafka unavailable")
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckUnavailable, results[0].Disposition)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = controller.CloseContext(ctx)
	require.ErrorContains(t, err, "Kafka unavailable")
	require.Empty(t, controller.pending)
	require.Nil(t, controller.committer)
}

func TestExternalAckControllerKafkaIdentityIncludesTopicIncarnation(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	controller.SetKafkaIdentity("logical-cluster", map[string]string{"topic": "topic-id-v1"})
	first := service.NewMessage([]byte("first"))
	require.NoError(t, controller.Track(&kgo.Record{Topic: "topic", Partition: 0, Offset: 0, Value: []byte("first")}, first))
	firstID, ok := first.MetaGet("tyk_kafka_message_id")
	require.True(t, ok)
	controller.InvalidateForReset()
	controller.SetKafkaIdentity("logical-cluster", map[string]string{"topic": "topic-id-v2"})
	second := service.NewMessage([]byte("second"))
	require.NoError(t, controller.Track(&kgo.Record{Topic: "topic", Partition: 0, Offset: 0, Value: []byte("second")}, second))
	secondID, ok := second.MetaGet("tyk_kafka_message_id")
	require.True(t, ok)
	require.NotEqual(t, firstID, secondID)
}

func TestExternalAckControllerDeadlinePause(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.AckDeadline = time.Minute
	controller.config.MissingAckPolicy = "pause"
	trackForTest(t, controller, 4)

	decision, err := controller.DeadlineAction(now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, DeadlinePause, decision.Action)
	assert.Equal(t, 1, decision.ExpiredRecords)
	assert.Equal(t, []TopicPartition{{Topic: "topic", Partition: 0}}, decision.Partitions)
	records, _ := controller.windows[topicPartition{"topic", 0}].Pending()
	assert.Equal(t, 1, records, "pause must retain the uncommitted delivery")
}

func TestExternalAckControllerDeadlineRedeliveryRotatesEpoch(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.AckDeadline = time.Minute
	controller.config.MissingAckPolicy = "redeliver"
	token := trackForTest(t, controller, 4)
	oldEpoch := controller.epoch

	decision, err := controller.DeadlineAction(now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, DeadlineRedeliverPartitions, decision.Action)
	assert.Equal(t, []RedeliveryTarget{{Topic: "topic", Partition: 0, Offset: 4}}, decision.Redeliver)
	assert.Greater(t, decision.Epoch, oldEpoch)
	assert.Empty(t, controller.windows)
	assert.Zero(t, controller.totalRecords)
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	assert.Equal(t, AckStale, results[0].Disposition)
}

func TestExternalAckControllerRedeliveryBackoffAndTerminalPause(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.AckDeadline = time.Minute
	controller.config.MissingAckPolicy = "redeliver"
	controller.config.RedeliveryMaxAttempts = 2
	controller.config.RedeliveryMaxAge = time.Hour
	controller.config.RedeliveryBackoff = 10 * time.Second
	controller.config.RedeliveryMaxBackoff = time.Minute
	controller.config.RedeliveryExhaustedPolicy = "pause"
	trackForTest(t, controller, 4)

	decision, err := controller.DeadlineAction(now.Add(time.Minute))
	require.NoError(t, err)
	require.Equal(t, DeadlineRedeliverPartitions, decision.Action)

	now = now.Add(time.Minute)
	token := trackForTest(t, controller, 4)
	window := controller.windows[topicPartition{"topic", 0}]
	require.Empty(t, window.Expired(now.Add(time.Minute+9*time.Second)), "retry must honor exponential backoff")
	require.Len(t, window.Expired(now.Add(time.Minute+10*time.Second)), 1)

	decision, err = controller.DeadlineAction(now.Add(time.Minute + 10*time.Second))
	require.NoError(t, err)
	require.Equal(t, DeadlinePause, decision.Action)
	require.NotNil(t, controller.windows[topicPartition{"topic", 0}], "terminal pause retains delivery for operator recovery")
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	require.Equal(t, AckApplied, results[0].Disposition, "late valid acknowledgement is the explicit recovery action")
}

func TestExternalAckControllerTokenBindsGroupOwnerIssuedAtAndNonce(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.SetDeliveryAuthority("consumer-group", "gateway-owner")
	token := trackForTest(t, controller, 4)
	claims, err := controller.codec.Verify(token, controller.scope)
	require.NoError(t, err)
	assert.Equal(t, "consumer-group", claims.ConsumerGroup)
	assert.Equal(t, "gateway-owner", claims.Owner)
	assert.Equal(t, now.Unix(), claims.IssuedAt)
	assert.NotEmpty(t, claims.Nonce)

	controller.SetDeliveryAuthority("consumer-group", "new-owner")
	results, err := controller.Acknowledge(context.Background(), []string{token})
	require.NoError(t, err)
	assert.Equal(t, AckStale, results[0].Disposition)
}

func TestExternalAckControllerDeadlineDeadLetterRequiresWriter(t *testing.T) {
	controller, committer := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.AckDeadline = time.Minute
	controller.config.MissingAckPolicy = "dead_letter"
	trackForTest(t, controller, 4)

	decision, err := controller.DeadlineAction(now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, DeadlineDeadLetterNotConfigured, decision.Action)
	assert.Empty(t, committer.records)
	records, _ := controller.windows[topicPartition{"topic", 0}].Pending()
	assert.Equal(t, 1, records)
}

func TestExternalAckControllerDeadlineDeadLetterAdvancesOnlyAfterDurableWrite(t *testing.T) {
	controller, committer := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.AckDeadline = time.Minute
	controller.config.MissingAckPolicy = "dead_letter"
	trackForTest(t, controller, 4)
	w := &recordingDeadLetterWriter{err: errors.New("DLQ unavailable")}
	controller.SetDeadLetterWriter(w)

	_, err := controller.DeadlineAction(now.Add(time.Minute))
	require.EqualError(t, err, "DLQ unavailable")
	assert.Empty(t, committer.records)
	records, _ := controller.windows[topicPartition{"topic", 0}].Pending()
	assert.Equal(t, 1, records)

	w.err = nil
	decision, err := controller.DeadlineAction(now.Add(time.Minute))
	require.NoError(t, err)
	assert.Equal(t, DeadlineDeadLettered, decision.Action)
	require.Len(t, w.records, 1)
	assert.Equal(t, int64(4), w.records[0].Record.Offset)
	require.Len(t, committer.records, 1)
	assert.Equal(t, int64(4), committer.records[0].Offset)
	records, _ = controller.windows[topicPartition{"topic", 0}].Pending()
	assert.Zero(t, records)
}

func TestExternalAckControllerDeadlineDeadLetterDoesNotHoldStateLock(t *testing.T) {
	controller, _ := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.AckDeadline = time.Minute
	controller.config.MissingAckPolicy = "dead_letter"
	trackForTest(t, controller, 4)
	w := &blockingDeadLetterWriter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetDeadLetterWriter(w)

	done := make(chan error, 1)
	go func() {
		_, err := controller.DeadlineAction(now.Add(time.Minute))
		done <- err
	}()
	<-w.started

	capacity := make(chan bool, 1)
	go func() { capacity <- controller.HasCapacity() }()
	select {
	case <-capacity:
	case <-time.After(time.Second):
		t.Fatal("state mutex remained held during durable DLQ I/O")
	}
	close(w.release)
	require.NoError(t, <-done)
}

func TestExternalAckControllerDeadlineCompletionFencedByConcurrentAck(t *testing.T) {
	controller, committer := externalControllerForTest(t, 2)
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.AckDeadline = time.Minute
	controller.config.MissingAckPolicy = "dead_letter"
	token := trackForTest(t, controller, 4)
	w := &blockingDeadLetterWriter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetDeadLetterWriter(w)

	deadlineDone := make(chan error, 1)
	go func() {
		_, err := controller.DeadlineAction(now.Add(time.Minute))
		deadlineDone <- err
	}()
	<-w.started
	ackDone := make(chan []AckResult, 1)
	go func() {
		results, _ := controller.Acknowledge(context.Background(), []string{token})
		ackDone <- results
	}()
	require.Eventually(t, func() bool {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		return controller.totalRecords == 0
	}, time.Second, time.Millisecond)
	close(w.release)
	require.NoError(t, <-deadlineDone)
	results := <-ackDone
	require.Len(t, results, 1)
	assert.Equal(t, AckApplied, results[0].Disposition)
	require.Len(t, committer.records, 1, "concurrent completion must commit one watermark")
}

func TestExternalAckControllerCloseCancelsDeadlineIO(t *testing.T) {
	codec, err := NewAckTokenCodec("test", map[string][]byte{"test": []byte("a sufficiently long unit test key")})
	require.NoError(t, err)
	config := defaultAcknowledgmentConfig()
	config.Mode = AcknowledgmentModeExternal
	config.CheckpointLimit, config.MaxInFlight, config.MaxInFlightBytes = 2, 100, 1024
	config.AckDeadline, config.TokenTTL = time.Minute, time.Hour
	controller, err := NewExternalAckController(ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "shutdown"}, "cluster", "replay", codec, config)
	require.NoError(t, err)
	controller.SetCommitter(&recordingCommitter{})
	now := time.Unix(1_800_000_000, 0)
	controller.now = func() time.Time { return now }
	controller.config.MissingAckPolicy = "dead_letter"
	trackForTest(t, controller, 4)
	w := &blockingDeadLetterWriter{started: make(chan struct{}, 1), release: make(chan struct{})}
	controller.SetDeadLetterWriter(w)

	deadlineDone := make(chan error, 1)
	go func() {
		_, actionErr := controller.DeadlineAction(now.Add(time.Minute))
		deadlineDone <- actionErr
	}()
	<-w.started
	closeDone := make(chan struct{})
	go func() { controller.Close(); close(closeDone) }()
	select {
	case actionErr := <-deadlineDone:
		require.ErrorIs(t, actionErr, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("deadline I/O did not observe shutdown cancellation")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("controller close deadlocked behind deadline I/O")
	}
}
