package kafka

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

func testAckRoute() AckRoute {
	return AckRoute{Key: ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}}
}

type channelCommitter chan *kgo.Record

func (c channelCommitter) CommitRecords(_ context.Context, records ...*kgo.Record) error {
	for _, record := range records {
		copyRecord := *record
		c <- &copyRecord
	}
	return nil
}

func TestDurableAcknowledgmentRouterAppendsBeforeQueued(t *testing.T) {
	ctx := context.Background()
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{MaxEntries: 1})
	router, err := NewDurableAcknowledgmentRouter(testAckRoute(), transport)
	require.NoError(t, err)
	now := time.Unix(100, 0)
	router.now = func() time.Time { return now }
	results, err := router.Acknowledge(ctx, []string{"token"})
	require.NoError(t, err)
	require.Equal(t, []AckResult{{Disposition: AckQueued}}, results)
	assert.Equal(t, 1, transport.Stats(ctx, testAckRoute()).Active)

	// The deterministic command ID makes retries idempotent.
	_, err = router.Acknowledge(ctx, []string{"token"})
	require.NoError(t, err)
	assert.Equal(t, 1, transport.Stats(ctx, testAckRoute()).Active)
	_, err = router.Acknowledge(ctx, []string{"another"})
	require.ErrorIs(t, err, ErrAckBacklogFull, "caller cannot return 202 when durable append fails")
}

func TestPartitionedDurableAcknowledgmentRouterRoutesSignedTokens(t *testing.T) {
	ctx := context.Background()
	base := testAckRoute()
	codec, err := NewAckTokenCodec("test", map[string][]byte{"test": []byte("a sufficiently long unit test key")})
	require.NoError(t, err)
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	router, err := NewPartitionedDurableAcknowledgmentRouter(base.Key, transport, codec)
	require.NoError(t, err)
	router.now = func() time.Time { return time.Unix(100, 0) }
	sign := func(topic string, partition int32) string {
		token, err := codec.Sign(AckClaims{Scope: controllerScope(base.Key), Epoch: 1, ReplayID: "r", Topic: topic, Partition: partition, Offset: 4, ExpiresAt: time.Now().Add(time.Hour).Unix()})
		require.NoError(t, err)
		return token
	}
	results, err := router.Acknowledge(ctx, []string{sign("a", 0), sign("a", 1), "invalid"})
	require.NoError(t, err)
	require.Equal(t, []AckResult{{Disposition: AckQueued}, {Disposition: AckQueued}, {Disposition: AckInvalid}}, results)
	require.Equal(t, 1, transport.Stats(ctx, AckRoute{Key: base.Key, Topic: "a", Partition: 0}).Active)
	require.Equal(t, 1, transport.Stats(ctx, AckRoute{Key: base.Key, Topic: "a", Partition: 1}).Active)
	require.Zero(t, transport.Stats(ctx, base).Active)
}

func TestDistributedAckOwnersApplyOnlyOwnedPartitions(t *testing.T) {
	key := testAckRoute().Key
	codec, err := NewAckTokenCodec("test", map[string][]byte{"test": []byte("a sufficiently long unit test key")})
	require.NoError(t, err)
	config := defaultAcknowledgmentConfig()
	config.Mode, config.CheckpointLimit, config.MaxInFlight = AcknowledgmentModeExternal, 2, 10
	config.MaxInFlightBytes, config.AckDeadline, config.TokenTTL = 1024, time.Minute, time.Hour
	config.CommitInterval = time.Millisecond
	commits := []channelCommitter{make(chan *kgo.Record, 1), make(chan *kgo.Record, 1)}
	tokens := make([]string, 2)
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	for partition := range 2 {
		controller, createErr := NewExternalAckController(key, "cluster", "replay", codec, config)
		require.NoError(t, createErr)
		t.Cleanup(controller.Close)
		controller.SetCommitter(commits[partition])
		controller.AssignPartitions(map[string][]int32{"topic": {int32(partition)}})
		message := service.NewMessage([]byte("event"))
		require.NoError(t, controller.Track(&kgo.Record{Topic: "topic", Partition: int32(partition), Offset: 0, Value: []byte("event")}, message))
		token, ok := message.MetaGet("tyk_kafka_ack_token")
		require.True(t, ok)
		owner, ownerErr := NewDistributedAckOwner(transport, key, string(rune('a'+partition)), controller)
		require.NoError(t, ownerErr)
		owner.interval = time.Millisecond
		require.NoError(t, owner.Assign(context.Background(), map[string][]int32{"topic": {int32(partition)}}, KafkaGroupIdentity{Generation: 1, MemberID: string(rune('m' + partition))}))
		t.Cleanup(owner.Close)
		tokens[partition] = token
	}
	router, err := NewPartitionedDurableAcknowledgmentRouter(key, transport, codec)
	require.NoError(t, err)
	results, err := router.Acknowledge(context.Background(), tokens)
	require.NoError(t, err)
	require.Equal(t, []AckResult{{Disposition: AckQueued}, {Disposition: AckQueued}}, results)
	for partition := range 2 {
		select {
		case record := <-commits[partition]:
			require.Equal(t, int32(partition), record.Partition)
		case <-time.After(time.Second):
			t.Fatalf("partition %d acknowledgment was not applied", partition)
		}
	}
}

func TestInMemoryDurableAckTransportFenceAndPendingRecovery(t *testing.T) {
	ctx := context.Background()
	route := testAckRoute()
	now := time.Unix(100, 0)
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	require.NoError(t, transport.AppendBatch(ctx, []AckCommand{{ID: "one", Route: route, Token: "token", AppendedAt: now}}))
	first, err := transport.Assign(ctx, route, "node-a", KafkaGroupIdentity{Generation: 1, MemberID: "member-a"})
	require.NoError(t, err)
	deliveries, err := transport.Claim(ctx, first, "worker-a", 1, time.Minute, now)
	require.NoError(t, err)
	require.Len(t, deliveries, 1)
	second, err := transport.Assign(ctx, route, "node-b", KafkaGroupIdentity{Generation: 2, MemberID: "member-b"})
	require.NoError(t, err)
	require.ErrorIs(t, transport.Complete(ctx, first, "one"), ErrAckRouteFenced)
	deliveries, err = transport.Claim(ctx, second, "worker-b", 1, time.Minute, now.Add(59*time.Second))
	require.NoError(t, err)
	require.Len(t, deliveries, 1, "new Kafka generation reclaims old pending work without waiting for its lease")
	assert.Equal(t, 2, deliveries[0].Attempts)
	assert.Equal(t, "worker-b", deliveries[0].Consumer)
}

func TestInMemoryDurableAckTransportRejectsStaleKafkaOwnership(t *testing.T) {
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	ctx, route := context.Background(), testAckRoute()
	current, err := transport.Assign(ctx, route, "gateway-new", KafkaGroupIdentity{Generation: 12, MemberID: "member-new"})
	require.NoError(t, err)

	_, err = transport.Assign(ctx, route, "gateway-old", KafkaGroupIdentity{Generation: 11, MemberID: "member-old"})
	require.ErrorIs(t, err, ErrAckRouteFenced, "delayed older callback must not replace current Kafka ownership")
	_, err = transport.Assign(ctx, route, "gateway-other", KafkaGroupIdentity{Generation: 12, MemberID: "member-other"})
	require.ErrorIs(t, err, ErrAckRouteFenced, "same-generation conflicting owner must fail closed")
	idempotent, err := transport.Assign(ctx, route, "gateway-new", KafkaGroupIdentity{Generation: 12, MemberID: "member-new"})
	require.NoError(t, err)
	assert.Equal(t, current, idempotent)
}

func TestInMemoryDurableAckTransportHeartbeatExpiry(t *testing.T) {
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	ctx, route := context.Background(), testAckRoute()
	a, err := transport.Assign(ctx, route, "gateway", KafkaGroupIdentity{Generation: 3, MemberID: "member"})
	require.NoError(t, err)
	now := time.Unix(100, 0)
	require.NoError(t, transport.Heartbeat(ctx, a, now, time.Second))
	_, err = transport.Claim(ctx, a, "worker", 1, time.Second, now.Add(time.Second))
	require.ErrorIs(t, err, ErrAckRouteFenced)
}

func TestDurableAckConsumerTransientBackoffPreventsPrematureDLQ(t *testing.T) {
	ctx, route, now := context.Background(), testAckRoute(), time.Unix(100, 0)
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	require.NoError(t, transport.AppendBatch(ctx, []AckCommand{{ID: "retry", Route: route, Token: "token"}}))
	a, err := transport.Assign(ctx, route, "owner", KafkaGroupIdentity{Generation: 1, MemberID: "member"})
	require.NoError(t, err)
	require.NoError(t, transport.Heartbeat(ctx, a, now, time.Minute))
	consumer := DurableAckConsumer{Transport: transport, Assignment: a, Consumer: "worker", Target: &fakeAckController{results: []AckResult{{Disposition: AckUnavailable}}}, Lease: time.Minute, MaxAttempts: 2, RetryBase: 500 * time.Millisecond}

	processed, err := consumer.Process(ctx, 1, now)
	require.NoError(t, err)
	assert.Zero(t, processed)
	processed, err = consumer.Process(ctx, 1, now.Add(499*time.Millisecond))
	require.NoError(t, err)
	assert.Zero(t, processed)
	assert.Zero(t, transport.Stats(ctx, route).DeadLetters)
	processed, err = consumer.Process(ctx, 1, now.Add(500*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	assert.Equal(t, 1, transport.Stats(ctx, route).DeadLetters)
}

func TestInMemoryDurableAckTransportNeverTrimsPendingToFit(t *testing.T) {
	ctx := context.Background()
	route := testAckRoute()
	now := time.Unix(100, 0)
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{MaxEntries: 1, MaxBytes: 10})
	require.NoError(t, transport.AppendBatch(ctx, []AckCommand{{ID: "pending", Route: route, Token: "12345"}}))
	a, err := transport.Assign(ctx, route, "owner", KafkaGroupIdentity{Generation: 1, MemberID: "member"})
	require.NoError(t, err)
	_, err = transport.Claim(ctx, a, "consumer", 1, time.Hour, now)
	require.NoError(t, err)
	require.ErrorIs(t, transport.AppendBatch(ctx, []AckCommand{{ID: "new", Route: route, Token: "1"}}), ErrAckBacklogFull)
	stats := transport.Stats(ctx, route)
	assert.Equal(t, 1, stats.Active)
	assert.Equal(t, 1, stats.Pending)
}

func TestDurableAckConsumerPoisonAndRetryDeadLetter(t *testing.T) {
	ctx := context.Background()
	route := testAckRoute()
	now := time.Unix(100, 0)
	t.Run("invalid is poison", func(t *testing.T) {
		transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
		router, _ := NewDurableAcknowledgmentRouter(route, transport)
		_, err := router.Acknowledge(ctx, []string{"bad"})
		require.NoError(t, err)
		a, _ := transport.Assign(ctx, route, "owner", KafkaGroupIdentity{Generation: 1, MemberID: "member"})
		consumer := DurableAckConsumer{Transport: transport, Assignment: a, Consumer: "worker", Target: &fakeAckController{results: []AckResult{{Disposition: AckInvalid}}}, Lease: time.Minute, MaxAttempts: 3}
		processed, err := consumer.Process(ctx, 1, now)
		require.NoError(t, err)
		assert.Equal(t, 1, processed)
		stats := transport.Stats(ctx, route)
		assert.Zero(t, stats.Active)
		assert.Equal(t, 1, stats.DeadLetters)
	})
	t.Run("unavailable reaches max attempts", func(t *testing.T) {
		transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
		router, _ := NewDurableAcknowledgmentRouter(route, transport)
		_, err := router.Acknowledge(ctx, []string{"retry"})
		require.NoError(t, err)
		a, _ := transport.Assign(ctx, route, "owner", KafkaGroupIdentity{Generation: 1, MemberID: "member"})
		consumer := DurableAckConsumer{Transport: transport, Assignment: a, Consumer: "worker", Target: &fakeAckController{results: []AckResult{{Disposition: AckUnavailable}}}, Lease: time.Minute, MaxAttempts: 2}
		processed, err := consumer.Process(ctx, 1, now)
		require.NoError(t, err)
		assert.Zero(t, processed)
		assert.Equal(t, 1, transport.Stats(ctx, route).Active)
		processed, err = consumer.Process(ctx, 1, now.Add(time.Second))
		require.NoError(t, err)
		assert.Equal(t, 1, processed)
		stats := transport.Stats(ctx, route)
		assert.Zero(t, stats.Active)
		assert.Equal(t, 1, stats.DeadLetters)
	})
}

func TestInMemoryDurableAckTransportConcurrentIdempotence(t *testing.T) {
	ctx := context.Background()
	route := testAckRoute()
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{MaxEntries: 10})
	command := AckCommand{ID: "same", Route: route, Token: "token"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); require.NoError(t, transport.AppendBatch(ctx, []AckCommand{command})) }()
	}
	wg.Wait()
	assert.Equal(t, 1, transport.Stats(ctx, route).Active)
}

func TestDurableAckConsumerProcessingErrorIsRecoverable(t *testing.T) {
	ctx := context.Background()
	route := testAckRoute()
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	router, _ := NewDurableAcknowledgmentRouter(route, transport)
	_, err := router.Acknowledge(ctx, []string{"retry"})
	require.NoError(t, err)
	a, _ := transport.Assign(ctx, route, "owner", KafkaGroupIdentity{Generation: 1, MemberID: "member"})
	consumer := DurableAckConsumer{Transport: transport, Assignment: a, Consumer: "worker", Target: &fakeAckController{err: errors.New("temporary")}, Lease: time.Minute, MaxAttempts: 3}
	_, err = consumer.Process(ctx, 1, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, transport.Stats(ctx, route).Active)
}
