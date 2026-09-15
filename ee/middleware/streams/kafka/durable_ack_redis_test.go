package kafka

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestRedisDurableAckTransportRealRedis(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")},
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	client := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port())})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.NoError(t, client.Ping(ctx).Err())

	route := AckRoute{Key: ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}}
	transport, err := NewRedisDurableAckTransport(client, RedisDurableAckOptions{Prefix: "test:ack", MaxEntries: 2, MaxBytes: 32})
	require.NoError(t, err)
	now := time.Now().UTC()
	commands := []AckCommand{
		{ID: "one", Route: route, Token: "token-one", AppendedAt: now},
		{ID: "two", Route: route, Token: "token-two", AppendedAt: now.Add(time.Nanosecond)},
	}
	require.NoError(t, transport.AppendBatch(ctx, append(commands, commands[0])))
	require.NoError(t, transport.AppendBatch(ctx, commands), "append is idempotent")
	assert.Equal(t, AckBacklogStats{Active: 2, ActiveBytes: 18}, transport.Stats(ctx, route))
	assert.ErrorIs(t, transport.AppendBatch(ctx, []AckCommand{{ID: "three", Route: route, Token: "x", AppendedAt: now}}), ErrAckBacklogFull)

	first, err := transport.Assign(ctx, route, "gateway-a", KafkaGroupIdentity{Generation: 7, MemberID: "member-a"})
	require.NoError(t, err)
	deliveries, err := transport.Claim(ctx, first, "worker-a", 1, time.Second, now)
	require.NoError(t, err)
	require.Len(t, deliveries, 1)
	assert.Equal(t, "one", deliveries[0].Command.ID)
	assert.Equal(t, 1, deliveries[0].Attempts)
	assert.Equal(t, 1, transport.Stats(ctx, route).Pending)

	second, err := transport.Assign(ctx, route, "gateway-b", KafkaGroupIdentity{Generation: 8, MemberID: "member-b"})
	require.NoError(t, err)
	assert.Greater(t, second.Generation, first.Generation)
	assert.ErrorIs(t, transport.Complete(ctx, first, "one"), ErrAckRouteFenced)
	deliveries, err = transport.Claim(ctx, second, "worker-b", 2, time.Second, now.Add(500*time.Millisecond))
	require.NoError(t, err)
	require.Len(t, deliveries, 2, "older-generation pending work is reclaimed before its lease expires")
	assert.Equal(t, 2, deliveries[0].Attempts)
	require.NoError(t, transport.Complete(ctx, second, deliveries[0].Command.ID))
	require.NoError(t, transport.DeadLetter(ctx, second, deliveries[1].Command.ID, "invalid token", now))
	assert.Equal(t, AckBacklogStats{DeadLetters: 1}, transport.Stats(ctx, route))

	_, err = transport.Assign(ctx, route, "delayed-gateway", KafkaGroupIdentity{Generation: 7, MemberID: "delayed-member"})
	require.ErrorIs(t, err, ErrAckRouteFenced)
	_, err = transport.Assign(ctx, route, "conflicting-gateway", KafkaGroupIdentity{Generation: 8, MemberID: "conflicting-member"})
	require.ErrorIs(t, err, ErrAckRouteFenced)
	idempotent, err := transport.Assign(ctx, route, "gateway-b", KafkaGroupIdentity{Generation: 8, MemberID: "member-b"})
	require.NoError(t, err)
	assert.Equal(t, second, idempotent)
	require.NoError(t, transport.Heartbeat(ctx, second, now, 20*time.Millisecond))
	require.Eventually(t, func() bool {
		_, claimErr := transport.Claim(ctx, second, "worker-b", 1, time.Second, now.Add(24*time.Hour))
		return errors.Is(claimErr, ErrAckRouteFenced)
	}, time.Second, 5*time.Millisecond, "Redis TTL, not caller time, must fence an expired owner")

	// Cross-instance clock skew cannot prematurely fence or prolong ownership.
	skewed, err := transport.Assign(ctx, route, "gateway-skewed", KafkaGroupIdentity{Generation: 9, MemberID: "member-skewed"})
	require.NoError(t, err)
	require.NoError(t, transport.AppendBatch(ctx, []AckCommand{{ID: "skew", Route: route, Token: "token-skew", AppendedAt: now}}))
	require.NoError(t, transport.Heartbeat(ctx, skewed, now.Add(24*time.Hour), 40*time.Millisecond))
	deliveries, err = transport.Claim(ctx, skewed, "fast-clock-worker", 1, time.Second, now.Add(24*time.Hour))
	require.NoError(t, err)
	require.Len(t, deliveries, 1, "a fast caller clock must not prematurely expire Redis ownership")
	require.Eventually(t, func() bool {
		_, claimErr := transport.Claim(ctx, skewed, "slow-clock-worker", 1, time.Second, now.Add(-24*time.Hour))
		return errors.Is(claimErr, ErrAckRouteFenced)
	}, time.Second, 5*time.Millisecond, "a slow caller clock must not prolong Redis ownership")

	t.Run("component global bounds are atomic across routes", func(t *testing.T) {
		bounded, createErr := NewRedisDurableAckTransport(client, RedisDurableAckOptions{Prefix: "test:ack-global", MaxEntries: 10, MaxBytes: 1024, MaxGlobalEntries: 3, MaxGlobalBytes: 64})
		require.NoError(t, createErr)
		routes := []AckRoute{{Key: route.Key, Topic: "topic", Partition: 0}, {Key: route.Key, Topic: "topic", Partition: 1}}
		firstKeys, secondKeys := bounded.keys(routes[0]), bounded.keys(routes[1])
		require.Equal(t, firstKeys.globalEntries, secondKeys.globalEntries)
		require.NotEqual(t, firstKeys.entries, secondKeys.entries)
		const attempts = 20
		var wg sync.WaitGroup
		results := make(chan error, attempts)
		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				selected := routes[i%len(routes)]
				results <- bounded.AppendBatch(ctx, []AckCommand{{ID: fmt.Sprintf("global-%d", i), Route: selected, Token: "token", AppendedAt: now.Add(time.Duration(i) * time.Nanosecond)}})
			}(i)
		}
		wg.Wait()
		close(results)
		successes := 0
		for appendErr := range results {
			if appendErr == nil {
				successes++
			} else {
				require.ErrorIs(t, appendErr, ErrAckBacklogFull)
			}
		}
		require.Equal(t, 3, successes)
		require.Equal(t, 3, bounded.Stats(ctx, routes[0]).Active+bounded.Stats(ctx, routes[1]).Active)
		globalCount, countErr := client.Get(ctx, firstKeys.globalEntries).Int()
		require.NoError(t, countErr)
		require.Equal(t, 3, globalCount)
		globalBytes, bytesErr := client.Get(ctx, firstKeys.globalBytes).Int64()
		require.NoError(t, bytesErr)
		require.Equal(t, int64(15), globalBytes)
	})
}

func TestRedisDurableAckTransportOutageRecoversPendingEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{Image: "redis:7-alpine", ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")}, Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	client := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port()), MaxRetries: 0})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	transport, err := NewRedisDurableAckTransport(client, RedisDurableAckOptions{Prefix: "test:outage"})
	require.NoError(t, err)
	route := testAckRoute()
	now := time.Now().UTC()
	require.NoError(t, transport.AppendBatch(ctx, []AckCommand{{ID: "pending", Route: route, Token: "token"}}))
	a, err := transport.Assign(ctx, route, "owner", KafkaGroupIdentity{Generation: 1, MemberID: "member"})
	require.NoError(t, err)
	deliveries, err := transport.Claim(ctx, a, "worker", 1, 100*time.Millisecond, now)
	require.NoError(t, err)
	require.Len(t, deliveries, 1)
	docker, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, docker.Close()) })
	require.NoError(t, docker.ContainerPause(ctx, container.GetContainerID()))
	failureCtx, failureCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	require.Error(t, transport.Complete(failureCtx, a, deliveries[0].Command.ID))
	failureCancel()
	require.NoError(t, docker.ContainerUnpause(ctx, container.GetContainerID()))
	require.Eventually(t, func() bool { return client.Ping(ctx).Err() == nil }, 10*time.Second, 100*time.Millisecond)
	deliveries, err = transport.Claim(ctx, a, "worker", 1, time.Second, now.Add(time.Second))
	require.NoError(t, err)
	require.Len(t, deliveries, 1)
	require.NoError(t, transport.Complete(ctx, a, deliveries[0].Command.ID))
	require.Zero(t, transport.Stats(ctx, route).Active)
}
