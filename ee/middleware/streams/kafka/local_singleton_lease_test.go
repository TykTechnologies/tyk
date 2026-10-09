package kafka

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLocalSingletonLeaseRealRedisContentionAndTakeover(t *testing.T) {
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
	client := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port())})
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	first, err := AcquireLocalSingletonLease(ctx, client, "api_stream_input", 300*time.Millisecond)
	require.NoError(t, err)
	_, err = AcquireLocalSingletonLease(ctx, client, "api_stream_input", 300*time.Millisecond)
	require.ErrorIs(t, err, ErrLocalSingletonHeld)
	first.Close()
	second, err := AcquireLocalSingletonLease(ctx, client, "api_stream_input", 300*time.Millisecond)
	require.NoError(t, err)
	second.cancel() // simulate a crashed gateway: stop heartbeats without release
	<-second.done
	require.Eventually(t, func() bool {
		takeover, takeoverErr := AcquireLocalSingletonLease(ctx, client, "api_stream_input", 300*time.Millisecond)
		if takeoverErr != nil {
			return false
		}
		takeover.Close()
		return true
	}, 2*time.Second, 50*time.Millisecond)
}
