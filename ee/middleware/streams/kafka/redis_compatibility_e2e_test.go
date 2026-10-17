package kafka

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func redisCompatibilityImages() []string {
	if configured := strings.TrimSpace(os.Getenv("TYK_REDIS_COMPAT_IMAGES")); configured != "" {
		var images []string
		for _, image := range strings.Split(configured, ",") {
			if image = strings.TrimSpace(image); image != "" {
				images = append(images, image)
			}
		}
		if len(images) > 0 {
			return images
		}
	}
	return []string{"redis:6-alpine", "redis:7-alpine"}
}

func TestRedisExternalAckAndResetCompatibilityMatrixE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	for _, image := range redisCompatibilityImages() {
		image := image
		t.Run(strings.NewReplacer("/", "_", ":", "_").Replace(image), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
				ContainerRequest: testcontainers.ContainerRequest{Image: image, ExposedPorts: []string{"6379/tcp"}, WaitingFor: wait.ForListeningPort("6379/tcp")}, Started: true,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = container.Terminate(context.Background()) })
			host, err := container.Host(ctx)
			require.NoError(t, err)
			port, err := container.MappedPort(ctx, "6379/tcp")
			require.NoError(t, err)
			client := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%s", host, port.Port())})
			defer client.Close()
			require.NoError(t, client.Ping(ctx).Err())
			suffix := fmt.Sprintf("%d", time.Now().UnixNano())

			route := AckRoute{Key: ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}, Topic: "events", Partition: 0}
			transport, err := NewRedisDurableAckTransport(client, RedisDurableAckOptions{Prefix: "compat:ack:" + suffix, MaxEntries: 8, MaxBytes: 1024})
			require.NoError(t, err)
			assignment, err := transport.Assign(ctx, route, "gateway-a", KafkaGroupIdentity{Generation: 1, MemberID: "member-a"})
			require.NoError(t, err)
			command := AckCommand{ID: "command-1", Route: route, Token: "signed-token", AppendedAt: time.Now().UTC()}
			require.NoError(t, transport.AppendBatch(ctx, []AckCommand{command}))
			deliveries, err := transport.Claim(ctx, assignment, "worker-a", 1, time.Second, time.Now().UTC())
			require.NoError(t, err)
			require.Len(t, deliveries, 1)
			require.Equal(t, command.ID, deliveries[0].Command.ID)
			require.NoError(t, transport.Complete(ctx, assignment, command.ID))
			require.Equal(t, AckBacklogStats{}, transport.Stats(ctx, route))

			store, err := NewRedisResetStateStore(client, "compat:reset:"+suffix)
			require.NoError(t, err)
			now := time.Now().UTC()
			plan := StoredResetPlan{Plan: ResetPlan{ID: "plan-1", ExpiresAt: now.Add(time.Minute)}, ConsumerGroup: "group"}
			require.NoError(t, store.PutPlan(ctx, plan))
			first, err := store.AcquireExecutionLease(ctx, plan.ConsumerGroup, plan.Plan.ID, "leader-a", 10*time.Second, now)
			require.NoError(t, err)
			_, err = store.AcquireExecutionLease(ctx, plan.ConsumerGroup, plan.Plan.ID, "leader-b", 10*time.Second, now)
			require.ErrorIs(t, err, ErrResetLeaseHeld)
			require.NoError(t, store.ReleaseExecutionLease(ctx, first))
			second, err := store.AcquireExecutionLease(ctx, plan.ConsumerGroup, plan.Plan.ID, "leader-b", 10*time.Second, now.Add(time.Millisecond))
			require.NoError(t, err)
			require.Greater(t, second.Generation, first.Generation)
			require.NoError(t, store.ReleaseExecutionLease(ctx, second))
		})
	}
}
