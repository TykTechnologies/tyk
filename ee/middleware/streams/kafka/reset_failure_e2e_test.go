package kafka

import (
	"context"
	"fmt"
	"testing"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/twmb/franz-go/pkg/kgo"
)

// TestDistributedResetBrokerLossAbortsWithoutOffsetAdvance proves the
// production admin path fails closed when Kafka disappears after planning.
// The durable coordinator is intentionally a deterministic fake so the test
// isolates broker behavior while asserting the distributed gate is released.
func TestDistributedResetBrokerLossAbortsWithoutOffsetAdvance(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.RequestTimeoutOverhead(time.Second),
		kgo.AllowAutoTopicCreation(),
	)
	require.NoError(t, err)
	t.Cleanup(client.Close)
	admin, err := NewKadmOffsetResetAdmin(client)
	require.NoError(t, err)
	topic := fmt.Sprintf("reset-outage-%d", time.Now().UnixNano())
	require.Eventually(t, func() bool {
		return client.ProduceSync(ctx,
			&kgo.Record{Topic: topic, Value: []byte("one")},
			&kgo.Record{Topic: topic, Value: []byte("two")},
		).FirstErr() == nil
	}, 20*time.Second, 200*time.Millisecond, "topic auto-creation and initial produce did not become ready")
	group := fmt.Sprintf("reset-outage-group-%d", time.Now().UnixNano())
	partition := TopicPartition{Topic: topic, Partition: 0}
	results, err := admin.AlterGroupOffsets(ctx, group, map[TopicPartition]int64{partition: 0})
	require.NoError(t, err)
	require.NoError(t, results[partition])

	store := &abortTestStore{InMemoryResetStateStore: NewInMemoryResetStateStore()}
	coordinator := &abortTestCoordinator{}
	controller, err := NewLocalOffsetResetController(LocalOffsetResetControllerConfig{
		ConsumerGroup: group, Topics: []string{topic}, Admin: admin, Store: store,
		OwnerID: "reset-outage-owner", Coordinator: coordinator, AllowActivePlan: true,
	})
	require.NoError(t, err)
	target := int64(1)
	plan, err := controller.PlanReset(ctx, ResetPlanRequest{ConsumerGroup: group, Reason: "broker outage recovery", Targets: []ResetTarget{{Topic: topic, Partition: 0, Offset: &target}}})
	require.NoError(t, err)

	docker, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	require.NoError(t, err)
	t.Cleanup(func() { _ = docker.Close() })
	paused := true
	require.NoError(t, docker.ContainerPause(ctx, container.GetContainerID()))
	t.Cleanup(func() {
		if paused {
			_ = docker.ContainerUnpause(context.Background(), container.GetContainerID())
		}
	})
	executeCtx, stopExecute := context.WithTimeout(context.Background(), 3*time.Second)
	_, executeErr := controller.ExecuteReset(executeCtx, ResetExecuteRequest{PlanID: plan.ID})
	stopExecute()
	require.Error(t, executeErr)
	require.Equal(t, 1, coordinator.quiesces)
	require.Equal(t, 1, coordinator.resumes, "broker failure after quiesce must publish abort-resume")

	require.NoError(t, docker.ContainerUnpause(ctx, container.GetContainerID()))
	paused = false
	require.Eventually(t, func() bool {
		current, fetchErr := admin.FetchGroupOffsets(ctx, group, []TopicPartition{partition})
		return fetchErr == nil && current[partition] == 0
	}, 20*time.Second, 200*time.Millisecond, "failed reset must not advance the group offset")

	execution, err := controller.ExecuteReset(ctx, ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	require.Equal(t, "completed", execution.Status)
	require.Equal(t, 2, coordinator.resumes, "successful retry must publish normal resume")
	current, err := admin.FetchGroupOffsets(ctx, group, []TopicPartition{partition})
	require.NoError(t, err)
	require.Equal(t, target, current[partition])
}
