package kafka

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tckafka "github.com/testcontainers/testcontainers-go/modules/kafka"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

type stubOffsetController struct {
	plans    int
	executes int
	execute  ResetExecution
	err      error
}

func (s *stubOffsetController) PlanReset(_ context.Context, _ ResetPlanRequest) (ResetPlan, error) {
	s.plans++
	return ResetPlan{ID: "plan", Targets: []ResolvedResetTarget{{Topic: "topic", Partition: 2, TargetOffset: 17}}}, nil
}

func (s *stubOffsetController) ExecuteReset(_ context.Context, _ ResetExecuteRequest) (ResetExecution, error) {
	s.executes++
	if s.execute.Status != "" || s.err != nil {
		return s.execute, s.err
	}
	return ResetExecution{ID: "execution", Status: "completed"}, nil
}

type stubGroupLeaver struct {
	admin  *fakeResetAdmin
	calls  int
	closed bool
}

type noOpGroupLeaver struct{ calls int }

func (s *noOpGroupLeaver) LeaveGroupContext(context.Context) error { s.calls++; return nil }
func (s *noOpGroupLeaver) Close()                                  {}

type failingGroupLeaver struct{ err error }

func (s *failingGroupLeaver) LeaveGroupContext(context.Context) error { return s.err }
func (s *failingGroupLeaver) Close()                                  {}

func (s *stubGroupLeaver) LeaveGroupContext(context.Context) error {
	s.calls++
	s.admin.group = GroupDescription{State: "Empty"}
	return nil
}

func (s *stubGroupLeaver) Close() { s.closed = true }

func TestConnectorOffsetControllerQuiescesBeforeExecute(t *testing.T) {
	inner := &stubOffsetController{}
	admin := &fakeResetAdmin{group: GroupDescription{State: "Stable", Members: []string{"member"}}}
	leaver := &stubGroupLeaver{admin: admin}
	var gate sync.RWMutex
	var resetting atomic.Bool
	controller, err := NewConnectorOffsetController(inner, admin, "group", leaver, &gate, &resetting, nil)
	require.NoError(t, err)
	controller.pollPeriod = time.Millisecond

	plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{})
	require.NoError(t, err)
	assert.Equal(t, "plan", plan.ID)
	execution, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: "plan"})
	require.NoError(t, err)
	assert.Equal(t, "completed", execution.Status)
	assert.Equal(t, 1, leaver.calls)
	assert.True(t, leaver.closed)
	assert.Equal(t, 1, inner.executes)
	assert.False(t, resetting.Load())
}

func TestConnectorOffsetControllerFailsClosedWhenOtherMembersRemain(t *testing.T) {
	inner := &stubOffsetController{}
	admin := &fakeResetAdmin{group: GroupDescription{State: "Stable", Members: []string{"other-gateway"}}}
	leaver := &noOpGroupLeaver{}
	var gate sync.RWMutex
	var resetting atomic.Bool
	controller, err := NewConnectorOffsetController(inner, admin, "group", leaver, &gate, &resetting, nil)
	require.NoError(t, err)
	controller.pollPeriod = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	_, err = controller.ExecuteReset(ctx, ResetExecuteRequest{PlanID: "plan"})
	assertControlStatus(t, err, 409)
	assert.Zero(t, inner.executes)
}

func TestConnectorOffsetControllerValidationAndFailureLifecycle(t *testing.T) {
	inner := &stubOffsetController{}
	admin := &fakeResetAdmin{group: GroupDescription{State: "Empty"}}
	var gate sync.RWMutex
	var resetting atomic.Bool

	_, err := NewConnectorOffsetController(nil, admin, "group", &noOpGroupLeaver{}, &gate, &resetting, nil)
	require.Error(t, err)
	_, err = NewConnectorOffsetController(inner, admin, "", &noOpGroupLeaver{}, &gate, &resetting, nil)
	require.Error(t, err)

	leaver := &failingGroupLeaver{err: errors.New("leave failed")}
	controller, err := NewConnectorOffsetController(inner, admin, "group", leaver, &gate, &resetting, nil)
	require.NoError(t, err)
	_, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: "plan"})
	assertControlStatus(t, err, 503)
	require.False(t, resetting.Load(), "failure must release the reset fence")

	admin.groupErr = errors.New("describe failed")
	controller, err = NewConnectorOffsetController(inner, admin, "group", &noOpGroupLeaver{}, &gate, &resetting, nil)
	require.NoError(t, err)
	_, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: "plan"})
	assertControlStatus(t, err, 503)
}

func TestConnectorOffsetControllerCoordinatedAndPartialExecutionDoNotCloseClient(t *testing.T) {
	admin := &fakeResetAdmin{group: GroupDescription{State: "Empty"}}
	var gate sync.RWMutex
	var resetting atomic.Bool
	leaver := &stubGroupLeaver{admin: admin}
	inner := &stubOffsetController{execute: ResetExecution{ID: "execution", Status: "partial_failed"}}
	controller, err := NewConnectorOffsetController(inner, admin, "group", leaver, &gate, &resetting, nil)
	require.NoError(t, err)
	execution, err := controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: "plan"})
	require.NoError(t, err)
	require.Equal(t, "partial_failed", execution.Status)
	require.False(t, leaver.closed, "partial execution must leave the client available for operator recovery")

	controller.EnableDistributedCoordination()
	inner.execute = ResetExecution{ID: "coordinated", Status: "completed"}
	execution, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: "plan"})
	require.NoError(t, err)
	require.Equal(t, "coordinated", execution.ID)
	require.Equal(t, 1, leaver.calls, "distributed supervisor owns quiescence")
}

func TestConnectorOffsetControllerRealKafkaReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container, err := tckafka.Run(ctx, "confluentinc/confluent-local:7.5.0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	brokers, err := container.Brokers(ctx)
	require.NoError(t, err)
	topic := fmt.Sprintf("connector-reset-%d", time.Now().UnixNano())
	group := fmt.Sprintf("connector-reset-group-%d", time.Now().UnixNano())
	client, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.ConsumeTopics(topic), kgo.ConsumerGroup(group), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	require.NoError(t, err)
	t.Cleanup(client.Close)
	created, err := kadm.NewClient(client).CreateTopics(ctx, 1, 1, nil, topic)
	require.NoError(t, err)
	require.NoError(t, created.Error())
	require.NoError(t, client.ProduceSync(ctx, &kgo.Record{Topic: topic, Value: []byte("replay-me")}).FirstErr())
	var first *kgo.Record
	require.Eventually(t, func() bool {
		pollCtx, pollCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer pollCancel()
		iter := client.PollRecords(pollCtx, 1).RecordIter()
		if iter.Done() {
			return false
		}
		first = iter.Next()
		return first != nil
	}, 20*time.Second, 100*time.Millisecond)
	require.NoError(t, client.CommitRecords(ctx, first))

	admin, err := NewKadmOffsetResetAdmin(client)
	require.NoError(t, err)
	local, err := NewLocalOffsetResetController(LocalOffsetResetControllerConfig{ConsumerGroup: group, Topics: []string{topic}, Admin: admin, AllowActivePlan: true})
	require.NoError(t, err)
	var gate sync.RWMutex
	var resetting atomic.Bool
	controller, err := NewConnectorOffsetController(local, admin, group, client, &gate, &resetting, nil)
	require.NoError(t, err)
	target := int64(0)
	plan, err := controller.PlanReset(ctx, ResetPlanRequest{ConsumerGroup: group, Reason: "real replay", Targets: []ResetTarget{{Topic: topic, Partition: 0, Offset: &target}}})
	require.NoError(t, err)
	execution, err := controller.ExecuteReset(ctx, ResetExecuteRequest{PlanID: plan.ID})
	require.NoError(t, err)
	require.Equal(t, "completed", execution.Status)
	replayClient, err := kgo.NewClient(kgo.SeedBrokers(brokers...), kgo.ConsumeTopics(topic), kgo.ConsumerGroup(group), kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()))
	require.NoError(t, err)
	t.Cleanup(replayClient.Close)
	replayAdmin, err := NewKadmOffsetResetAdmin(replayClient)
	require.NoError(t, err)
	offsets, err := replayAdmin.FetchGroupOffsets(ctx, group, []TopicPartition{{Topic: topic, Partition: 0}})
	require.NoError(t, err)
	require.Equal(t, int64(0), offsets[TopicPartition{Topic: topic, Partition: 0}])
	var replay *kgo.Record
	require.Eventually(t, func() bool {
		pollCtx, pollCancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer pollCancel()
		iter := replayClient.PollRecords(pollCtx, 1).RecordIter()
		if iter.Done() {
			return false
		}
		replay = iter.Next()
		return replay != nil
	}, 20*time.Second, 100*time.Millisecond)
	require.Equal(t, int64(0), replay.Offset)
	require.Equal(t, []byte("replay-me"), replay.Value)
}
