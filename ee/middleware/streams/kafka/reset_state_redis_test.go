package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type failAfterExecHook struct{ fired atomic.Bool }

func (h *failAfterExecHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}
func (h *failAfterExecHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook { return next }
func (h *failAfterExecHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		err := next(ctx, cmds)
		if err == nil {
			for _, cmd := range cmds {
				if cmd.Name() == "exec" && h.fired.CompareAndSwap(false, true) {
					return errors.New("injected response loss after EXEC")
				}
			}
		}
		return err
	}
}

func TestRedisResetStateStoreRealRedis(t *testing.T) {
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
	store, err := NewRedisResetStateStore(client, "test:reset")
	require.NoError(t, err)
	store.SetAuditIdentity("api-id", "stream-id", "component-id")
	now := time.Now().UTC()
	plan := StoredResetPlan{Plan: ResetPlan{ID: "plan", ExpiresAt: now.Add(time.Hour)}, ConsumerGroup: "group"}
	require.NoError(t, store.PutPlan(ctx, plan))
	require.NoError(t, store.PutPlan(ctx, plan), "identical plan persistence is idempotent")

	first, err := store.AcquireExecutionLease(ctx, "group", "plan", "leader-a", 100*time.Millisecond, now.Add(-24*time.Hour))
	require.NoError(t, err)
	time.Sleep(60 * time.Millisecond)
	renewedByAcquire, err := store.AcquireExecutionLease(ctx, "group", "plan", "leader-a", 250*time.Millisecond, now.Add(24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, first.Generation, renewedByAcquire.Generation, "same-owner acquisition renews rather than fencing itself")
	leasePTTL, err := client.PTTL(ctx, store.groupLeaseKeys("group").lease).Result()
	require.NoError(t, err)
	require.Greater(t, leasePTTL, 150*time.Millisecond, "same-owner acquisition must refresh the native Redis TTL")
	_, err = store.AcquireExecutionLease(ctx, "group", "plan", "leader-b", time.Second, now.Add(24*time.Hour))
	require.ErrorIs(t, err, ErrResetLeaseHeld)
	_, err = store.AcquireExecutionLease(ctx, "group", "different-plan", "leader-a", time.Second, now)
	require.ErrorIs(t, err, ErrResetLeaseHeld, "one live plan must own reset leadership for the whole consumer group")
	var second ResetExecutionLease
	require.Eventually(t, func() bool {
		second, err = store.AcquireExecutionLease(ctx, "group", "plan", "leader-b", 5*time.Second, now.Add(-24*time.Hour))
		return err == nil
	}, time.Second, 10*time.Millisecond, "native Redis TTL eventually permits takeover despite a slow caller clock")
	require.Greater(t, second.Generation, first.Generation)
	execution := StoredResetExecution{PlanID: "plan", Execution: ResetExecution{ID: "execution", Status: "running"}, Targets: []ResetTargetState{{Applied: true}}}
	require.ErrorIs(t, store.PutExecutionFenced(ctx, first, execution, now.Add(-24*time.Hour)), ErrResetFenced)
	require.NoError(t, store.PutExecutionFenced(ctx, second, execution, now.Add(24*time.Hour)))
	stored, ok, err := store.GetExecution(ctx, "plan")
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, stored.Targets[0].Applied, "partial target progress survives leader takeover")

	coordinationNow := now.Add(24 * time.Hour)
	require.NoError(t, store.HeartbeatParticipant(ctx, "group", "gateway-a", 100*time.Millisecond, coordinationNow))
	require.NoError(t, store.HeartbeatParticipant(ctx, "group", "gateway-b", 100*time.Millisecond, now.Add(-24*time.Hour)))
	// Model a stale LiveParticipants scan that classified gateway-a as
	// expired immediately before its heartbeat. Cleanup must recheck the
	// watched TTL key and retain the newly-live membership index.
	members, _, acknowledgements := store.coordinationKeys("group")
	revived, err := store.cleanupExpiredParticipant(ctx, members, "gateway-a")
	require.NoError(t, err)
	require.True(t, revived, "cleanup must report a heartbeat that won the expiry race")
	indexed, err := client.HExists(ctx, members, "gateway-a").Result()
	require.NoError(t, err)
	require.True(t, indexed)
	barrier, err := store.RequestQuiesce(ctx, second, "group", "replay-1", coordinationNow)
	require.NoError(t, err)
	require.Equal(t, []string{"gateway-a", "gateway-b"}, barrier.Participants)
	// A connector appearing after the initial snapshot is atomically enrolled
	// in the active generation and cannot fetch through the reset barrier. Any
	// stale acknowledgement predating enrollment must not satisfy the barrier.
	require.NoError(t, client.HSet(ctx, acknowledgements, "gateway-c", "0").Err())
	require.NoError(t, store.HeartbeatParticipant(ctx, "group", "gateway-c", 100*time.Millisecond, coordinationNow))
	_, err = client.HGet(ctx, acknowledgements, "gateway-c").Result()
	require.ErrorIs(t, err, redis.Nil, "first enrollment clears a stale acknowledgement")
	barrier, ok, err = store.CurrentBarrier(ctx, "group")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []string{"gateway-a", "gateway-b", "gateway-c"}, barrier.Participants)
	require.NoError(t, store.AcknowledgeQuiesced(ctx, barrier, "gateway-a"))
	status, err := store.BarrierStatus(ctx, barrier)
	require.NoError(t, err)
	require.False(t, status.Complete)
	require.NoError(t, store.AcknowledgeQuiesced(ctx, barrier, "gateway-b"))
	status, err = store.BarrierStatus(ctx, barrier)
	require.NoError(t, err)
	require.False(t, status.Complete, "late participant must block completion until it quiesces")
	require.NoError(t, store.AcknowledgeQuiesced(ctx, barrier, "gateway-c"))
	// Steady heartbeats must preserve the durable current-generation ack.
	require.NoError(t, store.HeartbeatParticipant(ctx, "group", "gateway-c", 100*time.Millisecond, coordinationNow))
	ackGeneration, err := client.HGet(ctx, acknowledgements, "gateway-c").Result()
	require.NoError(t, err)
	require.Equal(t, resetBarrierAckIdentity(barrier), ackGeneration)
	status, err = store.BarrierStatus(ctx, barrier)
	require.NoError(t, err)
	require.True(t, status.Complete)
	require.NoError(t, store.PublishResume(ctx, second, "group", "replay-2", coordinationNow))
	resumed, ok, err := store.CurrentBarrier(ctx, "group")
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, resumed.Resume)
	require.Equal(t, "replay-2", resumed.ReplayID)

	// A crashed participant whose heartbeat expired is not allowed to block a
	// takeover generation forever; an old-generation ack cannot satisfy it.
	require.Eventually(t, func() bool {
		live, liveErr := store.LiveParticipants(ctx, "group", now.Add(-24*time.Hour))
		return liveErr == nil && len(live) == 0
	}, time.Second, 10*time.Millisecond, "native participant TTL expires despite a slow caller clock")
	takeoverNow := now.Add(-24 * time.Hour)
	require.NoError(t, store.HeartbeatParticipant(ctx, "group", "gateway-b", time.Second, takeoverNow))
	require.NoError(t, store.ReleaseExecutionLease(ctx, second))
	thirdLeader, err := store.AcquireExecutionLease(ctx, "group", "plan", "leader-c", time.Second, takeoverNow)
	require.NoError(t, err)
	takeoverBarrier, err := store.RequestQuiesce(ctx, thirdLeader, "group", "replay-3", takeoverNow)
	require.NoError(t, err)
	require.Equal(t, []string{"gateway-b"}, takeoverBarrier.Participants)
	require.ErrorIs(t, store.AcknowledgeQuiesced(ctx, barrier, "gateway-a"), ErrResetFenced)
	require.NoError(t, store.AcknowledgeQuiesced(ctx, takeoverBarrier, "gateway-b"))
	status, err = store.BarrierStatus(ctx, takeoverBarrier)
	require.NoError(t, err)
	require.True(t, status.Complete)

	// Simulate the transport losing EXEC's successful response. Production
	// reconciliation must discover the committed generation and publish its
	// abort/resume before returning the original error.
	require.NoError(t, store.HeartbeatParticipant(ctx, "ambiguous-group", "gateway-a", time.Second, now))
	ambiguousLease, err := store.AcquireExecutionLease(ctx, "ambiguous-group", "ambiguous-plan", "leader-a", time.Second, now)
	require.NoError(t, err)
	fault := &failAfterExecHook{}
	client.AddHook(fault)
	_, ambiguousErr := store.RequestQuiesce(ctx, ambiguousLease, "ambiguous-group", "ambiguous-replay", now)
	require.ErrorContains(t, ambiguousErr, "injected response loss")
	require.True(t, fault.fired.Load(), "fault must occur after a real EXEC")
	ambiguousBarrier, exists, err := store.CurrentBarrier(ctx, "ambiguous-group")
	require.NoError(t, err)
	require.True(t, exists)
	require.True(t, ambiguousBarrier.Resume, "same-generation abort/resume must be durable before the lease can be released")

	// Expired generations are recovered automatically, while a native live
	// lease (including a concurrently acquired newer generation) fences the
	// janitor from changing the barrier.
	expiringLease, err := store.AcquireExecutionLease(ctx, "expired-group", "expired-barrier", "leader-a", 80*time.Millisecond, now)
	require.NoError(t, err)
	require.NoError(t, store.HeartbeatParticipant(ctx, "expired-group", "gateway-a", time.Second, now))
	_, err = store.RequestQuiesce(ctx, expiringLease, "expired-group", "replay-expiring", now)
	require.NoError(t, err)
	var recoveredAudit atomic.Int64
	store.SetAuditObserver(func(event ResetAuditEvent) {
		if event.Outcome == "expired_barrier_recovered" {
			recoveredAudit.Add(1)
		}
	})
	_, recovered, err := store.RecoverExpiredBarrier(ctx, "expired-group", now)
	require.NoError(t, err)
	require.False(t, recovered, "a live execution lease must never be auto-resumed")
	require.Eventually(t, func() bool {
		barrier, didRecover, recoverErr := store.RecoverExpiredBarrier(ctx, "expired-group", time.Now())
		return recoverErr == nil && didRecover && barrier.Resume
	}, time.Second, 10*time.Millisecond)
	_, recovered, err = store.RecoverExpiredBarrier(ctx, "expired-group", time.Now())
	require.NoError(t, err)
	require.False(t, recovered, "expired recovery is idempotent")
	recoveryAuditKey := store.auditKey()
	require.EqualValues(t, 1, client.LLen(ctx, recoveryAuditKey).Val(), "recovery and its durable audit outbox record are atomic")
	auditJSON, err := client.LIndex(ctx, recoveryAuditKey, 0).Bytes()
	require.NoError(t, err)
	require.NotContains(t, string(auditJSON), "expired-group")
	require.NotContains(t, string(auditJSON), "leader-a")
	var recoveryAudit ResetAuditEvent
	require.NoError(t, json.Unmarshal(auditJSON, &recoveryAudit))
	require.Equal(t, "expired_barrier_recovered", recoveryAudit.Outcome)
	require.Equal(t, hashStatusIdentity("expired-group"), recoveryAudit.ConsumerGroupHash)
	require.EqualValues(t, 1, recoveredAudit.Load(), "observer is notified once after the atomic recovery transaction")

	// A full canonical audit journal fails recovery closed: the active barrier
	// remains in place rather than becoming an unaudited resume.
	fill := make([]any, maxResetAuditEntries-1)
	for i := range fill {
		fill[i] = `{}`
	}
	require.NoError(t, client.RPush(ctx, recoveryAuditKey, fill...).Err())
	fullLease, err := store.AcquireExecutionLease(ctx, "full-audit-group", "full-audit-plan", "leader", 20*time.Millisecond, now)
	require.NoError(t, err)
	_, err = store.RequestQuiesce(ctx, fullLease, "full-audit-group", "full-audit-replay", now)
	require.NoError(t, err)
	time.Sleep(30 * time.Millisecond)
	barrier, recovered, err = store.RecoverExpiredBarrier(ctx, "full-audit-group", time.Now())
	require.ErrorContains(t, err, "audit backlog is full")
	require.False(t, recovered)
	require.False(t, barrier.Resume)
	require.EqualValues(t, maxResetAuditEntries, client.LLen(ctx, recoveryAuditKey).Val())
	require.EqualValues(t, 1, recoveredAudit.Load(), "failed recovery must not reach the exporter")

	fencedLease, err := store.AcquireExecutionLease(ctx, "fenced-group", "fenced-barrier", "leader-a", 50*time.Millisecond, now)
	require.NoError(t, err)
	require.NoError(t, store.HeartbeatParticipant(ctx, "fenced-group", "gateway-a", time.Second, now))
	_, err = store.RequestQuiesce(ctx, fencedLease, "fenced-group", "replay-fenced", now)
	require.NoError(t, err)
	var newLease ResetExecutionLease
	require.Eventually(t, func() bool {
		newLease, err = store.AcquireExecutionLease(ctx, "fenced-group", "fenced-barrier", "leader-b", time.Second, now)
		return err == nil
	}, time.Second, 10*time.Millisecond)
	require.Greater(t, newLease.Generation, fencedLease.Generation)
	barrier, recovered, err = store.RecoverExpiredBarrier(ctx, "fenced-group", now)
	require.NoError(t, err)
	require.False(t, recovered, "a concurrently acquired lease fences expired-barrier recovery")
	require.False(t, barrier.Resume)

	third, err := store.AcquireExecutionLease(ctx, "expiry-group", "expiry", "leader-a", 20*time.Millisecond, time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return errors.Is(store.PutExecutionFenced(ctx, third, StoredResetExecution{PlanID: "expiry"}, time.Now().Add(-24*time.Hour)), ErrResetFenced)
	}, time.Second, 10*time.Millisecond)

	const contenders = 12
	var wg sync.WaitGroup
	results := make(chan error, contenders)
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, acquireErr := store.AcquireExecutionLease(ctx, "concurrent-group", "concurrent", fmt.Sprintf("owner-%d", i), time.Minute, time.Now())
			results <- acquireErr
		}(i)
	}
	wg.Wait()
	close(results)
	winners := 0
	for acquireErr := range results {
		if acquireErr == nil {
			winners++
		} else {
			require.ErrorIs(t, acquireErr, ErrResetLeaseHeld)
		}
	}
	require.Equal(t, 1, winners, "CAS lease permits exactly one reset leader")

	planA, err := store.AcquireExecutionLease(ctx, "shared-group", "plan-a", "leader-a", 40*time.Millisecond, now)
	require.NoError(t, err)
	_, err = store.AcquireExecutionLease(ctx, "shared-group", "plan-b", "leader-b", time.Second, now)
	require.ErrorIs(t, err, ErrResetLeaseHeld)
	var planB ResetExecutionLease
	require.Eventually(t, func() bool {
		planB, err = store.AcquireExecutionLease(ctx, "shared-group", "plan-b", "leader-b", time.Second, now)
		return err == nil
	}, time.Second, 10*time.Millisecond)
	require.Greater(t, planB.Generation, planA.Generation, "generation is monotonic across plan IDs in one group")
}
