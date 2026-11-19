package kafka

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeResetSupervisorStore struct {
	mu              sync.Mutex
	barrier         ResetBarrier
	current         bool
	complete        bool
	heartbeats      int
	acknowledgments int
	resumes         int
	recoveries      int
	leaseExpired    bool
	err             error
	heartbeatBlock  <-chan struct{}
}

func (f *fakeResetSupervisorStore) HeartbeatParticipant(context.Context, string, string, time.Duration, time.Time) error {
	f.mu.Lock()
	f.heartbeats++
	err, block := f.err, f.heartbeatBlock
	f.mu.Unlock()
	if block != nil {
		<-block // deliberately ignores context to exercise the independent watchdog
	}
	return err
}
func (f *fakeResetSupervisorStore) CurrentBarrier(context.Context, string) (ResetBarrier, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.barrier, f.current, f.err
}
func (f *fakeResetSupervisorStore) RecoverExpiredBarrier(_ context.Context, _ string, _ time.Time) (ResetBarrier, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.barrier, false, f.err
	}
	if !f.current || f.barrier.Resume || !f.leaseExpired {
		return f.barrier, false, nil
	}
	f.barrier.Resume = true
	f.barrier.ReplayID = "abort-expired-test"
	f.recoveries++
	return f.barrier, true, nil
}
func (f *fakeResetSupervisorStore) AcknowledgeQuiesced(context.Context, ResetBarrier, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acknowledgments++
	return f.err
}
func (f *fakeResetSupervisorStore) RequestQuiesce(context.Context, ResetExecutionLease, string, string, time.Time) (ResetBarrier, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.barrier, f.err
}
func (f *fakeResetSupervisorStore) BarrierStatus(context.Context, ResetBarrier) (ResetBarrierStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ResetBarrierStatus{Complete: f.complete}, f.err
}
func (f *fakeResetSupervisorStore) PublishResume(context.Context, ResetExecutionLease, string, string, time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resumes++
	return f.err
}

type lifecycleResetClient struct {
	leaves atomic.Int32
	closes atomic.Int32
}

func (c *lifecycleResetClient) LeaveGroupContext(context.Context) error {
	c.leaves.Add(1)
	return nil
}
func (c *lifecycleResetClient) Close() { c.closes.Add(1) }

type blockingResetClient struct {
	lifecycleResetClient
	started chan struct{}
	release chan struct{}
}

func (c *blockingResetClient) Close() {
	c.closes.Add(1)
	close(c.started)
	<-c.release
}

func simulateResetPollLoopExit(s *RedisResetSupervisor, gate *sync.RWMutex) <-chan struct{} {
	done := make(chan struct{})
	started := make(chan struct{})
	go func() {
		close(started)
		gate.RLock()
		gate.RUnlock()
		// Mirrors the poll goroutine defer ordering: attach gate is secured
		// before batchChan is cleared and Bento can reconnect.
		s.UpdateClient(nil, nil)
		close(done)
	}()
	<-started
	return done
}

func TestResetSupervisorResumeKeepsGateUntilReplacementHandshake(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	client := &lifecycleResetClient{}
	s := &RedisResetSupervisor{pollGate: &gate, resetting: &resetting, client: client}
	gate.Lock()
	resetting.Store(true)
	s.blocked.Store(true)
	s.gateHeld = true
	s.barrierGeneration = 7
	s.barrierPlanID = "plan"
	s.barrierOwner = "owner"

	s.resumeLocal("plan", 6)
	require.Zero(t, client.closes.Load(), "stale resume must not reconstruct the client")
	require.True(t, s.blocked.Load())

	pollExited := simulateResetPollLoopExit(s, &gate)
	s.resumeLocal("plan", 7)
	<-pollExited
	require.EqualValues(t, 1, client.closes.Load())
	require.True(t, resetting.Load())
	require.True(t, s.blocked.Load())
	require.False(t, gate.TryLock(), "resume must not expose the stale client before replacement handshake")

	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	s.initializeAttached(replacement, ResetBarrier{PlanID: "plan", Owner: "owner", LeaseGeneration: 7, Resume: true}, true)
	require.False(t, resetting.Load())
	require.False(t, s.blocked.Load())
	require.True(t, gate.TryLock(), "replacement handshake releases the polling gate")
	gate.Unlock()
}

func TestResetSupervisorClassifiesQuiesceResumeAsReconstruction(t *testing.T) {
	resume := ResetBarrier{PlanID: "plan", Owner: "owner", LeaseGeneration: 7, Resume: true}
	require.True(t, resumeRequiresReconstruction(true, "plan", "owner", 7, resume, true))
	require.False(t, resumeRequiresReconstruction(true, "", "", 0, resume, true), "initial attachment observes resume without closing its fresh client")
	require.False(t, resumeRequiresReconstruction(true, "plan", "owner", 6, resume, true), "stale resume cannot reconstruct another generation")
	require.False(t, resumeRequiresReconstruction(true, "different-plan", "owner", 7, resume, true), "the same generation from another plan cannot alias")
	require.False(t, resumeRequiresReconstruction(true, "plan", "different-owner", 7, resume, true), "the same plan and generation from another owner cannot alias")
	require.False(t, resumeRequiresReconstruction(true, "plan", "owner", 7, resume, false))
}

func TestResetSupervisorRejectsResumeFromDifferentOwnerIdentity(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{barrier: ResetBarrier{PlanID: "plan", Owner: "owner-a", LeaseGeneration: 7, Participants: []string{"member"}}, current: true}
	s, err := NewRedisResetSupervisor(store, "group", "member", &gate, &resetting)
	require.NoError(t, err)
	client := &lifecycleResetClient{}
	s.UpdateClient(client, nil)
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.quiescedGeneration == 7
	}, time.Second, 5*time.Millisecond)
	store.mu.Lock()
	store.barrier.Resume = true
	store.barrier.Owner = "owner-b"
	store.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	require.Zero(t, client.closes.Load(), "same plan and generation from another owner must not release or reconstruct")
	require.True(t, s.Blocked())
	s.Close()
}

func TestResetBarrierAckIdentityDoesNotAliasPlanOwnerOrReplay(t *testing.T) {
	base := ResetBarrier{Version: 2, ConsumerGroup: "group", PlanID: "plan-a", Owner: "owner-a", LeaseGeneration: 7, ReplayID: "replay-a"}
	for _, other := range []ResetBarrier{
		{Version: 2, ConsumerGroup: "group", PlanID: "plan-b", Owner: "owner-a", LeaseGeneration: 7, ReplayID: "replay-a"},
		{Version: 2, ConsumerGroup: "group", PlanID: "plan-a", Owner: "owner-b", LeaseGeneration: 7, ReplayID: "replay-a"},
		{Version: 2, ConsumerGroup: "group", PlanID: "plan-a", Owner: "owner-a", LeaseGeneration: 7, ReplayID: "replay-b"},
	} {
		require.NotEqual(t, resetBarrierAckIdentity(base), resetBarrierAckIdentity(other))
	}
}

func TestResetSupervisorStuckCloseIsSingleAndDeadlineBounded(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	close(done)
	client := &blockingResetClient{started: make(chan struct{}), release: make(chan struct{})}
	s := &RedisResetSupervisor{pollGate: &gate, resetting: &resetting, client: client, ctx: ctx, cancel: cancel, done: done}
	gate.Lock()
	resetting.Store(true)
	s.blocked.Store(true)
	s.gateHeld, s.barrierGeneration = true, 9
	s.barrierPlanID = "plan"

	s.resumeLocal("plan", 9)
	<-client.started
	s.resumeLocal("plan", 9)
	require.EqualValues(t, 1, client.closes.Load(), "repeated resume must not double-close")
	require.False(t, gate.TryLock(), "gate cannot open before Close returns")
	deadline, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	require.ErrorIs(t, s.CloseContext(deadline), context.DeadlineExceeded)
	require.False(t, gate.TryLock(), "shutdown timeout cannot transfer gate ownership")

	close(client.release)
	require.Eventually(t, func() bool {
		s.mu.Lock()
		closing := s.closing
		s.mu.Unlock()
		return !closing
	}, time.Second, time.Millisecond)
	require.Eventually(t, func() bool {
		if !gate.TryLock() {
			return false
		}
		gate.Unlock()
		return true
	}, time.Second, time.Millisecond, "eventual Close completion releases the old poll loop")
}

func TestResetSupervisorReplacementRacingCloseStaysGated(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	old := &blockingResetClient{started: make(chan struct{}), release: make(chan struct{})}
	s := &RedisResetSupervisor{pollGate: &gate, resetting: &resetting, client: old, updated: make(chan struct{}, 1)}
	gate.Lock()
	resetting.Store(true)
	s.blocked.Store(true)
	s.gateHeld, s.barrierGeneration = true, 3
	s.barrierPlanID = "plan"
	s.resumeLocal("plan", 3)
	<-old.started

	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	close(old.release)
	require.Eventually(t, func() bool {
		s.mu.Lock()
		closing := s.closing
		s.mu.Unlock()
		return !closing
	}, time.Second, time.Millisecond)
	require.False(t, gate.TryLock(), "replacement cannot poll before its durable handshake")
	s.initializeAttached(replacement, ResetBarrier{PlanID: "plan", LeaseGeneration: 3, Resume: true}, true)
	require.Eventually(t, func() bool {
		if !gate.TryLock() {
			return false
		}
		gate.Unlock()
		return true
	}, time.Second, time.Millisecond, "successful registration releases the poll gate")
}

func TestResetSupervisorTerminalShutdownWinsReplacementRace(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	close(runDone)
	old := &blockingResetClient{started: make(chan struct{}), release: make(chan struct{})}
	s := &RedisResetSupervisor{pollGate: &gate, resetting: &resetting, client: old, ctx: ctx, cancel: cancel, done: runDone, watchdogDone: runDone, updated: make(chan struct{}, 1)}
	gate.Lock()
	resetting.Store(true)
	s.blocked.Store(true)
	s.gateHeld, s.barrierGeneration = true, 12
	s.barrierPlanID = "plan"
	s.resumeLocal("plan", 12)
	<-old.started

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- s.CloseContext(context.Background()) }()
	require.Eventually(t, func() bool {
		s.mu.Lock()
		terminal := s.shuttingDown
		s.mu.Unlock()
		return terminal
	}, time.Second, time.Millisecond)
	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	close(old.release)
	require.NoError(t, <-shutdownDone)
	require.EqualValues(t, 1, old.closes.Load())
	require.Zero(t, replacement.closes.Load())
	require.True(t, gate.TryLock(), "terminal completion must release the physical gate despite a raced replacement")
	gate.Unlock()
	require.False(t, resetting.Load())
	require.False(t, s.Blocked())
}

func TestResetSupervisorFailureReleaseKeepsAdminClientUsable(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	client := &lifecycleResetClient{}
	s := &RedisResetSupervisor{pollGate: &gate, resetting: &resetting, client: client}
	gate.Lock()
	resetting.Store(true)
	s.blocked.Store(true)
	s.gateHeld = true
	s.barrierGeneration = 9
	s.barrierPlanID = "plan"

	s.releaseGate("plan", 9, false)
	require.Zero(t, client.closes.Load(), "quiesce failure must not destroy the admin-capable client")
	require.False(t, resetting.Load())
	require.True(t, gate.TryLock())
	gate.Unlock()
}

func TestResetSupervisorValidatesDependenciesAndLifecycle(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{}

	_, err := NewRedisResetSupervisor(nil, "group", "member", &gate, &resetting)
	require.Error(t, err)
	_, err = NewRedisResetSupervisor(store, "", "member", &gate, &resetting)
	require.Error(t, err)

	s, err := NewRedisResetSupervisor(store, "group", "member", &gate, &resetting)
	require.NoError(t, err)
	s.UpdateClient(&lifecycleResetClient{}, nil)
	require.Eventually(t, func() bool { return !s.Blocked() }, time.Second, time.Millisecond)
	s.Close()
	store.mu.Lock()
	require.Positive(t, store.heartbeats)
	store.mu.Unlock()
	// Close is deliberately nil-safe for optional connector setup paths.
	(*RedisResetSupervisor)(nil).Close()
}

func TestResetSupervisorStartsBlockedAndQuiescesLateJoinBeforePolling(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{
		barrier: ResetBarrier{PlanID: "plan", ConsumerGroup: "group", Owner: "owner", LeaseGeneration: 7, Participants: []string{"existing-member"}},
		current: true,
	}
	s, err := NewRedisResetSupervisor(store, "group", "member", &gate, &resetting)
	require.NoError(t, err)
	require.True(t, s.Blocked(), "constructor must not expose a late joiner as fetch-ready")

	client := &lifecycleResetClient{}
	s.UpdateClient(client, nil)
	require.Eventually(t, func() bool { return client.leaves.Load() == 1 }, time.Second, time.Millisecond, "attached late joiner must leave before polling")
	require.True(t, s.Blocked())
	require.True(t, resetting.Load())
	require.False(t, gate.TryLock(), "poll gate remains closed until matching resume")
	store.mu.Lock()
	require.Zero(t, store.acknowledgments, "late joiner outside the barrier snapshot stays gated but cannot acknowledge for another participant")
	store.mu.Unlock()

	store.mu.Lock()
	store.barrier.Resume = true
	store.mu.Unlock()
	pollExited := simulateResetPollLoopExit(s, &gate)
	s.resumeLocal("plan", 7)
	<-pollExited
	require.True(t, s.Blocked())
	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	s.initializeAttached(replacement, store.barrier, true)
	require.False(t, s.Blocked())
	require.True(t, gate.TryLock())
	gate.Unlock()
	s.Close()
}

func TestResetSupervisorRegistrationFailureRetriesFailClosed(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{err: errors.New("redis unavailable")}
	s, err := NewRedisResetSupervisor(store, "group", "member", &gate, &resetting)
	require.NoError(t, err)
	defer s.Close()
	s.UpdateClient(&lifecycleResetClient{}, nil)
	require.True(t, s.Blocked())
	require.False(t, gate.TryLock(), "registration failure must leave polling fail-closed")
	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	require.Eventually(t, func() bool { return !s.Blocked() }, time.Second, 10*time.Millisecond, "registration and barrier observation must retry")
	require.True(t, gate.TryLock())
	gate.Unlock()
}

func TestResetSupervisorRedisOutageSelfGatesAndRecoversDurably(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{}
	s, err := NewRedisResetSupervisor(store, "group", "member", &gate, &resetting)
	require.NoError(t, err)
	defer s.Close()
	client := &lifecycleResetClient{}
	s.UpdateClient(client, nil)
	require.Eventually(t, func() bool { return !s.Blocked() }, time.Second, 5*time.Millisecond)

	store.mu.Lock()
	store.err = errors.New("redis unavailable")
	store.mu.Unlock()
	require.Eventually(t, func() bool { return s.Blocked() && client.leaves.Load() > 0 }, 4*time.Second, 10*time.Millisecond,
		"loss of durable membership before its TTL expires must stop Kafka participation")
	require.False(t, gate.TryLock(), "polling remains gated while Redis state is uncertain")
	pollExited := simulateResetPollLoopExit(s, &gate)

	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	<-pollExited
	require.Eventually(t, func() bool { return client.closes.Load() == 1 }, time.Second, time.Millisecond)
	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	require.Eventually(t, func() bool { return !s.Blocked() }, time.Second, 5*time.Millisecond,
		"polling resumes only after heartbeat and barrier reads are durable again")
	require.True(t, gate.TryLock())
	gate.Unlock()
}

func TestResetSupervisorRecoversExpiredBarrierAndReconstructs(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{
		barrier: ResetBarrier{PlanID: "plan", ConsumerGroup: "group", Owner: "owner", LeaseGeneration: 9, Participants: []string{"member"}},
		current: true,
	}
	s, err := NewRedisResetSupervisor(store, "group", "member", &gate, &resetting)
	require.NoError(t, err)
	defer s.Close()
	client := &lifecycleResetClient{}
	s.UpdateClient(client, nil)
	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.quiescedGeneration == 9
	}, time.Second, 5*time.Millisecond)
	require.True(t, s.Blocked())

	pollExited := simulateResetPollLoopExit(s, &gate)
	store.mu.Lock()
	store.leaseExpired = true
	store.mu.Unlock()
	require.Eventually(t, func() bool { return client.closes.Load() == 1 }, time.Second, 5*time.Millisecond)
	<-pollExited
	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	require.Eventually(t, func() bool { return !s.Blocked() }, time.Second, 5*time.Millisecond)
	store.mu.Lock()
	require.Equal(t, 1, store.recoveries)
	store.mu.Unlock()
	require.True(t, gate.TryLock())
	gate.Unlock()
}

func TestResetSupervisorBlackholedHeartbeatReconstructsBeforeRecovery(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{}
	s, err := NewRedisResetSupervisor(store, "group", "member", &gate, &resetting)
	require.NoError(t, err)
	client := &lifecycleResetClient{}
	s.UpdateClient(client, nil)
	require.Eventually(t, func() bool { return !s.Blocked() }, time.Second, time.Millisecond)

	blackhole := make(chan struct{})
	store.mu.Lock()
	store.heartbeatBlock = blackhole
	store.mu.Unlock()
	require.Eventually(t, func() bool { return s.Blocked() && client.leaves.Load() > 0 }, 4*time.Second, 10*time.Millisecond,
		"independent watchdog must gate before membership TTL despite a non-cooperative store")
	pollExited := simulateResetPollLoopExit(s, &gate)
	close(blackhole)
	store.mu.Lock()
	store.heartbeatBlock = nil
	store.mu.Unlock()
	<-pollExited
	require.Eventually(t, func() bool { return client.closes.Load() == 1 }, time.Second, time.Millisecond,
		"uncertain membership recovery must reconstruct the stale client")
	require.True(t, s.Blocked())
	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	require.Eventually(t, func() bool { return !s.Blocked() }, time.Second, time.Millisecond)
	require.NoError(t, s.CloseContext(context.Background()))
}

type failingLeaveResetClient struct {
	lifecycleResetClient
	mu  sync.Mutex
	err error
}

func (c *failingLeaveResetClient) LeaveGroupContext(context.Context) error {
	c.leaves.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func TestResetSupervisorQuiesceFailuresStayGatedAndRetry(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{}
	client := &failingLeaveResetClient{err: errors.New("leave failed")}
	s := &RedisResetSupervisor{store: store, group: "group", participant: "member", pollGate: &gate, resetting: &resetting, client: client, ctx: context.Background()}
	barrier := ResetBarrier{PlanID: "plan", Owner: "owner", LeaseGeneration: 11, Participants: []string{"member"}}
	s.quiesce(barrier)
	require.False(t, gate.TryLock(), "LeaveGroup failure must remain fail-closed")
	client.mu.Lock()
	client.err = nil
	client.mu.Unlock()
	store.mu.Lock()
	store.err = errors.New("ack failed")
	store.mu.Unlock()
	s.quiesceHeld(client, barrier)
	require.False(t, gate.TryLock(), "acknowledgment failure must remain fail-closed")
	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	s.quiesceHeld(client, barrier)
	s.mu.Lock()
	quiesced := s.quiescedGeneration
	s.mu.Unlock()
	require.Equal(t, uint64(11), quiesced)
	s.releaseGate("plan", 11, false)
}

func TestResetSupervisorQuiesceAndResumeControlOperations(t *testing.T) {
	store := &fakeResetSupervisorStore{
		barrier:  ResetBarrier{PlanID: "plan", Owner: "owner", LeaseGeneration: 4, Participants: []string{"member"}},
		complete: true,
	}
	s := &RedisResetSupervisor{store: store}
	lease := ResetExecutionLease{Generation: 4}
	published, err := s.Quiesce(context.Background(), lease, "group", "replay")
	require.NoError(t, err)
	require.True(t, published)
	require.NoError(t, s.Resume(context.Background(), lease, "group", "replay"))
	store.mu.Lock()
	require.Equal(t, 1, store.resumes)
	store.err = errors.New("redis unavailable")
	store.mu.Unlock()
	_, err = s.Quiesce(context.Background(), lease, "group", "replay")
	require.Error(t, err)
	require.Error(t, s.Resume(context.Background(), lease, "group", "replay"))
}

func TestResetSupervisorQuiesceParticipantLifecycle(t *testing.T) {
	var gate sync.RWMutex
	var resetting atomic.Bool
	store := &fakeResetSupervisorStore{}
	client := &lifecycleResetClient{}
	s := &RedisResetSupervisor{store: store, group: "group", participant: "member", pollGate: &gate, resetting: &resetting, client: client, ctx: context.Background()}
	barrier := ResetBarrier{PlanID: "plan", Owner: "owner", LeaseGeneration: 8, Participants: []string{"member"}}

	s.quiesce(barrier)
	require.EqualValues(t, 1, client.leaves.Load())
	require.True(t, resetting.Load())
	require.True(t, s.gateHeld)
	store.mu.Lock()
	require.Equal(t, 1, store.acknowledgments)
	store.mu.Unlock()

	// Repeated observation of the same barrier is idempotent.
	s.quiesce(barrier)
	require.EqualValues(t, 1, client.leaves.Load())
	pollExited := simulateResetPollLoopExit(s, &gate)
	s.resumeLocal("plan", 8)
	<-pollExited
	require.EqualValues(t, 1, client.closes.Load())
	require.False(t, gate.TryLock(), "reconstruction remains gated")
	replacement := &lifecycleResetClient{}
	s.UpdateClient(replacement, nil)
	s.initializeAttached(replacement, ResetBarrier{PlanID: "plan", Owner: "owner", LeaseGeneration: 8, Resume: true}, true)
	require.True(t, gate.TryLock())
	gate.Unlock()
}
