package kafka

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// RedisResetSupervisor lives at connector-component scope, not kgo.Client
// scope. It therefore continues heartbeating and enforcing a quiesce barrier
// while Bento reconstructs individual Kafka clients.
type RedisResetSupervisor struct {
	store       resetSupervisorStore
	group       string
	participant string
	pollGate    *sync.RWMutex
	resetting   *atomic.Bool

	mu                  sync.Mutex
	client              resetClient
	acks                *ExternalAckController
	gateHeld            bool
	quiescing           bool
	barrierGeneration   uint64
	barrierPlanID       string
	barrierOwner        string
	quiescedGeneration  uint64
	quiescedPlanID      string
	observedBarrier     ResetBarrier
	closing             bool
	closeDone           chan struct{}
	reconstructRequired bool
	shuttingDown        bool

	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	watchdogDone  chan struct{}
	updated       chan struct{}
	blocked       atomic.Bool
	interval      time.Duration
	ttl           time.Duration
	lastHeartbeat time.Time
}

// resetSupervisorStore keeps the participant lifecycle independently
// testable from Redis while RedisResetStateStore remains the production
// implementation.
type resetSupervisorStore interface {
	HeartbeatParticipant(context.Context, string, string, time.Duration, time.Time) error
	CurrentBarrier(context.Context, string) (ResetBarrier, bool, error)
	RecoverExpiredBarrier(context.Context, string, time.Time) (ResetBarrier, bool, error)
	AcknowledgeQuiesced(context.Context, ResetBarrier, string) error
	RequestQuiesce(context.Context, ResetExecutionLease, string, string, time.Time) (ResetBarrier, error)
	BarrierStatus(context.Context, ResetBarrier) (ResetBarrierStatus, error)
	PublishResume(context.Context, ResetExecutionLease, string, string, time.Time) error
}

func NewRedisResetSupervisor(store resetSupervisorStore, group, participant string, pollGate *sync.RWMutex, resetting *atomic.Bool) (*RedisResetSupervisor, error) {
	if store == nil || group == "" || participant == "" || pollGate == nil || resetting == nil {
		return nil, errors.New("complete distributed reset supervisor dependencies are required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Hold the polling writer gate until a client is attached, durable
	// membership is established, and the current barrier is observed.
	pollGate.Lock()
	resetting.Store(true)
	s := &RedisResetSupervisor{store: store, group: group, participant: participant, pollGate: pollGate, resetting: resetting, ctx: ctx, cancel: cancel, done: make(chan struct{}), watchdogDone: make(chan struct{}), updated: make(chan struct{}, 1), interval: 100 * time.Millisecond, ttl: 5 * time.Second, gateHeld: true}
	s.blocked.Store(true)
	go s.run()
	go s.watchdog()
	return s, nil
}

func (s *RedisResetSupervisor) UpdateClient(client resetClient, acks *ExternalAckController) {
	if client == nil {
		s.holdForAttach()
	}
	s.mu.Lock()
	s.client, s.acks = client, acks
	s.mu.Unlock()
	select {
	case s.updated <- struct{}{}:
	default:
	}
}

func (s *RedisResetSupervisor) Blocked() bool { return s != nil && s.blocked.Load() }

func (s *RedisResetSupervisor) Close() {
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = s.CloseContext(ctx)
}

func (s *RedisResetSupervisor) CloseContext(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	s.shuttingDown = true
	s.mu.Unlock()
	s.cancel()
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.watchdogDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	closeDone := s.closeDone
	s.mu.Unlock()
	if closeDone != nil {
		select {
		case <-closeDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *RedisResetSupervisor) run() {
	defer func() {
		s.releaseGate("", 0, false)
		close(s.done)
	}()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		s.mu.Lock()
		client, gated, planID, owner, generation := s.client, s.gateHeld, s.barrierPlanID, s.barrierOwner, s.barrierGeneration
		s.mu.Unlock()
		if client != nil {
			now := time.Now().UTC()
			probeTimeout := min(s.ttl/4, s.interval)
			probeCtx, cancel := context.WithTimeout(s.ctx, probeTimeout)
			heartbeatErr := s.store.HeartbeatParticipant(probeCtx, s.group, s.participant, s.ttl, now)
			barrier, ok, barrierErr := s.store.CurrentBarrier(probeCtx, s.group)
			if heartbeatErr == nil && barrierErr == nil && ok && !barrier.Resume {
				barrier, _, barrierErr = s.store.RecoverExpiredBarrier(probeCtx, s.group, now)
			}
			cancel()
			if heartbeatErr == nil && barrierErr == nil {
				s.mu.Lock()
				s.lastHeartbeat = now
				s.mu.Unlock()
				if resumeRequiresReconstruction(gated, planID, owner, generation, barrier, ok) {
					s.resumeLocal(barrier.PlanID, barrier.LeaseGeneration)
				} else if gated && generation == 0 {
					s.initializeAttached(client, barrier, ok)
				} else if gated && ok && !barrier.Resume && barrier.PlanID == planID && barrier.Owner == owner && barrier.LeaseGeneration == generation {
					s.quiesceHeld(client, barrier)
				} else if ok {
					// Matching resumes are handled only by the exact
					// plan/owner/generation predicate above. A resume for another
					// identity must never release this supervisor's gate.
					if !barrier.Resume && containsResetParticipant(barrier.Participants, s.participant) {
						s.blocked.Store(true)
						s.mu.Lock()
						s.observedBarrier = barrier
						s.mu.Unlock()
						s.quiesce(barrier)
					}
				}
			}
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.updated:
		case <-ticker.C:
		}
	}
}

func (s *RedisResetSupervisor) watchdog() {
	defer close(s.watchdogDone)
	ticker := time.NewTicker(max(s.interval, 10*time.Millisecond))
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			last, client, gated := s.lastHeartbeat, s.client, s.gateHeld
			s.mu.Unlock()
			if client != nil && !gated && !last.IsZero() && now.Sub(last) >= s.ttl/2 {
				s.gateForRedisLoss(client)
			}
		}
	}
}

func (s *RedisResetSupervisor) gateForRedisLoss(client resetClient) {
	s.mu.Lock()
	if s.gateHeld || s.quiescing || client == nil {
		s.mu.Unlock()
		return
	}
	s.quiescing = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.quiescing = false
		s.mu.Unlock()
	}()
	s.pollGate.Lock()
	if !s.resetting.CompareAndSwap(false, true) {
		s.pollGate.Unlock()
		return
	}
	s.mu.Lock()
	s.gateHeld = true
	s.barrierGeneration = 0
	s.reconstructRequired = true
	acks := s.acks
	s.mu.Unlock()
	s.blocked.Store(true)
	if acks != nil {
		acks.InvalidateForReset()
	}
	leaveCtx, cancel := context.WithTimeout(s.ctx, s.ttl/4)
	_ = client.LeaveGroupContext(leaveCtx)
	cancel()
}

func resumeRequiresReconstruction(gated bool, planID, owner string, generation uint64, barrier ResetBarrier, exists bool) bool {
	return gated && planID != "" && owner != "" && generation != 0 && exists && barrier.Resume && barrier.PlanID == planID && barrier.Owner == owner && barrier.LeaseGeneration == generation
}

func (s *RedisResetSupervisor) initializeAttached(client resetClient, barrier ResetBarrier, exists bool) {
	s.mu.Lock()
	reconstruct := s.reconstructRequired
	s.mu.Unlock()
	if reconstruct {
		s.releaseGate("", 0, true)
		return
	}
	if !exists || barrier.Resume {
		s.releaseGate("", 0, false)
		return
	}
	s.mu.Lock()
	if s.barrierPlanID == barrier.PlanID && s.barrierOwner == barrier.Owner && s.barrierGeneration == barrier.LeaseGeneration {
		s.mu.Unlock()
		return
	}
	s.observedBarrier = barrier
	acks := s.acks
	s.mu.Unlock()
	if acks != nil {
		acks.InvalidateForReset()
	}
	operationCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if err := client.LeaveGroupContext(operationCtx); err != nil {
		return
	}
	// Late joiners may not be in the barrier's original snapshot. They still
	// remain gated until resume, but only enrolled participants acknowledge it.
	if containsResetParticipant(barrier.Participants, s.participant) {
		if err := s.store.AcknowledgeQuiesced(operationCtx, barrier, s.participant); err != nil {
			return
		}
	}
	s.mu.Lock()
	s.barrierGeneration = barrier.LeaseGeneration
	s.barrierPlanID = barrier.PlanID
	s.barrierOwner = barrier.Owner
	s.quiescedGeneration = barrier.LeaseGeneration
	s.quiescedPlanID = barrier.PlanID
	s.mu.Unlock()
}

func (s *RedisResetSupervisor) holdForAttach() {
	if s == nil || s.pollGate == nil {
		return
	}
	if s.ctx != nil && s.ctx.Err() != nil {
		return
	}
	s.mu.Lock()
	if s.gateHeld {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.pollGate.Lock()
	if s.ctx != nil && s.ctx.Err() != nil {
		s.pollGate.Unlock()
		return
	}
	s.mu.Lock()
	if s.gateHeld {
		s.mu.Unlock()
		s.pollGate.Unlock()
		return
	}
	s.gateHeld = true
	s.barrierGeneration = 0
	s.barrierPlanID = ""
	s.barrierOwner = ""
	s.mu.Unlock()
	s.resetting.Store(true)
	s.blocked.Store(true)
}

func (s *RedisResetSupervisor) quiesce(barrier ResetBarrier) {
	s.mu.Lock()
	if s.gateHeld || s.quiescing || s.client == nil {
		s.mu.Unlock()
		return
	}
	s.quiescing = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.quiescing = false
		s.mu.Unlock()
	}()
	s.pollGate.Lock()
	if !s.resetting.CompareAndSwap(false, true) {
		s.pollGate.Unlock()
		return
	}
	s.mu.Lock()
	s.gateHeld = true
	s.barrierGeneration = barrier.LeaseGeneration
	s.barrierPlanID = barrier.PlanID
	s.barrierOwner = barrier.Owner
	s.observedBarrier = barrier
	client, acks := s.client, s.acks
	s.mu.Unlock()
	if acks != nil {
		acks.InvalidateForReset()
	}
	if client == nil {
		s.releaseGate(barrier.PlanID, barrier.LeaseGeneration, false)
		return
	}
	s.quiesceHeld(client, barrier)
}

func (s *RedisResetSupervisor) quiesceHeld(client resetClient, barrier ResetBarrier) {
	s.mu.Lock()
	if s.quiescedPlanID == barrier.PlanID && s.quiescedGeneration == barrier.LeaseGeneration {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	operationCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	if err := client.LeaveGroupContext(operationCtx); err != nil {
		return
	}
	if err := s.store.AcknowledgeQuiesced(operationCtx, barrier, s.participant); err != nil {
		return
	}
	s.mu.Lock()
	s.quiescedGeneration = barrier.LeaseGeneration
	s.quiescedPlanID = barrier.PlanID
	s.mu.Unlock()
}

func (s *RedisResetSupervisor) resumeLocal(planID string, generation uint64) {
	s.releaseGate(planID, generation, true)
}

func (s *RedisResetSupervisor) releaseGate(planID string, generation uint64, reconstruct bool) {
	s.mu.Lock()
	if !s.gateHeld || (generation != 0 && (s.barrierGeneration != generation || s.barrierPlanID != planID)) {
		s.mu.Unlock()
		return
	}
	client := s.client
	if reconstruct {
		// Close the Kafka client while polling is gated, then release the writer
		// so the existing poll loop can enter PollFetches, observe the closed
		// client, and run its deferred UpdateClient(nil). That defer reacquires the
		// attach gate before publishing batchChan=nil, so Bento cannot construct a
		// replacement with an ungated fetch window.
		if s.closing {
			s.mu.Unlock()
			return
		}
		s.barrierGeneration = 0
		s.barrierPlanID = ""
		s.barrierOwner = ""
		s.quiescedGeneration = 0
		s.quiescedPlanID = ""
		s.closing = true
		s.closeDone = make(chan struct{})
		done := s.closeDone
		s.mu.Unlock()
		go s.finishReconstruction(client, done)
		return
	}
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.gateHeld = false
	s.barrierGeneration = 0
	s.barrierPlanID = ""
	s.barrierOwner = ""
	s.quiescedGeneration = 0
	s.quiescedPlanID = ""
	s.mu.Unlock()
	s.resetting.Store(false)
	s.blocked.Store(false)
	s.pollGate.Unlock()
}

func (s *RedisResetSupervisor) finishReconstruction(client resetClient, done chan struct{}) {
	if client != nil {
		client.Close()
	}
	s.mu.Lock()
	terminal := s.shuttingDown
	replacementAttached := !terminal && s.client != nil && s.client != client
	if terminal || s.client == client {
		s.client, s.acks = nil, nil
	}
	s.closing = false
	s.reconstructRequired = false
	if !replacementAttached {
		s.gateHeld = false
	}
	s.mu.Unlock()
	// Close has fully returned before the physical gate is opened. The old
	// poll loop can now observe the closed client and reacquire the attach gate
	// in UpdateClient(nil) before Bento exposes a replacement opportunity.
	if !replacementAttached {
		if terminal {
			s.resetting.Store(false)
			s.blocked.Store(false)
		}
		s.pollGate.Unlock()
	} else {
		select {
		case s.updated <- struct{}{}:
		default:
		}
	}
	close(done)
}

func (s *RedisResetSupervisor) Quiesce(ctx context.Context, lease ResetExecutionLease, group, replayID string) (bool, error) {
	barrier, err := s.store.RequestQuiesce(ctx, lease, group, replayID, time.Now().UTC())
	if err != nil {
		return false, err
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, statusErr := s.store.BarrierStatus(ctx, barrier)
		if statusErr != nil {
			return true, statusErr
		}
		if status.Complete {
			return true, nil
		}
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *RedisResetSupervisor) Resume(ctx context.Context, lease ResetExecutionLease, group, replayID string) error {
	if err := s.store.PublishResume(ctx, lease, group, replayID, time.Now().UTC()); err != nil {
		return err
	}
	return nil
}
