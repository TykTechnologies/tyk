package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
)

// ResetBarrier is the durable group-wide command observed by every connector
// participant. LeaseGeneration fences acknowledgements and resume publication.
type ResetBarrier struct {
	Version         int       `json:"version"`
	PlanID          string    `json:"plan_id"`
	ConsumerGroup   string    `json:"consumer_group"`
	Owner           string    `json:"owner"`
	LeaseGeneration uint64    `json:"lease_generation"`
	ReplayID        string    `json:"replay_id"`
	Participants    []string  `json:"participants"`
	RequestedAt     time.Time `json:"requested_at"`
	Resume          bool      `json:"resume"`
}

func sameResetBarrierIdentity(a, b ResetBarrier) bool {
	return a.Version == 2 && b.Version == 2 && a.PlanID == b.PlanID && a.ConsumerGroup == b.ConsumerGroup &&
		a.Owner == b.Owner && a.LeaseGeneration == b.LeaseGeneration && a.ReplayID == b.ReplayID
}

func resetBarrierAckIdentity(barrier ResetBarrier) string {
	digest := sha256.Sum256([]byte(fmt.Sprintf("v2\x00%s\x00%s\x00%s\x00%d\x00%s", barrier.ConsumerGroup, barrier.PlanID, barrier.Owner, barrier.LeaseGeneration, barrier.ReplayID)))
	return "v2:" + fmt.Sprintf("%x", digest[:])
}

type ResetBarrierStatus struct {
	Barrier      ResetBarrier
	Acknowledged []string
	Complete     bool
}

func (s *RedisResetStateStore) coordinationKeys(group string) (members, barrier, acknowledgements string) {
	k := s.keys("group\x00" + group)
	return k.plan + ":members", k.plan + ":barrier", k.plan + ":acks"
}

func resetParticipantLeaseKey(members, participant string) string {
	return fmt.Sprintf("%s:lease:%x", members, sha256.Sum256([]byte(participant)))
}

// HeartbeatParticipant records live connector membership without creating a
// Redis connection. The hash is only a membership index; the per-participant
// native-TTL key is the authoritative liveness signal. Both keys retain the
// same Redis cluster hash tag.
func (s *RedisResetStateStore) HeartbeatParticipant(ctx context.Context, group, participant string, ttl time.Duration, now time.Time) error {
	if group == "" || participant == "" || ttl <= 0 {
		return errors.New("group, participant, and positive TTL are required")
	}
	members, barrierKey, acknowledgements := s.coordinationKeys(group)
	leaseKey := resetParticipantLeaseKey(members, participant)
	return s.watch(ctx, func(tx *redis.Tx) error {
		var barrier ResetBarrier
		barrierEncoded, barrierErr := tx.Get(ctx, barrierKey).Bytes()
		if barrierErr != nil && barrierErr != redis.Nil {
			return barrierErr
		}
		if barrierErr == nil {
			if err := json.Unmarshal(barrierEncoded, &barrier); err != nil {
				return err
			}
			if barrier.Version != 2 || barrier.ConsumerGroup != group || barrier.PlanID == "" || barrier.Owner == "" || barrier.LeaseGeneration == 0 || barrier.ReplayID == "" {
				return ErrResetFenced
			}
		}
		activeBarrier := barrierErr == nil && !barrier.Resume
		newlyEnrolled := activeBarrier && !containsResetParticipant(barrier.Participants, participant)
		if newlyEnrolled {
			barrier.Participants = append(barrier.Participants, participant)
			sort.Strings(barrier.Participants)
			barrierEncoded, _ = json.Marshal(barrier)
		}
		_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.HSet(ctx, members, participant, "1")
			pipe.Set(ctx, leaseKey, "1", ttl)
			if newlyEnrolled {
				pipe.Set(ctx, barrierKey, barrierEncoded, 0)
				// A participant rejoining this generation must quiesce again;
				// never inherit an acknowledgement from an earlier incarnation.
				pipe.HDel(ctx, acknowledgements, participant)
			}
			return nil
		})
		return err
	}, leaseKey, barrierKey)
}

func (s *RedisResetStateStore) LiveParticipants(ctx context.Context, group string, now time.Time) ([]string, error) {
	members, _, _ := s.coordinationKeys(group)
	participants, err := s.client.HKeys(ctx, members).Result()
	if err != nil {
		return nil, err
	}
	commands := make([]*redis.IntCmd, len(participants))
	_, err = s.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		for i, participant := range participants {
			commands[i] = pipe.Exists(ctx, resetParticipantLeaseKey(members, participant))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	live := make([]string, 0, len(participants))
	var expired []string
	for i, participant := range participants {
		if commands[i].Val() == 0 {
			expired = append(expired, participant)
			continue
		}
		live = append(live, participant)
	}
	for _, participant := range expired {
		revived, err := s.cleanupExpiredParticipant(ctx, members, participant)
		if err != nil {
			return nil, err
		}
		if revived {
			live = append(live, participant)
		}
	}
	sort.Strings(live)
	return live, nil
}

// cleanupExpiredParticipant removes a stale index entry only while its
// native-TTL lease key remains absent. A heartbeat racing after the preceding
// EXISTS scan changes the watched lease key and aborts/retries this deletion.
func (s *RedisResetStateStore) cleanupExpiredParticipant(ctx context.Context, members, participant string) (bool, error) {
	leaseKey := resetParticipantLeaseKey(members, participant)
	revived := false
	err := s.watch(ctx, func(tx *redis.Tx) error {
		exists, err := tx.Exists(ctx, leaseKey).Result()
		if err != nil {
			return err
		}
		if exists != 0 {
			revived = true
			return nil
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.HDel(ctx, members, participant)
			return nil
		})
		return err
	}, leaseKey)
	return revived, err
}

func (s *RedisResetStateStore) RequestQuiesce(ctx context.Context, lease ResetExecutionLease, group, replayID string, now time.Time) (ResetBarrier, error) {
	var barrier ResetBarrier
	if lease.ConsumerGroup != group {
		return barrier, ErrResetFenced
	}
	k := s.groupLeaseKeys(group)
	members, barrierKey, acknowledgements := s.coordinationKeys(group)
	err := s.watch(ctx, func(tx *redis.Tx) error {
		if err := verifyResetLease(ctx, tx, k.lease, lease); err != nil {
			return err
		}
		// Read membership only after WATCH is active. A heartbeat that lands
		// between this snapshot and EXEC modifies members and retries the whole
		// operation; one arriving after EXEC observes and joins the barrier.
		participants, membersErr := tx.HKeys(ctx, members).Result()
		if membersErr != nil {
			return membersErr
		}
		sort.Strings(participants)
		barrier = ResetBarrier{Version: 2, PlanID: lease.PlanID, ConsumerGroup: group, Owner: lease.Owner, LeaseGeneration: lease.Generation, ReplayID: replayID, Participants: participants, RequestedAt: now.UTC()}
		encoded, _ := json.Marshal(barrier)
		existing, getErr := tx.Get(ctx, barrierKey).Bytes()
		if getErr == nil {
			var current ResetBarrier
			if json.Unmarshal(existing, &current) != nil || current.Version != 2 {
				return ErrResetFenced
			}
			if current.LeaseGeneration > lease.Generation ||
				(current.LeaseGeneration == lease.Generation && !sameResetBarrierIdentity(current, barrier)) {
				return ErrResetFenced
			}
		} else if getErr != redis.Nil {
			return getErr
		}
		_, pipeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, barrierKey, encoded, 0)
			pipe.Del(ctx, acknowledgements)
			return nil
		})
		return pipeErr
	}, k.lease, members, barrierKey, acknowledgements)
	if err != nil {
		// WATCH/EXEC can return a transport error after Redis committed the
		// transaction. Reconcile with an independent bounded context. If this
		// generation is visible, publish its abort/resume before reporting the
		// failure; if Redis remains unavailable, mark the result ambiguous so the
		// controller retains the lease until native expiry rather than releasing
		// ownership underneath a possibly live barrier.
		reconcileCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		current, exists, reconcileErr := s.CurrentBarrier(reconcileCtx, group)
		if reconcileErr == nil && exists && sameResetBarrierIdentity(current, barrier) {
			resumeErr := s.PublishResume(reconcileCtx, lease, group, "abort-"+replayID, time.Now().UTC())
			if resumeErr == nil {
				return current, err
			}
			return current, fmt.Errorf("%w: publish abort resume: %v (original error: %v)", ErrResetBarrierAmbiguous, resumeErr, err)
		}
		if reconcileErr != nil {
			return barrier, fmt.Errorf("%w: reconcile quiesce: %v (original error: %v)", ErrResetBarrierAmbiguous, reconcileErr, err)
		}
	}
	return barrier, err
}

func (s *RedisResetStateStore) CurrentBarrier(ctx context.Context, group string) (ResetBarrier, bool, error) {
	_, barrierKey, _ := s.coordinationKeys(group)
	var barrier ResetBarrier
	encoded, err := s.client.Get(ctx, barrierKey).Bytes()
	if err == redis.Nil {
		return barrier, false, nil
	}
	if err != nil {
		return barrier, false, err
	}
	if err := json.Unmarshal(encoded, &barrier); err != nil {
		return barrier, false, err
	}
	if barrier.Version != 2 || barrier.PlanID == "" || barrier.ConsumerGroup != group || barrier.Owner == "" || barrier.LeaseGeneration == 0 || barrier.ReplayID == "" {
		return ResetBarrier{}, false, ErrResetFenced
	}
	return barrier, true, nil
}

// RecoverExpiredBarrier publishes a fenced abort/resume only when the exact
// non-resume barrier observed at the start of the operation still exists and
// its plan's native Redis execution lease is absent. Watching both keys makes
// a concurrent lease acquisition or barrier replacement abort the EXEC.
func (s *RedisResetStateStore) RecoverExpiredBarrier(ctx context.Context, group string, now time.Time) (ResetBarrier, bool, error) {
	observed, exists, err := s.CurrentBarrier(ctx, group)
	if err != nil || !exists || observed.Resume {
		return observed, false, err
	}
	_, barrierKey, _ := s.coordinationKeys(group)
	leaseKey := s.groupLeaseKeys(group).lease
	auditKey := s.auditKey()
	identity, observer := s.auditConfiguration()
	if identity.apiID == "" || identity.streamID == "" || identity.componentID == "" {
		return observed, false, errors.New("Kafka reset recovery audit identity is not configured")
	}
	recovered := false
	var recoveryAudit ResetAuditEvent
	err = s.watch(ctx, func(tx *redis.Tx) error {
		encoded, getErr := tx.Get(ctx, barrierKey).Bytes()
		if getErr != nil {
			return ErrResetFenced
		}
		var current ResetBarrier
		if json.Unmarshal(encoded, &current) != nil || !sameResetBarrierIdentity(current, observed) || current.Resume {
			return ErrResetFenced
		}
		live, liveErr := tx.Exists(ctx, leaseKey).Result()
		if liveErr != nil {
			return liveErr
		}
		if live != 0 {
			observed = current
			return nil
		}
		serverNow, timeErr := tx.Time(ctx).Result()
		if timeErr != nil {
			return timeErr
		}
		current.Resume = true
		current.ReplayID = fmt.Sprintf("abort-expired-%d-%d", current.LeaseGeneration, serverNow.UTC().UnixNano())
		encoded, _ = json.Marshal(current)
		recoveryAudit = ResetAuditEvent{Time: serverNow.UTC(), APIID: identity.apiID, StreamID: identity.streamID,
			ComponentID: identity.componentID, ConsumerGroupHash: hashStatusIdentity(current.ConsumerGroup),
			ActorHash: hashStatusIdentity("gateway-reset-supervisor"), CorrelationID: current.ReplayID,
			PlanID: current.PlanID, ExecutionID: current.ReplayID, Outcome: "expired_barrier_recovered",
			Reason: "execution lease expired while reset barrier was active"}
		if validateErr := recoveryAudit.Validate(); validateErr != nil {
			return validateErr
		}
		audit, marshalErr := json.Marshal(recoveryAudit)
		if marshalErr != nil {
			return marshalErr
		}
		count, countErr := tx.LLen(ctx, auditKey).Result()
		if countErr != nil {
			return countErr
		}
		if count >= maxResetAuditEntries {
			return errors.New("Kafka reset audit backlog is full")
		}
		if _, setErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, barrierKey, encoded, 0)
			pipe.RPush(ctx, auditKey, audit)
			return nil
		}); setErr != nil {
			return setErr
		}
		observed, recovered = current, true
		return nil
	}, barrierKey, leaseKey, auditKey)
	if err == nil && recovered && observer != nil {
		observer(recoveryAudit)
	}
	return observed, recovered, err
}

func (s *RedisResetStateStore) AcknowledgeQuiesced(ctx context.Context, barrier ResetBarrier, participant string) error {
	_, barrierKey, acknowledgements := s.coordinationKeys(barrier.ConsumerGroup)
	return s.watch(ctx, func(tx *redis.Tx) error {
		encoded, err := tx.Get(ctx, barrierKey).Bytes()
		if err != nil {
			return ErrResetFenced
		}
		var current ResetBarrier
		if json.Unmarshal(encoded, &current) != nil || !sameResetBarrierIdentity(current, barrier) || current.Resume {
			return ErrResetFenced
		}
		if !containsResetParticipant(current.Participants, participant) {
			return ErrResetFenced
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.HSet(ctx, acknowledgements, participant, resetBarrierAckIdentity(barrier))
			return nil
		})
		return err
	}, barrierKey, acknowledgements)
}

func (s *RedisResetStateStore) BarrierStatus(ctx context.Context, barrier ResetBarrier) (ResetBarrierStatus, error) {
	current, ok, err := s.CurrentBarrier(ctx, barrier.ConsumerGroup)
	if err != nil || !ok || !sameResetBarrierIdentity(current, barrier) {
		if err == nil {
			err = ErrResetFenced
		}
		return ResetBarrierStatus{}, err
	}
	_, _, acknowledgements := s.coordinationKeys(barrier.ConsumerGroup)
	values, err := s.client.HGetAll(ctx, acknowledgements).Result()
	if err != nil {
		return ResetBarrierStatus{}, err
	}
	status := ResetBarrierStatus{Barrier: current}
	live, err := s.LiveParticipants(ctx, current.ConsumerGroup, time.Now().UTC())
	if err != nil {
		return ResetBarrierStatus{}, err
	}
	liveSet := make(map[string]struct{}, len(live))
	for _, participant := range live {
		liveSet[participant] = struct{}{}
	}
	complete := true
	for _, participant := range current.Participants {
		if values[participant] == resetBarrierAckIdentity(current) {
			status.Acknowledged = append(status.Acknowledged, participant)
		} else if _, stillLive := liveSet[participant]; stillLive {
			complete = false
		}
	}
	sort.Strings(status.Acknowledged)
	status.Complete = complete
	if status.Complete {
		// A late heartbeat atomically extends the barrier participant set. Do
		// not return a completion decision derived from the older snapshot.
		latest, exists, latestErr := s.CurrentBarrier(ctx, barrier.ConsumerGroup)
		if latestErr != nil {
			return ResetBarrierStatus{}, latestErr
		}
		if !exists || !sameResetBarrierIdentity(latest, current) {
			return ResetBarrierStatus{}, ErrResetFenced
		}
		if latest.Resume || !slices.Equal(latest.Participants, current.Participants) {
			status.Barrier = latest
			status.Complete = false
		}
	}
	return status, nil
}

func (s *RedisResetStateStore) PublishResume(ctx context.Context, lease ResetExecutionLease, group, replayID string, now time.Time) error {
	if lease.ConsumerGroup != group {
		return ErrResetFenced
	}
	k := s.groupLeaseKeys(group)
	_, barrierKey, _ := s.coordinationKeys(group)
	return s.watch(ctx, func(tx *redis.Tx) error {
		if err := verifyResetLease(ctx, tx, k.lease, lease); err != nil {
			return err
		}
		encoded, err := tx.Get(ctx, barrierKey).Bytes()
		if err != nil {
			return ErrResetFenced
		}
		var barrier ResetBarrier
		if json.Unmarshal(encoded, &barrier) != nil || barrier.Version != 2 || barrier.ConsumerGroup != group || barrier.PlanID != lease.PlanID || barrier.Owner != lease.Owner || barrier.LeaseGeneration != lease.Generation {
			return ErrResetFenced
		}
		barrier.Resume, barrier.ReplayID = true, replayID
		encoded, _ = json.Marshal(barrier)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Set(ctx, barrierKey, encoded, 0); return nil })
		return err
	}, k.lease, barrierKey)
}

func containsResetParticipant(participants []string, target string) bool {
	for _, participant := range participants {
		if participant == target {
			return true
		}
	}
	return false
}
