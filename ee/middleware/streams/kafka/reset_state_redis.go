package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrResetLeaseHeld = errors.New("reset execution lease is held")
	ErrResetFenced    = errors.New("reset execution leader is fenced")
	// ErrResetBarrierAmbiguous means Redis did not confirm whether a quiesce
	// transaction committed. Callers must not explicitly release the execution
	// lease unless a same-generation resume has subsequently been confirmed.
	ErrResetBarrierAmbiguous = errors.New("reset barrier publication is ambiguous")
)

type ResetExecutionLease struct {
	Version       int       `json:"version"`
	ConsumerGroup string    `json:"consumer_group"`
	PlanID        string    `json:"plan_id"`
	Owner         string    `json:"owner"`
	Generation    uint64    `json:"generation"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// FencedResetStateStore extends durable plan/execution persistence with the
// lease and fencing operations required by a distributed reset leader.
type FencedResetStateStore interface {
	ResetStateStore
	AcquireExecutionLease(context.Context, string, string, string, time.Duration, time.Time) (ResetExecutionLease, error)
	RenewExecutionLease(context.Context, ResetExecutionLease, time.Duration, time.Time) (ResetExecutionLease, error)
	PutExecutionFenced(context.Context, ResetExecutionLease, StoredResetExecution, time.Time) error
	ReleaseExecutionLease(context.Context, ResetExecutionLease) error
}

type RedisResetStateStore struct {
	client        redis.UniversalClient
	prefix        string
	auditMu       sync.RWMutex
	auditObserver func(ResetAuditEvent)
	auditIdentity resetAuditIdentity
}

type resetAuditIdentity struct{ apiID, streamID, componentID string }

const maxResetAuditEntries int64 = 10000

// SetAuditIdentity supplies the non-secret resource identity required by the
// canonical reset audit schema. It must be configured before recovery runs.
func (s *RedisResetStateStore) SetAuditIdentity(apiID, streamID, componentID string) {
	s.auditMu.Lock()
	s.auditIdentity = resetAuditIdentity{apiID: apiID, streamID: streamID, componentID: componentID}
	s.auditMu.Unlock()
}

func (s *RedisResetStateStore) SetAuditObserver(observer func(ResetAuditEvent)) {
	s.auditMu.Lock()
	s.auditObserver = observer
	s.auditMu.Unlock()
}

func (s *RedisResetStateStore) auditConfiguration() (resetAuditIdentity, func(ResetAuditEvent)) {
	s.auditMu.RLock()
	defer s.auditMu.RUnlock()
	return s.auditIdentity, s.auditObserver
}

// auditKey occupies the same Redis Cluster slot as every other v2 reset key,
// allowing recovery state and its audit journal entry to commit atomically.
func (s *RedisResetStateStore) auditKey() string { return s.keys("audit").plan + ":events" }

func (s *RedisResetStateStore) watch(ctx context.Context, fn func(*redis.Tx) error, keys ...string) error {
	for attempt := 0; attempt < 16; attempt++ {
		err := s.client.Watch(ctx, fn, keys...)
		if err != redis.TxFailedErr {
			return err
		}
	}
	return redis.TxFailedErr
}

func NewRedisResetStateStore(client redis.UniversalClient, prefix string) (*RedisResetStateStore, error) {
	if client == nil {
		return nil, errors.New("Redis client is required")
	}
	if prefix == "" {
		prefix = "tyk:kafka:reset"
	}
	return &RedisResetStateStore{client: client, prefix: prefix}, nil
}

// WriteResetAudit durably appends a redacted event to the Gateway-managed
// Redis store. It fails closed at the hard bound rather than trimming an
// unaudited event; operators must archive/clear records deliberately.
func (s *RedisResetStateStore) WriteResetAudit(ctx context.Context, event ResetAuditEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	key := s.auditKey()
	err = s.watch(ctx, func(tx *redis.Tx) error {
		count, err := tx.LLen(ctx, key).Result()
		if err != nil {
			return err
		}
		if count >= maxResetAuditEntries {
			return errors.New("Kafka reset audit backlog is full")
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.RPush(ctx, key, encoded); return nil })
		return err
	}, key)
	_, observer := s.auditConfiguration()
	if err == nil && observer != nil {
		observer(event)
	}
	return err
}

type resetRedisKeys struct{ plan, execution, lease, generation string }

func (s *RedisResetStateStore) keys(planID string) resetRedisKeys {
	// All keys participating in reset fencing transactions must occupy one
	// Redis Cluster slot. The plan digest remains outside the hash tag, so plan
	// state is still isolated while transactions can also include group barrier
	// keys. A store prefix is component-scoped by its Manager lifecycle.
	slot := sha256.Sum256([]byte(s.prefix))
	plan := sha256.Sum256([]byte(planID))
	base := s.prefix + ":v2:{" + hex.EncodeToString(slot[:12]) + "}:" + hex.EncodeToString(plan[:12])
	return resetRedisKeys{base + ":plan", base + ":execution", base + ":lease", base + ":generation"}
}

func (s *RedisResetStateStore) groupLeaseKeys(group string) resetRedisKeys {
	return s.keys("group\x00" + group)
}

func (s *RedisResetStateStore) PutPlan(ctx context.Context, plan StoredResetPlan) error {
	if plan.Plan.ID == "" {
		return errors.New("reset plan ID is required")
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	k := s.keys(plan.Plan.ID)
	return s.watch(ctx, func(tx *redis.Tx) error {
		existing, err := tx.Get(ctx, k.plan).Bytes()
		if err == nil {
			if string(existing) == string(encoded) {
				return nil
			}
			return errors.New("reset plan ID already contains different data")
		}
		if err != redis.Nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, k.plan, encoded, 0)
			return nil
		})
		return err
	}, k.plan)
}

func (s *RedisResetStateStore) GetPlan(ctx context.Context, id string) (StoredResetPlan, bool, error) {
	var plan StoredResetPlan
	encoded, err := s.client.Get(ctx, s.keys(id).plan).Bytes()
	if err == redis.Nil {
		return plan, false, nil
	}
	if err != nil {
		return plan, false, err
	}
	if err := json.Unmarshal(encoded, &plan); err != nil {
		return plan, false, err
	}
	return plan, true, nil
}

func (s *RedisResetStateStore) PutExecution(ctx context.Context, execution StoredResetExecution) error {
	if execution.PlanID == "" {
		return errors.New("reset execution plan ID is required")
	}
	encoded, err := json.Marshal(execution)
	if err != nil {
		return err
	}
	k := s.keys(execution.PlanID)
	return s.watch(ctx, func(tx *redis.Tx) error {
		if exists, err := tx.Exists(ctx, k.lease).Result(); err != nil {
			return err
		} else if exists != 0 {
			return ErrResetFenced
		}
		_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Set(ctx, k.execution, encoded, 0); return nil })
		return err
	}, k.lease, k.execution)
}

func (s *RedisResetStateStore) GetExecution(ctx context.Context, planID string) (StoredResetExecution, bool, error) {
	var execution StoredResetExecution
	encoded, err := s.client.Get(ctx, s.keys(planID).execution).Bytes()
	if err == redis.Nil {
		return execution, false, nil
	}
	if err != nil {
		return execution, false, err
	}
	if err := json.Unmarshal(encoded, &execution); err != nil {
		return execution, false, err
	}
	return execution, true, nil
}

func (s *RedisResetStateStore) AcquireExecutionLease(ctx context.Context, group, planID, owner string, ttl time.Duration, now time.Time) (ResetExecutionLease, error) {
	if group == "" || planID == "" || owner == "" || ttl <= 0 {
		return ResetExecutionLease{}, errors.New("group, plan, owner, and positive lease TTL are required")
	}
	k := s.groupLeaseKeys(group)
	var acquired ResetExecutionLease
	err := s.watch(ctx, func(tx *redis.Tx) error {
		var current ResetExecutionLease
		encoded, err := tx.Get(ctx, k.lease).Bytes()
		if err == nil {
			if err := json.Unmarshal(encoded, &current); err != nil {
				return err
			}
			// Redis expiry is authoritative. If GET returned the lease then its
			// native TTL has not elapsed, regardless of either gateway's clock.
			if current.Version == 2 && current.ConsumerGroup == group && current.PlanID == planID && current.Owner == owner {
				serverNow, timeErr := tx.Time(ctx).Result()
				if timeErr != nil {
					return timeErr
				}
				current.ExpiresAt = serverNow.Add(ttl).UTC()
				value, _ := json.Marshal(current)
				if _, setErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
					pipe.Set(ctx, k.lease, value, ttl)
					return nil
				}); setErr != nil {
					return setErr
				}
				acquired = current
				return nil
			}
			return ErrResetLeaseHeld
		} else if err != redis.Nil {
			return err
		}
		generation, err := tx.Get(ctx, k.generation).Uint64()
		if err != nil && err != redis.Nil {
			return err
		}
		serverNow, err := tx.Time(ctx).Result()
		if err != nil {
			return err
		}
		acquired = ResetExecutionLease{Version: 2, ConsumerGroup: group, PlanID: planID, Owner: owner, Generation: generation + 1, ExpiresAt: serverNow.Add(ttl).UTC()}
		value, _ := json.Marshal(acquired)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, k.generation, strconv.FormatUint(acquired.Generation, 10), 0)
			pipe.Set(ctx, k.lease, value, ttl)
			return nil
		})
		return err
	}, k.lease, k.generation)
	return acquired, err
}

func (s *RedisResetStateStore) RenewExecutionLease(ctx context.Context, lease ResetExecutionLease, ttl time.Duration, now time.Time) (ResetExecutionLease, error) {
	if ttl <= 0 {
		return ResetExecutionLease{}, errors.New("positive lease TTL is required")
	}
	k := s.groupLeaseKeys(lease.ConsumerGroup)
	renewed := lease
	err := s.watch(ctx, func(tx *redis.Tx) error {
		if err := verifyResetLease(ctx, tx, k.lease, lease); err != nil {
			return err
		}
		serverNow, err := tx.Time(ctx).Result()
		if err != nil {
			return err
		}
		renewed.ExpiresAt = serverNow.Add(ttl).UTC()
		value, _ := json.Marshal(renewed)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Set(ctx, k.lease, value, ttl); return nil })
		return err
	}, k.lease)
	return renewed, err
}

func (s *RedisResetStateStore) PutExecutionFenced(ctx context.Context, lease ResetExecutionLease, execution StoredResetExecution, now time.Time) error {
	if execution.PlanID != lease.PlanID {
		return ErrResetFenced
	}
	encoded, err := json.Marshal(execution)
	if err != nil {
		return err
	}
	leaseKeys := s.groupLeaseKeys(lease.ConsumerGroup)
	executionKey := s.keys(execution.PlanID).execution
	return s.watch(ctx, func(tx *redis.Tx) error {
		if err := verifyResetLease(ctx, tx, leaseKeys.lease, lease); err != nil {
			return err
		}
		_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Set(ctx, executionKey, encoded, 0); return nil })
		return err
	}, leaseKeys.lease, executionKey)
}

func (s *RedisResetStateStore) ReleaseExecutionLease(ctx context.Context, lease ResetExecutionLease) error {
	k := s.groupLeaseKeys(lease.ConsumerGroup)
	return s.watch(ctx, func(tx *redis.Tx) error {
		if err := verifyResetLease(ctx, tx, k.lease, lease); err != nil {
			return err
		}
		_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Del(ctx, k.lease); return nil })
		return err
	}, k.lease)
}

func verifyResetLease(ctx context.Context, tx *redis.Tx, key string, expected ResetExecutionLease) error {
	encoded, err := tx.Get(ctx, key).Bytes()
	if err != nil {
		return ErrResetFenced
	}
	var current ResetExecutionLease
	if json.Unmarshal(encoded, &current) != nil || current.Version != 2 || expected.Version != 2 || current.ConsumerGroup != expected.ConsumerGroup || current.PlanID != expected.PlanID || current.Owner != expected.Owner || current.Generation != expected.Generation {
		return ErrResetFenced
	}
	return nil
}
