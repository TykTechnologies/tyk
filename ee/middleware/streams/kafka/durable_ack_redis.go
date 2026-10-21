package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisDurableAckOptions struct {
	Prefix           string
	MaxEntries       int   // per route
	MaxBytes         int64 // per route
	MaxGlobalEntries int
	MaxGlobalBytes   int64
	OwnerTTL         time.Duration
	ClaimScanLimit   int64
}

const (
	DefaultRedisAckMaxRouteEntries  = 100_000
	DefaultRedisAckMaxRouteBytes    = int64(256 << 20)
	DefaultRedisAckMaxGlobalEntries = 100_000
	DefaultRedisAckMaxGlobalBytes   = int64(256 << 20)
)

type RedisDurableAckTransport struct {
	client  redis.UniversalClient
	options RedisDurableAckOptions
}

var _ DurableAckTransport = (*RedisDurableAckTransport)(nil)

func NewRedisDurableAckTransport(client redis.UniversalClient, options RedisDurableAckOptions) (*RedisDurableAckTransport, error) {
	if client == nil {
		return nil, errors.New("Redis client is required")
	}
	if options.Prefix == "" {
		options.Prefix = "tyk:kafka:ack"
	}
	if options.MaxEntries <= 0 {
		options.MaxEntries = DefaultRedisAckMaxRouteEntries
	}
	if options.MaxBytes <= 0 {
		options.MaxBytes = DefaultRedisAckMaxRouteBytes
	}
	if options.MaxGlobalEntries <= 0 {
		options.MaxGlobalEntries = DefaultRedisAckMaxGlobalEntries
	}
	if options.MaxGlobalBytes <= 0 {
		options.MaxGlobalBytes = DefaultRedisAckMaxGlobalBytes
	}
	return &RedisDurableAckTransport{client: client, options: options}, nil
}

type redisAckEntry struct {
	Command         AckCommand `json:"command"`
	Consumer        string     `json:"consumer,omitempty"`
	Attempts        int        `json:"attempts"`
	LeaseUntil      int64      `json:"lease_until,omitempty"`
	NextAttempt     int64      `json:"next_attempt,omitempty"`
	ClaimGeneration int32      `json:"claim_generation,omitempty"`
	Pending         bool       `json:"pending"`
}

type redisAckKeys struct {
	assignment, generation, heartbeat, entries, order, bytes, dead string
	globalEntries, globalBytes                                     string
}

func (r *RedisDurableAckTransport) keys(route AckRoute) redisAckKeys {
	component := route.Key.APIID + "\x00" + route.Key.StreamID + "\x00" + route.Key.ComponentID
	componentSum := sha256.Sum256([]byte(component))
	routeSum := sha256.Sum256([]byte(route.Topic + "\x00" + strconv.FormatInt(int64(route.Partition), 10)))
	slotBase := r.options.Prefix + ":{" + hex.EncodeToString(componentSum[:12]) + "}"
	base := slotBase + ":route:" + hex.EncodeToString(routeSum[:12])
	return redisAckKeys{
		assignment: base + ":assignment", generation: base + ":generation", heartbeat: base + ":heartbeat",
		entries: base + ":entries", order: base + ":order", bytes: base + ":bytes", dead: base + ":dead",
		globalEntries: slotBase + ":global:entries", globalBytes: slotBase + ":global:bytes",
	}
}

func (r *RedisDurableAckTransport) watch(ctx context.Context, fn func(*redis.Tx) error, keys ...string) error {
	for attempt := 0; attempt < 64; attempt++ {
		err := r.client.Watch(ctx, fn, keys...)
		if err != redis.TxFailedErr {
			return err
		}
	}
	return redis.TxFailedErr
}

func (r *RedisDurableAckTransport) AppendBatch(ctx context.Context, commands []AckCommand) error {
	if len(commands) == 0 {
		return nil
	}
	route := commands[0].Route
	for _, command := range commands {
		if command.ID == "" || command.Token == "" || command.Route != route {
			return errors.New("invalid or mixed-route acknowledgement batch")
		}
	}
	k := r.keys(route)
	return r.watch(ctx, func(tx *redis.Tx) error {
		count, err := tx.HLen(ctx, k.entries).Result()
		if err != nil {
			return err
		}
		used, err := tx.Get(ctx, k.bytes).Int64()
		if err != nil && err != redis.Nil {
			return err
		}
		globalCount, err := tx.Get(ctx, k.globalEntries).Int64()
		if err != nil && err != redis.Nil {
			return err
		}
		globalUsed, err := tx.Get(ctx, k.globalBytes).Int64()
		if err != nil && err != redis.Nil {
			return err
		}
		entries := make([]redisAckEntry, 0, len(commands))
		seen := make(map[string]struct{}, len(commands))
		for _, command := range commands {
			if _, duplicate := seen[command.ID]; duplicate {
				continue
			}
			seen[command.ID] = struct{}{}
			exists, err := tx.HExists(ctx, k.entries, command.ID).Result()
			if err != nil {
				return err
			}
			if !exists {
				entries = append(entries, redisAckEntry{Command: command})
				used += int64(len(command.Token))
				globalUsed += int64(len(command.Token))
			}
		}
		globalCount += int64(len(entries))
		if (r.options.MaxEntries > 0 && count+int64(len(entries)) > int64(r.options.MaxEntries)) ||
			(r.options.MaxBytes > 0 && used > r.options.MaxBytes) ||
			(r.options.MaxGlobalEntries > 0 && globalCount > int64(r.options.MaxGlobalEntries)) ||
			(r.options.MaxGlobalBytes > 0 && globalUsed > r.options.MaxGlobalBytes) {
			return ErrAckBacklogFull
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			for _, entry := range entries {
				encoded, _ := json.Marshal(entry)
				pipe.HSet(ctx, k.entries, entry.Command.ID, encoded)
				pipe.ZAdd(ctx, k.order, redis.Z{Score: float64(entry.Command.AppendedAt.UnixNano()), Member: entry.Command.ID})
				pipe.IncrBy(ctx, k.bytes, int64(len(entry.Command.Token)))
				pipe.Incr(ctx, k.globalEntries)
				pipe.IncrBy(ctx, k.globalBytes, int64(len(entry.Command.Token)))
			}
			return nil
		})
		return err
	}, k.entries, k.order, k.bytes, k.globalEntries, k.globalBytes)
}

func (r *RedisDurableAckTransport) Assign(ctx context.Context, route AckRoute, owner string, identity KafkaGroupIdentity) (AckAssignment, error) {
	if owner == "" || identity.MemberID == "" || identity.Generation < 0 {
		return AckAssignment{}, errors.New("owner and valid Kafka group identity are required")
	}
	k := r.keys(route)
	assignment := AckAssignment{Route: route, Owner: owner, Generation: identity.Generation, GroupMemberID: identity.MemberID}
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		encodedCurrent, err := tx.Get(ctx, k.assignment).Bytes()
		if err == nil {
			var current AckAssignment
			if err := json.Unmarshal(encodedCurrent, &current); err != nil {
				return fmt.Errorf("decode acknowledgement assignment: %w", err)
			}
			if assignment.Generation < current.Generation {
				return ErrAckRouteFenced
			}
			if assignment.Generation == current.Generation {
				if current.Owner == assignment.Owner && current.GroupMemberID == assignment.GroupMemberID {
					assignment = current
					return nil
				}
				return ErrAckRouteFenced
			}
		} else if err != redis.Nil {
			return err
		}
		encoded, err := json.Marshal(assignment)
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			ttl := r.options.OwnerTTL
			if ttl <= 0 {
				ttl = 45 * time.Second
			}
			pipe.Set(ctx, k.generation, assignment.Generation, 0)
			pipe.Set(ctx, k.assignment, encoded, 0)
			pipe.Set(ctx, k.heartbeat, "alive", ttl)
			return nil
		})
		return err
	}, k.generation, k.assignment)
	return assignment, err
}

func (r *RedisDurableAckTransport) Heartbeat(ctx context.Context, assignment AckAssignment, now time.Time, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("positive ownership heartbeat TTL is required")
	}
	k := r.keys(assignment.Route)
	return r.watch(ctx, func(tx *redis.Tx) error {
		if err := checkRedisAssignment(ctx, tx, k.assignment, k.heartbeat, assignment); err != nil {
			return err
		}
		_, err := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.Set(ctx, k.heartbeat, "alive", ttl); return nil })
		return err
	}, k.assignment, k.heartbeat)
}

func (r *RedisDurableAckTransport) Claim(ctx context.Context, assignment AckAssignment, consumer string, limit int, lease time.Duration, now time.Time) ([]AckDelivery, error) {
	if consumer == "" || limit <= 0 || lease <= 0 {
		return nil, errors.New("consumer, positive limit, and lease are required")
	}
	k := r.keys(assignment.Route)
	var deliveries []AckDelivery
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		if err := checkRedisAssignment(ctx, tx, k.assignment, k.heartbeat, assignment); err != nil {
			return err
		}
		serverNow, err := tx.Time(ctx).Result()
		if err != nil {
			return err
		}
		scan := r.options.ClaimScanLimit
		if scan <= 0 {
			scan = int64(limit * 8)
		}
		if scan < int64(limit) {
			scan = int64(limit)
		}
		if scan > 1024 {
			scan = 1024
		}
		ids, err := tx.ZRange(ctx, k.order, 0, scan-1).Result()
		if err != nil {
			return err
		}
		updates := map[string][]byte{}
		for _, id := range ids {
			encoded, err := tx.HGet(ctx, k.entries, id).Bytes()
			if err == redis.Nil {
				continue
			}
			if err != nil {
				return err
			}
			var entry redisAckEntry
			if err := json.Unmarshal(encoded, &entry); err != nil {
				return fmt.Errorf("decode durable acknowledgement entry: %w", err)
			}
			if serverNow.UnixMilli() < entry.NextAttempt || (entry.Pending && entry.ClaimGeneration == assignment.Generation && serverNow.UnixMilli() < entry.LeaseUntil) {
				continue
			}
			entry.Pending, entry.Consumer, entry.Attempts, entry.LeaseUntil = true, consumer, entry.Attempts+1, serverNow.Add(lease).UnixMilli()
			entry.ClaimGeneration = assignment.Generation
			updates[id], _ = json.Marshal(entry)
			deliveries = append(deliveries, AckDelivery{Command: entry.Command, Consumer: consumer, Attempts: entry.Attempts, LeaseUntil: time.UnixMilli(entry.LeaseUntil)})
			if len(deliveries) == limit {
				break
			}
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			for id, encoded := range updates {
				pipe.HSet(ctx, k.entries, id, encoded)
			}
			return nil
		})
		return err
	}, k.assignment, k.heartbeat, k.entries, k.order)
	return deliveries, err
}

func checkRedisAssignment(ctx context.Context, tx *redis.Tx, key, heartbeatKey string, assignment AckAssignment) error {
	value, err := tx.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrAckRouteFenced
		}
		return err
	}
	var current AckAssignment
	if json.Unmarshal([]byte(value), &current) != nil || current != assignment {
		return ErrAckRouteFenced
	}
	exists, err := tx.Exists(ctx, heartbeatKey).Result()
	if err != nil || exists != 1 {
		return ErrAckRouteFenced
	}
	return nil
}

func (r *RedisDurableAckTransport) Complete(ctx context.Context, assignment AckAssignment, id string) error {
	return r.remove(ctx, assignment, id, "", time.Time{})
}
func (r *RedisDurableAckTransport) DeadLetter(ctx context.Context, assignment AckAssignment, id, reason string, now time.Time) error {
	return r.remove(ctx, assignment, id, reason, now)
}
func (r *RedisDurableAckTransport) remove(ctx context.Context, assignment AckAssignment, id, reason string, now time.Time) error {
	k := r.keys(assignment.Route)
	return r.watch(ctx, func(tx *redis.Tx) error {
		if err := checkRedisAssignment(ctx, tx, k.assignment, k.heartbeat, assignment); err != nil {
			return err
		}
		encoded, err := tx.HGet(ctx, k.entries, id).Bytes()
		if err == redis.Nil {
			return nil
		}
		if err != nil {
			return err
		}
		var entry redisAckEntry
		if err := json.Unmarshal(encoded, &entry); err != nil {
			return err
		}
		if !entry.Pending {
			return errors.New("acknowledgement command is not pending")
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			if reason != "" {
				dead, _ := json.Marshal(AckDeadLetter{Delivery: AckDelivery{Command: entry.Command, Consumer: entry.Consumer, Attempts: entry.Attempts, LeaseUntil: time.UnixMilli(entry.LeaseUntil)}, Reason: reason, At: now})
				pipe.RPush(ctx, k.dead, dead)
			}
			pipe.HDel(ctx, k.entries, id)
			pipe.ZRem(ctx, k.order, id)
			pipe.DecrBy(ctx, k.bytes, int64(len(entry.Command.Token)))
			pipe.Decr(ctx, k.globalEntries)
			pipe.DecrBy(ctx, k.globalBytes, int64(len(entry.Command.Token)))
			return nil
		})
		return err
	}, k.assignment, k.heartbeat, k.entries, k.order, k.bytes, k.dead, k.globalEntries, k.globalBytes)
}

func (r *RedisDurableAckTransport) Release(ctx context.Context, assignment AckAssignment, id string) error {
	return r.ScheduleRetry(ctx, assignment, id, time.Time{})
}

func (r *RedisDurableAckTransport) ScheduleRetry(ctx context.Context, assignment AckAssignment, id string, next time.Time) error {
	k := r.keys(assignment.Route)
	return r.client.Watch(ctx, func(tx *redis.Tx) error {
		if err := checkRedisAssignment(ctx, tx, k.assignment, k.heartbeat, assignment); err != nil {
			return err
		}
		encoded, err := tx.HGet(ctx, k.entries, id).Bytes()
		if err == redis.Nil {
			return nil
		}
		if err != nil {
			return err
		}
		var entry redisAckEntry
		if err := json.Unmarshal(encoded, &entry); err != nil {
			return err
		}
		entry.Pending, entry.Consumer, entry.LeaseUntil, entry.NextAttempt = false, "", 0, next.UnixMilli()
		encoded, _ = json.Marshal(entry)
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error { pipe.HSet(ctx, k.entries, id, encoded); return nil })
		return err
	}, k.assignment, k.heartbeat, k.entries)
}

func (r *RedisDurableAckTransport) Stats(ctx context.Context, route AckRoute) AckBacklogStats {
	k := r.keys(route)
	entries, err := r.client.HVals(ctx, k.entries).Result()
	if err != nil {
		return AckBacklogStats{}
	}
	stats := AckBacklogStats{Active: len(entries)}
	for _, encoded := range entries {
		var entry redisAckEntry
		if json.Unmarshal([]byte(encoded), &entry) == nil {
			stats.ActiveBytes += int64(len(entry.Command.Token))
			if entry.Pending {
				stats.Pending++
			}
		}
	}
	stats.DeadLetters = int(r.client.LLen(ctx, k.dead).Val())
	return stats
}

func (r *RedisDurableAckTransport) String() string {
	return fmt.Sprintf("redis durable ack transport %s", r.options.Prefix)
}
