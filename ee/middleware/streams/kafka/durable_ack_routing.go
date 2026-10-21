package kafka

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrAckRouteFenced = errors.New("acknowledgement route owner is fenced")
	ErrAckBacklogFull = errors.New("durable acknowledgement backlog is full")
)

// AckRoute identifies the active connector partition that must apply a durable
// command. Topic and Partition are empty/zero only for legacy route-wide tests.
type AckRoute struct {
	Key       ControllerKey
	Topic     string
	Partition int32
}

type AckCommand struct {
	ID         string
	Route      AckRoute
	Token      string
	AppendedAt time.Time
}

type AckAssignment struct {
	Route         AckRoute
	Owner         string
	Generation    int32
	GroupMemberID string
}

// KafkaGroupIdentity is the coordinator-issued identity of the active group
// member. Generation ordering is authoritative for ownership fencing.
type KafkaGroupIdentity struct {
	Generation int32
	MemberID   string
}

type AckDelivery struct {
	Command    AckCommand
	Consumer   string
	Attempts   int
	LeaseUntil time.Time
}

type AckDeadLetter struct {
	Delivery AckDelivery
	Reason   string
	At       time.Time
}

type AckBacklogStats struct {
	Active      int
	ActiveBytes int64
	Pending     int
	DeadLetters int
}

// DurableAckTransport is shaped after a Redis Streams consumer group: batch
// append is durable and atomic, Claim includes stale-pending recovery, and all
// mutations are fenced by the current route assignment.
type DurableAckTransport interface {
	AppendBatch(context.Context, []AckCommand) error
	Assign(context.Context, AckRoute, string, KafkaGroupIdentity) (AckAssignment, error)
	Heartbeat(context.Context, AckAssignment, time.Time, time.Duration) error
	Claim(context.Context, AckAssignment, string, int, time.Duration, time.Time) ([]AckDelivery, error)
	Complete(context.Context, AckAssignment, string) error
	Release(context.Context, AckAssignment, string) error
	ScheduleRetry(context.Context, AckAssignment, string, time.Time) error
	DeadLetter(context.Context, AckAssignment, string, string, time.Time) error
	Stats(context.Context, AckRoute) AckBacklogStats
}

// DurableAcknowledgmentRouter implements the HTTP-facing controller contract.
// AckQueued is returned only after AppendBatch confirms durable acceptance.
type DurableAcknowledgmentRouter struct {
	route     AckRoute
	transport DurableAckTransport
	codec     *AckTokenCodec
	scope     string
	now       func() time.Time
}

func NewDurableAcknowledgmentRouter(route AckRoute, transport DurableAckTransport) (*DurableAcknowledgmentRouter, error) {
	if err := route.Key.validate(); err != nil {
		return nil, err
	}
	if transport == nil {
		return nil, errors.New("durable acknowledgement transport is required")
	}
	return &DurableAcknowledgmentRouter{route: route, transport: transport, now: time.Now}, nil
}

func NewPartitionedDurableAcknowledgmentRouter(key ControllerKey, transport DurableAckTransport, codec *AckTokenCodec) (*DurableAcknowledgmentRouter, error) {
	if codec == nil {
		return nil, errors.New("acknowledgement token codec is required")
	}
	router, err := NewDurableAcknowledgmentRouter(AckRoute{Key: key}, transport)
	if err != nil {
		return nil, err
	}
	router.codec = codec
	router.scope = controllerScope(key)
	return router, nil
}

func (r *DurableAcknowledgmentRouter) Acknowledge(ctx context.Context, tokens []string) ([]AckResult, error) {
	commandsByRoute := make(map[AckRoute][]AckCommand)
	indexesByRoute := make(map[AckRoute][]int)
	results := make([]AckResult, len(tokens))
	now := r.now()
	for i, token := range tokens {
		if token == "" {
			results[i].Disposition = AckInvalid
			continue
		}
		route := r.route
		if r.codec != nil {
			claims, err := r.codec.Verify(token, r.scope)
			if err != nil {
				switch {
				case errors.Is(err, ErrExpiredAckToken):
					results[i].Disposition = AckExpired
				case errors.Is(err, ErrScopeMismatch):
					results[i].Disposition = AckStale
				default:
					results[i].Disposition = AckInvalid
				}
				continue
			}
			route.Topic, route.Partition = claims.Topic, claims.Partition
		}
		command := AckCommand{ID: ackCommandID(route, token), Route: route, Token: token, AppendedAt: now}
		commandsByRoute[route] = append(commandsByRoute[route], command)
		indexesByRoute[route] = append(indexesByRoute[route], i)
	}
	for route, commands := range commandsByRoute {
		disposition := AckQueued
		if err := r.transport.AppendBatch(ctx, commands); err != nil {
			if r.codec == nil {
				return nil, err
			}
			disposition = AckUnavailable
		}
		for _, index := range indexesByRoute[route] {
			results[index].Disposition = disposition
		}
	}
	return results, nil
}

func ackCommandID(route AckRoute, token string) string {
	sum := sha256.Sum256([]byte(route.String() + "\x00" + token))
	return hex.EncodeToString(sum[:])
}

// DurableAckConsumer drains commands for one fenced owner. Unavailable and
// processing errors remain recoverable; poison commands are dead-lettered only
// after MaxAttempts claims.
type DurableAckConsumer struct {
	Transport   DurableAckTransport
	Assignment  AckAssignment
	Consumer    string
	Target      AcknowledgmentController
	Lease       time.Duration
	MaxAttempts int
	RetryBase   time.Duration
	RetryMax    time.Duration
}

func (c *DurableAckConsumer) Process(ctx context.Context, limit int, now time.Time) (int, error) {
	if c.Transport == nil || c.Target == nil || c.Consumer == "" {
		return 0, errors.New("durable acknowledgement consumer is incomplete")
	}
	deliveries, err := c.Transport.Claim(ctx, c.Assignment, c.Consumer, limit, c.Lease, now)
	if err != nil {
		return 0, err
	}
	processed := 0
	for _, delivery := range deliveries {
		results, applyErr := c.Target.Acknowledge(ctx, []string{delivery.Command.Token})
		if applyErr == nil && len(results) == 1 && results[0].Disposition == AckInvalid {
			if err := c.Transport.DeadLetter(ctx, c.Assignment, delivery.Command.ID, "invalid acknowledgement command", now); err != nil {
				return processed, err
			}
			processed++
			continue
		}
		poison := applyErr != nil || len(results) != 1 || results[0].Disposition == AckUnavailable
		if poison {
			if c.MaxAttempts > 0 && delivery.Attempts >= c.MaxAttempts {
				reason := "acknowledgement processing unavailable"
				if applyErr != nil {
					reason = applyErr.Error()
				}
				if err := c.Transport.DeadLetter(ctx, c.Assignment, delivery.Command.ID, reason, now); err != nil {
					return processed, err
				}
				processed++
				continue
			}
			base := c.RetryBase
			if base <= 0 {
				base = time.Second
			}
			maximum := c.RetryMax
			if maximum <= 0 {
				maximum = 30 * time.Second
			}
			delay := base
			for attempt := 1; attempt < delivery.Attempts && delay < maximum/2; attempt++ {
				delay *= 2
			}
			if delay > maximum {
				delay = maximum
			}
			if err := c.Transport.ScheduleRetry(ctx, c.Assignment, delivery.Command.ID, now.Add(delay)); err != nil {
				return processed, err
			}
			continue
		}
		if err := c.Transport.Complete(ctx, c.Assignment, delivery.Command.ID); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

type InMemoryDurableAckOptions struct {
	MaxEntries int
	MaxBytes   int64
	OwnerTTL   time.Duration
}
type memoryAckEntry struct {
	command         AckCommand
	consumer        string
	attempts        int
	leaseUntil      time.Time
	nextAttempt     time.Time
	claimGeneration int32
	pending         bool
}

// InMemoryDurableAckTransport is a concurrency-safe reference implementation,
// intended for tests and as executable semantics for a Redis Streams adapter.
type InMemoryDurableAckTransport struct {
	mu          sync.Mutex
	options     InMemoryDurableAckOptions
	entries     map[string]*memoryAckEntry
	order       []string
	assignments map[AckRoute]AckAssignment
	ownerExpiry map[AckRoute]time.Time
	deadLetters []AckDeadLetter
	bytes       int64
}

func NewInMemoryDurableAckTransport(options InMemoryDurableAckOptions) *InMemoryDurableAckTransport {
	return &InMemoryDurableAckTransport{options: options, entries: map[string]*memoryAckEntry{}, assignments: map[AckRoute]AckAssignment{}, ownerExpiry: map[AckRoute]time.Time{}}
}

func (m *InMemoryDurableAckTransport) AppendBatch(_ context.Context, commands []AckCommand) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	newCount, newBytes := 0, int64(0)
	seen := map[string]struct{}{}
	for _, command := range commands {
		if command.ID == "" || command.Token == "" {
			return errors.New("invalid acknowledgement command")
		}
		if _, duplicate := seen[command.ID]; duplicate {
			continue
		}
		seen[command.ID] = struct{}{}
		if existing := m.entries[command.ID]; existing != nil {
			continue
		}
		newCount++
		newBytes += int64(len(command.Token))
	}
	if (m.options.MaxEntries > 0 && len(m.entries)+newCount > m.options.MaxEntries) || (m.options.MaxBytes > 0 && m.bytes+newBytes > m.options.MaxBytes) {
		return ErrAckBacklogFull
	}
	for _, command := range commands {
		if m.entries[command.ID] != nil {
			continue
		}
		copyCommand := command
		m.entries[command.ID] = &memoryAckEntry{command: copyCommand}
		m.order = append(m.order, command.ID)
		m.bytes += int64(len(command.Token))
	}
	return nil
}

func (m *InMemoryDurableAckTransport) Assign(_ context.Context, route AckRoute, owner string, identity KafkaGroupIdentity) (AckAssignment, error) {
	if owner == "" || identity.MemberID == "" || identity.Generation < 0 {
		return AckAssignment{}, errors.New("owner and valid Kafka group identity are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.assignments[route]
	if exists {
		if identity.Generation < current.Generation {
			return AckAssignment{}, ErrAckRouteFenced
		}
		if identity.Generation == current.Generation {
			if current.Owner == owner && current.GroupMemberID == identity.MemberID {
				return current, nil
			}
			return AckAssignment{}, ErrAckRouteFenced
		}
	}
	a := AckAssignment{Route: route, Owner: owner, Generation: identity.Generation, GroupMemberID: identity.MemberID}
	m.assignments[route] = a
	ttl := m.options.OwnerTTL
	if ttl <= 0 {
		ttl = 45 * time.Second
	}
	m.ownerExpiry[route] = time.Now().Add(ttl)
	return a, nil
}

func (m *InMemoryDurableAckTransport) Heartbeat(_ context.Context, a AckAssignment, now time.Time, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fenced(a) || ttl <= 0 {
		return ErrAckRouteFenced
	}
	m.ownerExpiry[a.Route] = now.Add(ttl)
	return nil
}

func (m *InMemoryDurableAckTransport) fenced(a AckAssignment) bool {
	return m.assignments[a.Route] != a
}

func (m *InMemoryDurableAckTransport) Claim(_ context.Context, a AckAssignment, consumer string, limit int, lease time.Duration, now time.Time) ([]AckDelivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fenced(a) {
		return nil, ErrAckRouteFenced
	}
	if !m.ownerExpiry[a.Route].After(now) {
		return nil, ErrAckRouteFenced
	}
	if consumer == "" || limit <= 0 || lease <= 0 {
		return nil, errors.New("consumer, positive limit, and lease are required")
	}
	result := make([]AckDelivery, 0, limit)
	for _, id := range m.order {
		entry := m.entries[id]
		if entry == nil || entry.command.Route != a.Route || now.Before(entry.nextAttempt) || (entry.pending && entry.claimGeneration == a.Generation && now.Before(entry.leaseUntil)) {
			continue
		}
		entry.pending, entry.consumer, entry.leaseUntil = true, consumer, now.Add(lease)
		entry.attempts++
		entry.claimGeneration = a.Generation
		result = append(result, AckDelivery{Command: entry.command, Consumer: consumer, Attempts: entry.attempts, LeaseUntil: entry.leaseUntil})
		if len(result) == limit {
			break
		}
	}
	return result, nil
}

func (m *InMemoryDurableAckTransport) Complete(_ context.Context, a AckAssignment, id string) error {
	return m.remove(a, id, "", time.Time{})
}
func (m *InMemoryDurableAckTransport) DeadLetter(_ context.Context, a AckAssignment, id, reason string, now time.Time) error {
	return m.remove(a, id, reason, now)
}
func (m *InMemoryDurableAckTransport) remove(a AckAssignment, id, reason string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fenced(a) {
		return ErrAckRouteFenced
	}
	e := m.entries[id]
	if e == nil {
		return nil
	}
	if !e.pending {
		return errors.New("acknowledgement command is not pending")
	}
	if reason != "" {
		m.deadLetters = append(m.deadLetters, AckDeadLetter{Delivery: AckDelivery{Command: e.command, Consumer: e.consumer, Attempts: e.attempts, LeaseUntil: e.leaseUntil}, Reason: reason, At: now})
	}
	delete(m.entries, id)
	m.bytes -= int64(len(e.command.Token))
	return nil
}
func (m *InMemoryDurableAckTransport) Release(_ context.Context, a AckAssignment, id string) error {
	return m.ScheduleRetry(context.Background(), a, id, time.Time{})
}
func (m *InMemoryDurableAckTransport) ScheduleRetry(_ context.Context, a AckAssignment, id string, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fenced(a) {
		return ErrAckRouteFenced
	}
	e := m.entries[id]
	if e == nil {
		return nil
	}
	e.pending, e.consumer, e.leaseUntil, e.nextAttempt = false, "", time.Time{}, next
	return nil
}
func (m *InMemoryDurableAckTransport) Stats(_ context.Context, route AckRoute) AckBacklogStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := AckBacklogStats{DeadLetters: len(m.deadLetters)}
	for _, e := range m.entries {
		if e.command.Route == route {
			s.Active++
			s.ActiveBytes += int64(len(e.command.Token))
			if e.pending {
				s.Pending++
			}
		}
	}
	return s
}

func (a AckRoute) String() string {
	return fmt.Sprintf("%s/%s/%s/%s/%d", a.Key.APIID, a.Key.StreamID, a.Key.ComponentID, a.Topic, a.Partition)
}
