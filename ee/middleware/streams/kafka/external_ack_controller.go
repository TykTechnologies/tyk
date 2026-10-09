package kafka

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/warpstreamlabs/bento/public/service"
)

type recordCommitter interface {
	CommitRecords(context.Context, ...*kgo.Record) error
}

type topicPartition struct {
	topic     string
	partition int32
}

type DeadlineActionKind string

const (
	DeadlineNone                    DeadlineActionKind = "none"
	DeadlinePause                   DeadlineActionKind = "pause"
	DeadlineRestartForRedelivery    DeadlineActionKind = "restart_for_redelivery" // Deprecated: retained for API compatibility.
	DeadlineRedeliverPartitions     DeadlineActionKind = "redeliver_partitions"
	DeadlineDeadLettered            DeadlineActionKind = "dead_lettered"
	DeadlineDeadLetterNotConfigured DeadlineActionKind = "dead_letter_not_configured"
)

type DeadlineDecision struct {
	Action         DeadlineActionKind
	ExpiredRecords int
	Partitions     []TopicPartition
	Epoch          uint64
	Redeliver      []RedeliveryTarget
}

type RedeliveryTarget struct {
	Topic     string
	Partition int32
	Offset    int64
}

type redeliveryAttempt struct {
	Attempts int
	FirstAt  time.Time
}

type DeadLetterRecord struct {
	Scope    string
	Epoch    uint64
	ReplayID string
	Record   *kgo.Record
	Deadline time.Time
}

// DurableDeadLetterWriter must return nil only after the record is durably
// accepted. The controller never acknowledges a record when this call fails.
type DurableDeadLetterWriter interface {
	WriteDeadLetter(context.Context, DeadLetterRecord) error
}

// ExternalAckController owns the acknowledgement state associated with one
// active franz-go consumer. Kafka progress is never changed by HTTP handlers;
// they submit opaque capabilities to this controller instead.
type ExternalAckController struct {
	mu             sync.Mutex
	commitMu       sync.Mutex
	commitCtx      context.Context
	commitCancel   context.CancelFunc
	commitDone     chan struct{}
	commitRequests chan commitFlushRequest

	key             ControllerKey
	scope           string
	clusterID       string
	topicIDs        map[string]string
	replayID        string
	epoch           uint64
	codec           *AckTokenCodec
	committer       recordCommitter
	deadLetters     DurableDeadLetterWriter
	metrics         *ExternalAckMetrics
	now             func() time.Time
	config          AcknowledgmentConfig
	windows         map[topicPartition]*PartitionAckWindow
	partitionEpochs map[topicPartition]uint64
	pending         map[topicPartition]*CommitPoint
	deliveries      map[topicPartition]map[int64]*kgo.Record
	redeliveries    map[topicPartition]redeliveryAttempt
	totalRecords    int
	totalBytes      int64
	closed          bool
	consumerGroup   string
	ownerID         string
}

func (c *ExternalAckController) SetDeliveryAuthority(group, owner string) {
	c.mu.Lock()
	c.consumerGroup, c.ownerID = group, owner
	c.mu.Unlock()
}

type commitFlushRequest struct {
	ctx    context.Context
	result chan error
}

// HasCapacity reports whether polling may admit at least one more record. It
// intentionally does not predict record size; Track enforces the hard byte
// limit once Kafka reveals the next record.
func (c *ExternalAckController) HasCapacity() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	return (c.config.MaxInFlight <= 0 || c.totalRecords < c.config.MaxInFlight) &&
		(c.config.MaxInFlightBytes == 0 || uint64(c.totalBytes) < c.config.MaxInFlightBytes)
}

// CanTrack evaluates admission for a fetched record without reserving it.
// Track remains the authority and rechecks these limits atomically.
func (c *ExternalAckController) CanTrack(record *kgo.Record) bool {
	if record == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	size := int64(len(record.Key) + len(record.Value))
	if c.config.MaxInFlight > 0 && c.totalRecords+1 > c.config.MaxInFlight {
		return false
	}
	if c.config.MaxInFlightBytes > 0 && uint64(c.totalBytes+size) > c.config.MaxInFlightBytes {
		return false
	}
	window := c.windows[topicPartition{record.Topic, record.Partition}]
	if window == nil {
		return true
	}
	records, bytes := window.Pending()
	return (c.config.CheckpointLimit <= 0 || records+1 <= c.config.CheckpointLimit) &&
		(c.config.MaxInFlightBytes == 0 || uint64(bytes+size) <= c.config.MaxInFlightBytes)
}

func (c *ExternalAckController) RecordExceedsLimit(record *kgo.Record) bool {
	if record == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	size := uint64(len(record.Key) + len(record.Value))
	return c.config.MaxInFlightBytes > 0 && size > c.config.MaxInFlightBytes
}

var acknowledgmentEpoch atomic.Uint64

func NewExternalAckController(key ControllerKey, clusterID, replayID string, codec *AckTokenCodec, config AcknowledgmentConfig) (*ExternalAckController, error) {
	if err := key.validate(); err != nil {
		return nil, err
	}
	if codec == nil {
		return nil, errors.New("acknowledgement token codec is required")
	}
	if config.Mode != AcknowledgmentModeExternal {
		return nil, errors.New("external acknowledgement mode is required")
	}
	if clusterID == "" {
		clusterID = "unknown"
	}
	if replayID == "" {
		replayID = "0"
	}
	epoch := acknowledgmentEpoch.Add(1)
	commitCtx, commitCancel := context.WithCancel(context.Background())
	controller := &ExternalAckController{
		key:             key,
		scope:           controllerScope(key),
		clusterID:       clusterID,
		replayID:        replayID,
		epoch:           epoch,
		codec:           codec,
		metrics:         &ExternalAckMetrics{},
		config:          config,
		now:             time.Now,
		windows:         make(map[topicPartition]*PartitionAckWindow),
		partitionEpochs: make(map[topicPartition]uint64),
		pending:         make(map[topicPartition]*CommitPoint),
		deliveries:      make(map[topicPartition]map[int64]*kgo.Record),
		redeliveries:    make(map[topicPartition]redeliveryAttempt),
		topicIDs:        make(map[string]string),
		commitCtx:       commitCtx,
		commitCancel:    commitCancel,
		commitDone:      make(chan struct{}),
		commitRequests:  make(chan commitFlushRequest),
	}
	go controller.runCommitLoop()
	return controller, nil
}

func (c *ExternalAckController) SetKafkaIdentity(clusterID string, topicIDs map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if clusterID != "" {
		c.clusterID = clusterID
	}
	if c.topicIDs == nil {
		c.topicIDs = make(map[string]string, len(topicIDs))
	}
	for topic, id := range topicIDs {
		if id != "" {
			c.topicIDs[topic] = id
		}
	}
}

func controllerScope(key ControllerKey) string {
	return key.APIID + "\x00" + key.StreamID + "\x00" + key.ComponentID
}

func randomIdentity() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (c *ExternalAckController) SetCommitter(committer recordCommitter) {
	c.mu.Lock()
	c.committer = committer
	c.mu.Unlock()
}

func (c *ExternalAckController) SetDeadLetterWriter(writer DurableDeadLetterWriter) {
	c.mu.Lock()
	c.deadLetters = writer
	c.mu.Unlock()
}

// InvalidateForReset fences all pre-reset delivery capabilities and frees the
// bounded in-flight state. Kafka will redeliver from the newly selected offset.
func (c *ExternalAckController) InvalidateForReset() {
	c.commitMu.Lock()
	defer c.commitMu.Unlock()
	c.mu.Lock()
	c.epoch = acknowledgmentEpoch.Add(1)
	c.windows = make(map[topicPartition]*PartitionAckWindow)
	c.pending = make(map[topicPartition]*CommitPoint)
	c.deliveries = make(map[topicPartition]map[int64]*kgo.Record)
	c.totalRecords, c.totalBytes = 0, 0
	c.mu.Unlock()
}

// AssignPartitions establishes a fresh fencing epoch for each newly assigned
// partition. The window itself is initialized by the first record because the
// group callback does not provide the partition's starting fetch offset.
func (c *ExternalAckController) AssignPartitions(partitions map[string][]int32) {
	c.commitMu.Lock()
	defer c.commitMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	for topic, values := range partitions {
		for _, partition := range values {
			tp := topicPartition{topic: topic, partition: partition}
			c.clearPartitionLocked(tp)
			epoch := acknowledgmentEpoch.Add(1)
			c.partitionEpochs[tp] = epoch
			c.epoch = epoch
		}
	}
}

// RevokePartitions is the revocation barrier. It excludes concurrent HTTP
// acknowledgments, retries any safe contiguous commit, and invalidates only
// the revoked partitions. State is discarded even when the final commit fails
// so Kafka can safely redeliver it to the next owner.
func (c *ExternalAckController) RevokePartitions(ctx context.Context, partitions map[string][]int32) error {
	operationCtx, cancel := boundedAckOperationContext(ctx, 10*time.Second)
	defer cancel()
	c.commitMu.Lock()
	defer c.commitMu.Unlock()

	targets := topicPartitionSet(partitions)
	c.mu.Lock()
	committer := c.committer
	records := make([]*kgo.Record, 0, len(targets))
	epochs := make(map[topicPartition]uint64, len(targets))
	for tp := range targets {
		epochs[tp] = c.partitionEpochs[tp]
		if point := c.pending[tp]; point != nil {
			records = append(records, commitPointRecord(point))
		}
	}
	c.mu.Unlock()

	var result error
	if len(records) > 0 {
		if committer == nil {
			result = errors.New("Kafka committer is not configured")
		} else {
			c.metrics.commitAttempts.Add(1)
			if err := committer.CommitRecords(operationCtx, records...); err != nil {
				c.metrics.commitFailures.Add(1)
				result = fmt.Errorf("commit revoked partitions: %w", err)
			}
		}
	}

	c.mu.Lock()
	for tp, epoch := range epochs {
		// Assign/reset also take commitMu. The epoch check documents and enforces
		// that a delayed lifecycle completion can never erase replacement state.
		if c.partitionEpochs[tp] == epoch {
			c.clearPartitionLocked(tp)
			delete(c.partitionEpochs, tp)
		}
	}
	c.mu.Unlock()
	return result
}

func topicPartitionSet(partitions map[string][]int32) map[topicPartition]struct{} {
	targets := make(map[topicPartition]struct{})
	for topic, values := range partitions {
		for _, partition := range values {
			targets[topicPartition{topic: topic, partition: partition}] = struct{}{}
		}
	}
	return targets
}

func boundedAckOperationContext(parent context.Context, maximum time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if deadline, ok := parent.Deadline(); ok && time.Until(deadline) <= maximum {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, maximum)
}

// LosePartitions fences partitions without committing because the group has
// already lost ownership and a generation-aware commit is no longer safe.
func (c *ExternalAckController) LosePartitions(partitions map[string][]int32) {
	c.commitMu.Lock()
	defer c.commitMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	for topic, values := range partitions {
		for _, partition := range values {
			tp := topicPartition{topic: topic, partition: partition}
			c.clearPartitionLocked(tp)
			delete(c.partitionEpochs, tp)
		}
	}
}

func (c *ExternalAckController) clearPartitionLocked(tp topicPartition) {
	if window := c.windows[tp]; window != nil {
		records, bytes := window.Pending()
		c.totalRecords -= records
		c.totalBytes -= bytes
	}
	delete(c.windows, tp)
	delete(c.pending, tp)
	delete(c.deliveries, tp)
}

func commitPointRecord(point *CommitPoint) *kgo.Record {
	return &kgo.Record{Topic: point.Topic, Partition: point.Partition, Offset: point.RecordOffset, LeaderEpoch: point.LeaderEpoch}
}

// Track reserves acknowledgement capacity and attaches immutable delivery
// identity metadata to the Bento message before it enters the output pipeline.
func (c *ExternalAckController) Track(record *kgo.Record, message *service.Message) error {
	if record == nil || message == nil {
		return errors.New("record and message are required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("acknowledgement controller is closed")
	}
	size := int64(len(record.Key) + len(record.Value))
	if c.config.MaxInFlight > 0 && c.totalRecords+1 > c.config.MaxInFlight {
		c.metrics.capacityRejects.Add(1)
		return ErrWindowFull
	}
	if c.config.MaxInFlightBytes > 0 && uint64(c.totalBytes+size) > c.config.MaxInFlightBytes {
		c.metrics.capacityRejects.Add(1)
		return ErrWindowFull
	}
	tp := topicPartition{record.Topic, record.Partition}
	epoch := c.partitionEpochs[tp]
	if epoch == 0 {
		epoch = c.epoch
		c.partitionEpochs[tp] = epoch
	}
	window := c.windows[tp]
	if window == nil {
		var err error
		window, err = NewPartitionAckWindow(record.Topic, record.Partition, epoch, record.Offset, WindowLimits{
			MaxRecords: c.config.CheckpointLimit,
			MaxBytes:   int64(c.config.MaxInFlightBytes),
		})
		if err != nil {
			return err
		}
		c.windows[tp] = window
	}
	now := c.now()
	deadline := now.Add(c.config.AckDeadline + c.redeliveryDelayLocked(tp))
	if err := window.Track(epoch, DeliveredRecord{Offset: record.Offset, LeaderEpoch: record.LeaderEpoch, Bytes: size, Deadline: deadline}); err != nil {
		return err
	}
	c.totalRecords++
	c.totalBytes += size
	if c.deliveries[tp] == nil {
		c.deliveries[tp] = make(map[int64]*kgo.Record)
	}
	c.deliveries[tp][record.Offset] = cloneKafkaRecord(record)
	claimTopicID := c.topicIDs[record.Topic]
	topicID := claimTopicID
	if topicID == "" {
		topicID = "unknown"
	}
	eventID := EventIdentity(c.scope, c.clusterID, record.Topic, topicID, record.Partition, record.Offset)
	deliveryID := DeliveryIdentity(eventID, epoch, c.replayID)
	claims := AckClaims{
		Scope: c.scope, Epoch: epoch, ReplayID: c.replayID,
		ClusterID: c.clusterID, Topic: record.Topic, TopicID: claimTopicID, Partition: record.Partition, Offset: record.Offset,
		ExpiresAt: now.Add(c.config.TokenTTL).Unix(),
	}
	if c.consumerGroup != "" && c.ownerID != "" {
		nonce, nonceErr := randomIdentity()
		if nonceErr != nil {
			return nonceErr
		}
		claims.IssuedAt, claims.ConsumerGroup, claims.Owner, claims.Nonce = now.Unix(), c.consumerGroup, c.ownerID, nonce
	}
	token, err := c.codec.Sign(claims)
	if err != nil {
		return err
	}
	message.MetaSetMut("tyk_kafka_message_id", eventID)
	message.MetaSetMut("tyk_kafka_delivery_id", deliveryID)
	message.MetaSetMut("tyk_kafka_replay_generation", c.replayID)
	message.MetaSetMut("tyk_kafka_ack_token", token)
	c.metrics.delivered.Add(1)
	return nil
}

func (c *ExternalAckController) Acknowledge(ctx context.Context, tokens []string) ([]AckResult, error) {
	results := make([]AckResult, len(tokens))
	defer func() { c.metrics.observeResults(results) }()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		for i := range results {
			results[i].Disposition = AckUnavailable
		}
		return results, nil
	}
	needsCommit := make(map[topicPartition][]int)
	for i, token := range tokens {
		claims, err := c.codec.Verify(token, c.scope)
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
		if claims.ReplayID != c.replayID {
			results[i].Disposition = AckStale
			continue
		}
		// Kafka topic names can be deleted and recreated with a different topic
		// identity. Never allow a capability issued for the old log to
		// acknowledge the new log at the same numeric partition/offset.
		currentTopicID := c.topicIDs[claims.Topic]
		if (claims.ClusterID != "" && claims.ClusterID != c.clusterID) ||
			(claims.TopicID != "" && currentTopicID != "" && claims.TopicID != currentTopicID) {
			results[i].Disposition = AckStale
			continue
		}
		if claims.ConsumerGroup != c.consumerGroup || claims.Owner != c.ownerID {
			results[i].Disposition = AckStale
			continue
		}
		tp := topicPartition{claims.Topic, claims.Partition}
		window := c.windows[tp]
		if window == nil {
			results[i].Disposition = AckStale
			continue
		}
		if claims.Epoch != window.Epoch() {
			results[i].Disposition = AckStale
			continue
		}
		beforeRecords, beforeBytes := window.Pending()
		point, ackErr := window.Acknowledge(claims.Epoch, claims.Offset)
		if ackErr != nil {
			if errors.Is(ackErr, ErrStaleEpoch) {
				results[i].Disposition = AckStale
			} else if errors.Is(ackErr, ErrUnknownDelivery) && claims.Offset < window.NextOffset() {
				results[i].Disposition = AckDuplicate
				if c.pending[tp] != nil {
					needsCommit[tp] = append(needsCommit[tp], i)
				}
			} else {
				results[i].Disposition = AckInvalid
			}
			continue
		}
		afterRecords, afterBytes := window.Pending()
		c.totalRecords -= beforeRecords - afterRecords
		c.totalBytes -= beforeBytes - afterBytes
		if point != nil {
			c.pending[tp] = point
			c.removeCommittedDeliveries(tp, point.RecordOffset)
		}
		if c.pending[tp] != nil {
			needsCommit[tp] = append(needsCommit[tp], i)
		}
		if point == nil && claims.Offset < window.NextOffset() {
			results[i].Disposition = AckDuplicate
		} else {
			results[i].Disposition = AckApplied
		}
	}
	c.mu.Unlock()

	if len(needsCommit) > 0 {
		if err := c.flushPending(ctx); err != nil {
			for _, indexes := range needsCommit {
				for _, i := range indexes {
					results[i].Disposition = AckUnavailable
				}
			}
		}
	}
	return results, nil
}

// flushPending serializes commits without holding the state lock during broker
// I/O. If a newer watermark is produced while this call is in flight it is
// deliberately left pending for the next flush.
func (c *ExternalAckController) flushPending(ctx context.Context) error {
	request := commitFlushRequest{ctx: ctx, result: make(chan error, 1)}
	select {
	case c.commitRequests <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.commitCtx.Done():
		return errors.New("acknowledgement controller is closed")
	}
	select {
	case err := <-request.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-c.commitCtx.Done():
		return errors.New("acknowledgement controller is closed")
	}
}

func (c *ExternalAckController) flushPendingDirect(ctx context.Context) error {
	c.commitMu.Lock()
	defer c.commitMu.Unlock()
	return c.flushPendingUnderCommitLock(ctx)
}

// flushPendingUnderCommitLock snapshots state, performs broker I/O without the
// state mutex, and removes only the exact watermark from the same assignment
// epoch after a successful commit. The caller must hold commitMu.
func (c *ExternalAckController) flushPendingUnderCommitLock(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("acknowledgement controller is closed")
	}
	committer := c.committer
	snapshot := make(map[topicPartition]*CommitPoint, len(c.pending))
	epochs := make(map[topicPartition]uint64, len(c.pending))
	records := make([]*kgo.Record, 0, len(c.pending))
	for tp, point := range c.pending {
		copyPoint := *point
		snapshot[tp] = &copyPoint
		epochs[tp] = c.partitionEpochs[tp]
		records = append(records, commitPointRecord(point))
	}
	c.mu.Unlock()

	if len(records) == 0 {
		return nil
	}
	if committer == nil {
		return errors.New("Kafka committer is not configured")
	}
	c.metrics.commitAttempts.Add(1)
	if err := committer.CommitRecords(ctx, records...); err != nil {
		c.metrics.commitFailures.Add(1)
		return err
	}

	c.mu.Lock()
	for tp, committed := range snapshot {
		if current := c.pending[tp]; current != nil && c.partitionEpochs[tp] == epochs[tp] && current.NextOffset == committed.NextOffset {
			delete(c.pending, tp)
		}
	}
	c.mu.Unlock()
	return nil
}

type deadlineCandidate struct {
	tp       topicPartition
	epoch    uint64
	replayID string
	record   DeliveredRecord
	original *kgo.Record
}

func (c *ExternalAckController) runCommitLoop() {
	defer close(c.commitDone)
	for {
		var first commitFlushRequest
		select {
		case <-c.commitCtx.Done():
			return
		case first = <-c.commitRequests:
		}
		batch := []commitFlushRequest{first}
		timer := time.NewTimer(c.config.CommitInterval)
	collect:
		for len(batch) < c.config.CommitBatchSize {
			select {
			case request := <-c.commitRequests:
				batch = append(batch, request)
			case <-timer.C:
				break collect
			case <-c.commitCtx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				for _, request := range batch {
					request.result <- errors.New("acknowledgement controller is closed")
				}
				return
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		commitTimeout := 10 * time.Second
		if candidate := c.config.CommitInterval * 4; candidate > commitTimeout {
			commitTimeout = candidate
		}
		commitCtx, cancel := context.WithTimeout(c.commitCtx, commitTimeout)
		err := c.flushPendingDirect(commitCtx)
		cancel()
		for _, request := range batch {
			request.result <- err
		}
	}
}

// DeadlineAction deterministically evaluates missing acknowledgements at now.
// Redelivery is partition-scoped: affected partitions are fenced and returned
// with their earliest unresolved offsets for the poll owner to seek.
func (c *ExternalAckController) DeadlineAction(now time.Time) (DeadlineDecision, error) {
	operationCtx, cancel := context.WithTimeout(c.commitCtx, 10*time.Second)
	defer cancel()
	c.commitMu.Lock()
	defer c.commitMu.Unlock()

	if err := c.flushPendingUnderCommitLock(operationCtx); err != nil {
		return DeadlineDecision{Action: DeadlineNone}, err
	}

	c.mu.Lock()
	decision := DeadlineDecision{Action: DeadlineNone, Epoch: c.epoch}
	if c.closed {
		c.mu.Unlock()
		return decision, errors.New("acknowledgement controller is closed")
	}
	var candidates []deadlineCandidate
	for tp, window := range c.windows {
		if records := window.Expired(now); len(records) > 0 {
			decision.ExpiredRecords += len(records)
			decision.Partitions = append(decision.Partitions, TopicPartition{Topic: tp.topic, Partition: tp.partition})
			for _, record := range records {
				original := c.deliveries[tp][record.Offset]
				if original == nil {
					c.mu.Unlock()
					return decision, fmt.Errorf("missing delivery for %s/%d offset %d", tp.topic, tp.partition, record.Offset)
				}
				candidates = append(candidates, deadlineCandidate{
					tp: tp, epoch: window.Epoch(), replayID: c.replayID,
					record: record, original: cloneKafkaRecord(original),
				})
			}
		}
	}
	if decision.ExpiredRecords == 0 {
		c.mu.Unlock()
		return decision, nil
	}
	slices.SortFunc(decision.Partitions, func(a, b TopicPartition) int {
		if a.Topic < b.Topic {
			return -1
		}
		if a.Topic > b.Topic {
			return 1
		}
		return cmp.Compare(a.Partition, b.Partition)
	})
	policy := c.config.MissingAckPolicy
	if policy == "redeliver" {
		for _, partition := range decision.Partitions {
			tp := topicPartition{topic: partition.Topic, partition: partition.Partition}
			attempt := c.redeliveries[tp]
			if attempt.FirstAt.IsZero() {
				attempt.FirstAt = now
			}
			attempt.Attempts++
			c.redeliveries[tp] = attempt
			if attempt.Attempts >= c.config.RedeliveryMaxAttempts || now.Sub(attempt.FirstAt) >= c.config.RedeliveryMaxAge {
				policy = c.config.RedeliveryExhaustedPolicy
				break
			}
		}
	}
	switch policy {
	case "pause":
		decision.Action = DeadlinePause
		c.mu.Unlock()
		return decision, nil
	case "redeliver":
		for _, partition := range decision.Partitions {
			tp := topicPartition{topic: partition.Topic, partition: partition.Partition}
			window := c.windows[tp]
			if window == nil {
				continue
			}
			decision.Redeliver = append(decision.Redeliver, RedeliveryTarget{
				Topic: tp.topic, Partition: tp.partition, Offset: window.NextOffset(),
			})
			c.clearPartitionLocked(tp)
			epoch := acknowledgmentEpoch.Add(1)
			c.partitionEpochs[tp] = epoch
			if epoch > c.epoch {
				c.epoch = epoch
			}
		}
		decision.Action, decision.Epoch = DeadlineRedeliverPartitions, c.epoch
		c.mu.Unlock()
		return decision, nil
	case "dead_letter":
		writer := c.deadLetters
		if writer == nil {
			decision.Action = DeadlineDeadLetterNotConfigured
			c.mu.Unlock()
			return decision, nil
		}
		scope := c.scope
		c.mu.Unlock()

		for _, candidate := range candidates {
			if err := writer.WriteDeadLetter(operationCtx, DeadLetterRecord{Scope: scope, Epoch: candidate.epoch, ReplayID: candidate.replayID, Record: candidate.original, Deadline: candidate.record.Deadline}); err != nil {
				return decision, err
			}

			c.mu.Lock()
			window := c.windows[candidate.tp]
			// A reset, rebalance, redelivery, or concurrent acknowledgement may
			// have fenced this completion while the durable write was in flight.
			if !c.closed && c.replayID == candidate.replayID && window != nil && window.Epoch() == candidate.epoch {
				beforeRecords, beforeBytes := window.Pending()
				point, err := window.Acknowledge(candidate.epoch, candidate.record.Offset)
				if err != nil && !errors.Is(err, ErrUnknownDelivery) {
					c.mu.Unlock()
					return decision, err
				}
				afterRecords, afterBytes := window.Pending()
				c.totalRecords -= beforeRecords - afterRecords
				c.totalBytes -= beforeBytes - afterBytes
				if point != nil {
					c.pending[candidate.tp] = point
					c.removeCommittedDeliveries(candidate.tp, point.RecordOffset)
				}
			}
			c.mu.Unlock()
		}
		if err := c.flushPendingUnderCommitLock(operationCtx); err != nil {
			return decision, err
		}
		decision.Action = DeadlineDeadLettered
		return decision, nil
	default:
		c.mu.Unlock()
		return decision, fmt.Errorf("unsupported missing acknowledgement policy %q", c.config.MissingAckPolicy)
	}
}

func cloneKafkaRecord(record *kgo.Record) *kgo.Record {
	copyRecord := *record
	copyRecord.Key = append([]byte(nil), record.Key...)
	copyRecord.Value = append([]byte(nil), record.Value...)
	copyRecord.Headers = make([]kgo.RecordHeader, len(record.Headers))
	for i, header := range record.Headers {
		copyRecord.Headers[i] = kgo.RecordHeader{Key: header.Key, Value: append([]byte(nil), header.Value...)}
	}
	return &copyRecord
}

func (c *ExternalAckController) removeCommittedDeliveries(tp topicPartition, through int64) {
	for offset := range c.deliveries[tp] {
		if offset <= through {
			delete(c.deliveries[tp], offset)
		}
	}
	if len(c.deliveries[tp]) == 0 {
		delete(c.redeliveries, tp)
	}
}

func (c *ExternalAckController) redeliveryDelayLocked(tp topicPartition) time.Duration {
	attempts := c.redeliveries[tp].Attempts
	if attempts <= 0 {
		return 0
	}
	delay := c.config.RedeliveryBackoff
	for i := 1; i < attempts && delay < c.config.RedeliveryMaxBackoff; i++ {
		if delay > c.config.RedeliveryMaxBackoff/2 {
			return c.config.RedeliveryMaxBackoff
		}
		delay *= 2
	}
	if delay > c.config.RedeliveryMaxBackoff {
		return c.config.RedeliveryMaxBackoff
	}
	return delay
}

func (c *ExternalAckController) ShouldPause(topic string, partition int32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	tp := topicPartition{topic, partition}
	window := c.windows[tp]
	if window == nil {
		return false
	}
	return c.shouldPauseLocked(tp, window)
}

func (c *ExternalAckController) shouldPauseLocked(_ topicPartition, window *PartitionAckWindow) bool {
	records, bytes := window.Pending()
	deadlineBlocked := false
	if c.config.MissingAckPolicy == "pause" || (c.config.MissingAckPolicy == "dead_letter" && c.deadLetters == nil) {
		deadlineBlocked = window.DeadlineState(c.now()).ExpiredCount > 0
	}
	return records >= c.config.CheckpointLimit ||
		(c.config.MaxInFlight > 0 && c.totalRecords >= c.config.MaxInFlight) ||
		(c.config.MaxInFlightBytes > 0 && uint64(c.totalBytes) >= c.config.MaxInFlightBytes) ||
		(c.config.MaxInFlightBytes > 0 && uint64(bytes) >= c.config.MaxInFlightBytes) || deadlineBlocked
}

func (c *ExternalAckController) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.CloseContext(ctx)
}

// CloseContext stops new acknowledgements, joins the commit worker, makes one
// bounded final attempt to persist every safe contiguous watermark, and then
// discards local state. Failure is safe: Kafka redelivers from its last stored
// offsets after the connector closes.
func (c *ExternalAckController) CloseContext(ctx context.Context) error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()

	c.commitCancel()
	select {
	case <-c.commitDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	c.commitMu.Lock()
	defer c.commitMu.Unlock()
	c.mu.Lock()
	committer := c.committer
	records := make([]*kgo.Record, 0, len(c.pending))
	for _, point := range c.pending {
		records = append(records, commitPointRecord(point))
	}
	c.mu.Unlock()

	var result error
	if len(records) > 0 {
		if committer == nil {
			result = errors.New("Kafka committer is not configured")
		} else {
			operationCtx, cancel := boundedAckOperationContext(ctx, 10*time.Second)
			c.metrics.commitAttempts.Add(1)
			if err := committer.CommitRecords(operationCtx, records...); err != nil {
				c.metrics.commitFailures.Add(1)
				result = err
			}
			cancel()
		}
	}

	c.mu.Lock()
	c.committer = nil
	c.windows = make(map[topicPartition]*PartitionAckWindow)
	c.partitionEpochs = make(map[topicPartition]uint64)
	c.pending = make(map[topicPartition]*CommitPoint)
	c.deliveries = make(map[topicPartition]map[int64]*kgo.Record)
	c.totalRecords, c.totalBytes = 0, 0
	c.mu.Unlock()
	return result
}

func (c *ExternalAckController) String() string {
	return fmt.Sprintf("external acknowledgment controller %s/%s/%s", c.key.APIID, c.key.StreamID, c.key.ComponentID)
}
