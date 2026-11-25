package kafka

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type TopicPartition struct {
	Topic     string
	Partition int32
}

type GroupDescription struct {
	State   string
	Members []string
}

type LogBounds struct {
	Start int64
	End   int64
}

type TimestampOffset struct {
	Offset int64
	Found  bool
}

// OffsetResetAdmin is the narrow administrative surface required by the reset
// controller. A franz-go/kadm adapter can implement it without exposing either
// client to HTTP handlers.
type OffsetResetAdmin interface {
	DescribeGroup(context.Context, string) (GroupDescription, error)
	FetchGroupOffsets(context.Context, string, []TopicPartition) (map[TopicPartition]int64, error)
	FetchLogBounds(context.Context, []TopicPartition) (map[TopicPartition]LogBounds, error)
	ResolveTimestamps(context.Context, map[TopicPartition]int64) (map[TopicPartition]TimestampOffset, error)
	AlterGroupOffsets(context.Context, string, map[TopicPartition]int64) (map[TopicPartition]error, error)
}

type ResetTargetState struct {
	Target   ResolvedResetTarget
	Applied  bool
	Verified bool
	Failed   bool
}

type StoredResetPlan struct {
	Plan          ResetPlan
	ConsumerGroup string
	Reason        string
	Targets       []ResolvedResetTarget
}

type StoredResetExecution struct {
	Execution ResetExecution
	PlanID    string
	Targets   []ResetTargetState
}

// ResetStateStore is intentionally persistence-shaped. The local controller
// ships with an in-memory implementation; a durable control-plane store can be
// substituted without changing the controller or HTTP API.
type ResetStateStore interface {
	PutPlan(context.Context, StoredResetPlan) error
	GetPlan(context.Context, string) (StoredResetPlan, bool, error)
	PutExecution(context.Context, StoredResetExecution) error
	GetExecution(context.Context, string) (StoredResetExecution, bool, error)
}

type InMemoryResetStateStore struct {
	mu         sync.RWMutex
	plans      map[string]StoredResetPlan
	executions map[string]StoredResetExecution
}

func NewInMemoryResetStateStore() *InMemoryResetStateStore {
	return &InMemoryResetStateStore{
		plans:      make(map[string]StoredResetPlan),
		executions: make(map[string]StoredResetExecution),
	}
}

func (s *InMemoryResetStateStore) PutPlan(_ context.Context, plan StoredResetPlan) error {
	s.mu.Lock()
	s.plans[plan.Plan.ID] = cloneStoredPlan(plan)
	s.mu.Unlock()
	return nil
}

func (s *InMemoryResetStateStore) GetPlan(_ context.Context, id string) (StoredResetPlan, bool, error) {
	s.mu.RLock()
	plan, ok := s.plans[id]
	s.mu.RUnlock()
	return cloneStoredPlan(plan), ok, nil
}

func (s *InMemoryResetStateStore) PutExecution(_ context.Context, execution StoredResetExecution) error {
	s.mu.Lock()
	s.executions[execution.PlanID] = cloneStoredExecution(execution)
	s.mu.Unlock()
	return nil
}

func (s *InMemoryResetStateStore) GetExecution(_ context.Context, planID string) (StoredResetExecution, bool, error) {
	s.mu.RLock()
	execution, ok := s.executions[planID]
	s.mu.RUnlock()
	return cloneStoredExecution(execution), ok, nil
}

func cloneStoredPlan(plan StoredResetPlan) StoredResetPlan {
	plan.Targets = append([]ResolvedResetTarget(nil), plan.Targets...)
	plan.Plan.Targets = append([]ResolvedResetTarget(nil), plan.Plan.Targets...)
	return plan
}

func cloneStoredExecution(execution StoredResetExecution) StoredResetExecution {
	execution.Targets = append([]ResetTargetState(nil), execution.Targets...)
	return execution
}

type LocalOffsetResetControllerConfig struct {
	ConsumerGroup   string
	Topics          []string
	PlanTTL         time.Duration
	Admin           OffsetResetAdmin
	Store           ResetStateStore
	Now             func() time.Time
	AllowActivePlan bool
	LeaseTTL        time.Duration
	OwnerID         string
	Coordinator     ResetExecutionCoordinator
	Auditor         DurableResetAuditSink
	AuditKey        ControllerKey
	RequireAudit    bool
}

type ResetExecutionCoordinator interface {
	Quiesce(context.Context, ResetExecutionLease, string, string) (bool, error)
	Resume(context.Context, ResetExecutionLease, string, string) error
}

// LocalOffsetResetController is safe for one exclusive Tyk owner. It refuses
// to alter offsets unless Kafka reports an empty group. Multi-gateway barriers,
// leases, and fencing belong in a distributed controller implementation.
type LocalOffsetResetController struct {
	consumerGroup   string
	topics          map[string]struct{}
	planTTL         time.Duration
	admin           OffsetResetAdmin
	store           ResetStateStore
	now             func() time.Time
	allowActivePlan bool
	leaseTTL        time.Duration
	ownerID         string
	coordinator     ResetExecutionCoordinator
	auditor         DurableResetAuditSink
	auditKey        ControllerKey
	requireAudit    bool
	mu              sync.Mutex
}

type resetLeaseKeeper struct {
	cancel      context.CancelCauseFunc
	done        chan struct{}
	stopTimeout time.Duration
	mu          sync.Mutex
	err         error
}

func startResetLeaseKeeper(parent context.Context, store FencedResetStateStore, lease ResetExecutionLease, ttl time.Duration) (context.Context, *resetLeaseKeeper) {
	ctx, cancel := context.WithCancelCause(parent)
	interval := ttl / 3
	if interval <= 0 {
		interval = time.Millisecond
	}
	stopTimeout := ttl / 2
	if stopTimeout < 100*time.Millisecond {
		stopTimeout = 100 * time.Millisecond
	}
	k := &resetLeaseKeeper{cancel: cancel, done: make(chan struct{}), stopTimeout: stopTimeout}
	go func() {
		defer close(k.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		current := lease
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(ctx, ttl/4)
				renewed, err := store.RenewExecutionLease(renewCtx, current, ttl, time.Now().UTC())
				renewCancel()
				if err != nil {
					k.mu.Lock()
					k.err = err
					k.mu.Unlock()
					cancel(err)
					return
				}
				current = renewed
			}
		}
	}()
	return ctx, k
}

func (k *resetLeaseKeeper) stop() error {
	k.cancel(context.Canceled)
	select {
	case <-k.done:
	case <-time.After(k.stopTimeout):
		return errors.New("timed out stopping reset lease keeper")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.err
}

func boundedResetOperationContext(parent context.Context, ttl time.Duration) (context.Context, context.CancelFunc) {
	limit := ttl / 2
	if limit <= 0 {
		limit = time.Second
	}
	return context.WithTimeout(parent, limit)
}

var _ OffsetController = (*LocalOffsetResetController)(nil)

func NewLocalOffsetResetController(config LocalOffsetResetControllerConfig) (*LocalOffsetResetController, error) {
	if strings.TrimSpace(config.ConsumerGroup) == "" || len(config.Topics) == 0 || config.Admin == nil {
		return nil, errors.New("consumer group, topics, and admin are required")
	}
	if config.PlanTTL <= 0 {
		config.PlanTTL = 5 * time.Minute
	}
	if config.Store == nil {
		config.Store = NewInMemoryResetStateStore()
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.LeaseTTL <= 0 {
		config.LeaseTTL = 30 * time.Second
	} else if config.LeaseTTL < 100*time.Millisecond {
		return nil, errors.New("reset lease TTL must be at least 100ms")
	}
	if config.OwnerID == "" {
		var err error
		config.OwnerID, err = randomID()
		if err != nil {
			return nil, err
		}
	}
	topics := make(map[string]struct{}, len(config.Topics))
	for _, topic := range config.Topics {
		if strings.TrimSpace(topic) == "" {
			return nil, errors.New("configured topic is empty")
		}
		topics[topic] = struct{}{}
	}
	return &LocalOffsetResetController{
		consumerGroup:   config.ConsumerGroup,
		topics:          topics,
		planTTL:         config.PlanTTL,
		admin:           config.Admin,
		store:           config.Store,
		now:             config.Now,
		allowActivePlan: config.AllowActivePlan,
		leaseTTL:        config.LeaseTTL, ownerID: config.OwnerID, coordinator: config.Coordinator,
		auditor: config.Auditor, auditKey: config.AuditKey, requireAudit: config.RequireAudit,
	}, nil
}

func (c *LocalOffsetResetController) PlanReset(ctx context.Context, request ResetPlanRequest) (ResetPlan, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.validateRequest(request); err != nil {
		return ResetPlan{}, controlError(http.StatusBadRequest, err)
	}
	if !c.allowActivePlan {
		if err := c.requireEmptyGroup(ctx); err != nil {
			return ResetPlan{}, err
		}
	}
	partitions := make([]TopicPartition, 0, len(request.Targets))
	timestamps := make(map[TopicPartition]int64)
	for _, target := range request.Targets {
		partition := TopicPartition{Topic: target.Topic, Partition: target.Partition}
		partitions = append(partitions, partition)
		if target.TimestampMS != nil {
			timestamps[partition] = *target.TimestampMS
		}
	}
	bounds, err := c.admin.FetchLogBounds(ctx, partitions)
	if err != nil {
		return ResetPlan{}, controlError(http.StatusServiceUnavailable, err)
	}
	resolvedTimestamps := map[TopicPartition]TimestampOffset{}
	if len(timestamps) > 0 {
		resolvedTimestamps, err = c.admin.ResolveTimestamps(ctx, timestamps)
		if err != nil {
			return ResetPlan{}, controlError(http.StatusServiceUnavailable, err)
		}
	}
	current, err := c.admin.FetchGroupOffsets(ctx, c.consumerGroup, partitions)
	if err != nil {
		return ResetPlan{}, controlError(http.StatusServiceUnavailable, err)
	}

	resolved := make([]ResolvedResetTarget, 0, len(request.Targets))
	for _, target := range request.Targets {
		partition := TopicPartition{Topic: target.Topic, Partition: target.Partition}
		bound, ok := bounds[partition]
		if !ok || bound.Start < 0 || bound.End < bound.Start {
			return ResetPlan{}, controlError(http.StatusBadRequest, errors.New("log bounds unavailable"))
		}
		var offset int64
		if target.Offset != nil {
			offset = *target.Offset
		} else {
			lookup, ok := resolvedTimestamps[partition]
			if !ok || !lookup.Found {
				return ResetPlan{}, controlError(http.StatusBadRequest, errors.New("timestamp has no offset"))
			}
			offset = lookup.Offset
		}
		// End is a valid committed next-offset; anything outside the retained
		// log is rejected rather than relying on auto.offset.reset.
		if offset < bound.Start || offset > bound.End {
			return ResetPlan{}, controlError(http.StatusBadRequest, errors.New("target outside log bounds"))
		}
		currentOffset := int64(-1)
		if value, exists := current[partition]; exists {
			currentOffset = value
		}
		resolved = append(resolved, ResolvedResetTarget{
			Topic: target.Topic, Partition: target.Partition,
			CurrentOffset: currentOffset, TargetOffset: offset,
		})
	}
	sort.Slice(resolved, func(i, j int) bool {
		if resolved[i].Topic == resolved[j].Topic {
			return resolved[i].Partition < resolved[j].Partition
		}
		return resolved[i].Topic < resolved[j].Topic
	})
	id, err := randomID()
	if err != nil {
		return ResetPlan{}, controlError(http.StatusInternalServerError, err)
	}
	plan := ResetPlan{ID: id, ExpiresAt: c.now().Add(c.planTTL), Targets: append([]ResolvedResetTarget(nil), resolved...)}
	if err := c.store.PutPlan(ctx, StoredResetPlan{Plan: plan, ConsumerGroup: c.consumerGroup, Reason: request.Reason, Targets: resolved}); err != nil {
		return ResetPlan{}, controlError(http.StatusServiceUnavailable, err)
	}
	if err := c.writeAudit(ctx, ResetAuditEvent{Time: c.now(), CorrelationID: plan.ID, Reason: request.Reason, PlanID: plan.ID, Outcome: "planned"}); err != nil {
		return ResetPlan{}, controlError(http.StatusServiceUnavailable, err)
	}
	return plan, nil
}

func (c *LocalOffsetResetController) ExecuteReset(ctx context.Context, request ResetExecuteRequest) (result ResetExecution, resultErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.TrimSpace(request.PlanID) == "" {
		return ResetExecution{}, controlError(http.StatusBadRequest, errors.New("plan id required"))
	}
	existing, executionExists, err := c.store.GetExecution(ctx, request.PlanID)
	if err != nil {
		return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
	} else if executionExists && existing.Execution.Status == "completed" && c.coordinator == nil {
		return existing.Execution, nil
	}
	storedPlan, ok, err := c.store.GetPlan(ctx, request.PlanID)
	if err != nil {
		return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
	}
	if !ok || storedPlan.ConsumerGroup != c.consumerGroup {
		return ResetExecution{}, controlError(http.StatusNotFound, errors.New("plan not found"))
	}
	if !c.now().Before(storedPlan.Plan.ExpiresAt) {
		return ResetExecution{}, controlError(http.StatusGone, errors.New("plan expired"))
	}
	var lease *ResetExecutionLease
	releaseLease := true
	if fenced, ok := c.store.(FencedResetStateStore); ok {
		acquired, leaseErr := fenced.AcquireExecutionLease(ctx, c.consumerGroup, request.PlanID, c.ownerID, c.leaseTTL, c.now())
		if leaseErr != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(leaseErr, ErrResetLeaseHeld) || errors.Is(leaseErr, ErrResetFenced) {
				status = http.StatusConflict
			}
			return ResetExecution{}, controlError(status, leaseErr)
		}
		lease = &acquired
		defer func() {
			if !releaseLease {
				return
			}
			releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = fenced.ReleaseExecutionLease(releaseCtx, *lease)
		}()
		var keeper *resetLeaseKeeper
		ctx, keeper = startResetLeaseKeeper(ctx, fenced, acquired, c.leaseTTL)
		defer func() {
			if keepErr := keeper.stop(); keepErr != nil && resultErr == nil {
				resultErr = controlError(http.StatusConflict, fmt.Errorf("reset execution lease renewal failed: %w", keepErr))
			}
		}()
	}
	quiesced, resumed := false, false
	defer func() {
		if !quiesced || resumed {
			return
		}
		resumeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		setAbortErr := func(err error) {
			if resultErr != nil {
				resultErr = controlError(http.StatusServiceUnavailable, errors.Join(resultErr, err))
				return
			}
			resultErr = controlError(http.StatusServiceUnavailable, err)
		}
		baseAudit := ResetAuditEvent{Time: c.now(), CorrelationID: request.PlanID, Reason: storedPlan.Reason, PlanID: request.PlanID, ExecutionID: result.ID}
		intent := baseAudit
		intent.Outcome = "abort_resume_requested"
		if err := c.writeAudit(resumeCtx, intent); err != nil {
			// Keep consumers gated when the resume side effect cannot first be
			// represented durably.
			setAbortErr(fmt.Errorf("audit reset abort resume intent: %w", err))
			return
		}
		if err := c.coordinator.Resume(resumeCtx, *lease, c.consumerGroup, "abort-"+request.PlanID); err != nil {
			failed := baseAudit
			failed.Outcome = "abort_resume_failed"
			if auditErr := c.writeAudit(resumeCtx, failed); auditErr != nil {
				setAbortErr(fmt.Errorf("publish reset abort resume: %w", errors.Join(err, fmt.Errorf("audit resume failure: %w", auditErr))))
			} else {
				setAbortErr(fmt.Errorf("publish reset abort resume: %w", err))
			}
			return
		}
		completed := baseAudit
		completed.Outcome = "aborted"
		if err := c.writeAudit(resumeCtx, completed); err != nil {
			setAbortErr(fmt.Errorf("audit completed reset abort resume: %w", err))
		}
	}()
	if lease != nil && c.coordinator != nil {
		published, err := c.coordinator.Quiesce(ctx, *lease, c.consumerGroup, request.PlanID)
		if published {
			quiesced = true // A durable barrier exists and every exit must publish resume.
		}
		if err != nil {
			if errors.Is(err, ErrResetBarrierAmbiguous) {
				releaseLease = false
			}
			if auditErr := c.writeAudit(ctx, ResetAuditEvent{Time: c.now(), CorrelationID: request.PlanID, Reason: storedPlan.Reason, PlanID: request.PlanID, Outcome: "quiesce_failed"}); auditErr != nil {
				return ResetExecution{}, controlError(http.StatusServiceUnavailable, auditErr)
			}
			return ResetExecution{}, controlError(http.StatusConflict, err)
		}
		quiesced = true
		if err := c.writeAudit(ctx, ResetAuditEvent{Time: c.now(), CorrelationID: request.PlanID, Reason: storedPlan.Reason, PlanID: request.PlanID, Outcome: "quiesced"}); err != nil {
			return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
		}
	}
	if err := c.requireEmptyGroup(ctx); err != nil {
		return ResetExecution{}, err
	}

	execution := existing
	if !executionExists {
		executionID, err := randomID()
		if err != nil {
			return ResetExecution{}, controlError(http.StatusInternalServerError, err)
		}
		execution = StoredResetExecution{
			Execution: ResetExecution{ID: executionID, Status: "running"}, PlanID: request.PlanID,
			Targets: make([]ResetTargetState, len(storedPlan.Targets)),
		}
		for i, target := range storedPlan.Targets {
			execution.Targets[i].Target = target
		}
		if err := c.persistExecution(ctx, lease, execution); err != nil {
			return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
		}
	}

	desired := make(map[TopicPartition]int64, len(execution.Targets))
	for _, target := range execution.Targets {
		if !target.Applied {
			desired[TopicPartition{Topic: target.Target.Topic, Partition: target.Target.Partition}] = target.Target.TargetOffset
		}
	}
	if len(desired) > 0 {
		if err := resetExecutionActive(ctx); err != nil {
			return ResetExecution{}, err
		}
		if err := c.renewExecutionLease(ctx, lease); err != nil {
			return ResetExecution{}, controlError(http.StatusConflict, err)
		}
		adminCtx, adminCancel := boundedResetOperationContext(ctx, c.leaseTTL)
		perTargetErrors, alterErr := c.admin.AlterGroupOffsets(adminCtx, c.consumerGroup, desired)
		adminCancel()
		for i := range execution.Targets {
			partition := TopicPartition{Topic: execution.Targets[i].Target.Topic, Partition: execution.Targets[i].Target.Partition}
			if _, pending := desired[partition]; !pending {
				continue
			}
			targetErr, reported := perTargetErrors[partition]
			execution.Targets[i].Applied = alterErr == nil && reported && targetErr == nil
			execution.Targets[i].Failed = !execution.Targets[i].Applied
		}
	}
	if err := c.persistExecution(ctx, lease, execution); err != nil {
		return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
	}

	verifyTargets := make(map[TopicPartition]int64, len(execution.Targets))
	for _, target := range execution.Targets {
		if target.Applied && !target.Verified {
			verifyTargets[TopicPartition{Topic: target.Target.Topic, Partition: target.Target.Partition}] = target.Target.TargetOffset
		}
	}
	verifyCtx, verifyCancel := boundedResetOperationContext(ctx, c.leaseTTL)
	verifiedOffsets, verifyErr := c.admin.FetchGroupOffsets(verifyCtx, c.consumerGroup, keys(verifyTargets))
	verifyCancel()
	for i := range execution.Targets {
		if !execution.Targets[i].Applied || execution.Targets[i].Verified || verifyErr != nil {
			continue
		}
		partition := TopicPartition{Topic: execution.Targets[i].Target.Topic, Partition: execution.Targets[i].Target.Partition}
		verifiedOffset, reported := verifiedOffsets[partition]
		execution.Targets[i].Verified = reported && verifiedOffset == execution.Targets[i].Target.TargetOffset
		execution.Targets[i].Failed = !execution.Targets[i].Verified
	}
	execution.Execution.Status = "completed"
	for _, target := range execution.Targets {
		if target.Failed || !target.Verified {
			execution.Execution.Status = "partial_failed"
			break
		}
	}
	if err := c.persistExecution(ctx, lease, execution); err != nil {
		return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
	}
	if err := c.writeAudit(ctx, ResetAuditEvent{Time: c.now(), CorrelationID: request.PlanID, Reason: storedPlan.Reason, PlanID: request.PlanID, ExecutionID: execution.Execution.ID, Outcome: execution.Execution.Status, Targets: execution.Targets}); err != nil {
		return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
	}
	if execution.Execution.Status == "completed" && lease != nil && c.coordinator != nil {
		if err := resetExecutionActive(ctx); err != nil {
			return ResetExecution{}, err
		}
		replayID, replayErr := randomID()
		if replayErr != nil {
			return ResetExecution{}, controlError(http.StatusInternalServerError, replayErr)
		}
		if err := c.coordinator.Resume(ctx, *lease, c.consumerGroup, replayID); err != nil {
			if auditErr := c.writeAudit(ctx, ResetAuditEvent{Time: c.now(), CorrelationID: request.PlanID, Reason: storedPlan.Reason, PlanID: request.PlanID, ExecutionID: execution.Execution.ID, Outcome: "resume_failed", Targets: execution.Targets}); auditErr != nil {
				return ResetExecution{}, controlError(http.StatusServiceUnavailable, auditErr)
			}
			return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
		}
		resumed = true
		if err := c.writeAudit(ctx, ResetAuditEvent{Time: c.now(), CorrelationID: request.PlanID, Reason: storedPlan.Reason, PlanID: request.PlanID, ExecutionID: execution.Execution.ID, Outcome: "resumed", Targets: execution.Targets}); err != nil {
			return ResetExecution{}, controlError(http.StatusServiceUnavailable, err)
		}
	}
	return execution.Execution, nil
}

func resetExecutionActive(ctx context.Context) error {
	if err := context.Cause(ctx); err != nil {
		return controlError(http.StatusConflict, fmt.Errorf("reset execution is no longer fenced: %w", err))
	}
	return nil
}

func (c *LocalOffsetResetController) writeAudit(ctx context.Context, event ResetAuditEvent) error {
	if c.auditor == nil {
		if c.requireAudit {
			return errors.New("durable Kafka reset audit sink is unavailable")
		}
		return nil
	}
	event.APIID, event.StreamID, event.ComponentID = c.auditKey.APIID, c.auditKey.StreamID, c.auditKey.ComponentID
	event.ConsumerGroupHash, event.ActorHash = hashStatusIdentity(c.consumerGroup), resetAuditActorHash(ctx)
	if err := event.Validate(); err != nil {
		return err
	}
	return c.auditor.WriteResetAudit(ctx, event)
}

func (c *LocalOffsetResetController) renewExecutionLease(ctx context.Context, lease *ResetExecutionLease) error {
	if lease == nil {
		return nil
	}
	fenced := c.store.(FencedResetStateStore)
	renewed, err := fenced.RenewExecutionLease(ctx, *lease, c.leaseTTL, c.now())
	if err == nil {
		*lease = renewed
	}
	return err
}

func (c *LocalOffsetResetController) persistExecution(ctx context.Context, lease *ResetExecutionLease, execution StoredResetExecution) error {
	if lease == nil {
		return c.store.PutExecution(ctx, execution)
	}
	return c.store.(FencedResetStateStore).PutExecutionFenced(ctx, *lease, execution, c.now())
}

func (c *LocalOffsetResetController) validateRequest(request ResetPlanRequest) error {
	if request.ConsumerGroup != c.consumerGroup {
		return errors.New("consumer group is not configured for this input")
	}
	if strings.TrimSpace(request.Reason) == "" || len(request.Targets) == 0 {
		return errors.New("reason and targets are required")
	}
	seen := make(map[TopicPartition]struct{}, len(request.Targets))
	for _, target := range request.Targets {
		if _, ok := c.topics[target.Topic]; !ok || target.Partition < 0 || (target.Offset == nil) == (target.TimestampMS == nil) {
			return errors.New("invalid reset target")
		}
		if target.Offset != nil && *target.Offset < 0 || target.TimestampMS != nil && *target.TimestampMS < 0 {
			return errors.New("negative target")
		}
		partition := TopicPartition{Topic: target.Topic, Partition: target.Partition}
		if _, ok := seen[partition]; ok {
			return errors.New("duplicate reset target")
		}
		seen[partition] = struct{}{}
	}
	return nil
}

func (c *LocalOffsetResetController) requireEmptyGroup(ctx context.Context) error {
	description, err := c.admin.DescribeGroup(ctx, c.consumerGroup)
	if err != nil {
		return controlError(http.StatusServiceUnavailable, err)
	}
	if len(description.Members) != 0 || !strings.EqualFold(description.State, "empty") {
		return controlError(http.StatusConflict, errors.New("consumer group is active"))
	}
	return nil
}

func keys(offsets map[TopicPartition]int64) []TopicPartition {
	result := make([]TopicPartition, 0, len(offsets))
	for partition := range offsets {
		result = append(result, partition)
	}
	return result
}

func controlError(status int, err error) error {
	return &ControlError{Status: status, Err: err}
}

func randomID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
