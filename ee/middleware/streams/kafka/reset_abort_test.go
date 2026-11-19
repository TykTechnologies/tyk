package kafka

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type abortTestStore struct {
	*InMemoryResetStateStore
	persistErr error
	renewErr   error
	renews     atomic.Int32
	mu         sync.Mutex
}

func (s *abortTestStore) AcquireExecutionLease(_ context.Context, group, plan, owner string, ttl time.Duration, now time.Time) (ResetExecutionLease, error) {
	return ResetExecutionLease{ConsumerGroup: group, PlanID: plan, Owner: owner, Generation: 1, ExpiresAt: now.Add(ttl)}, nil
}
func (s *abortTestStore) RenewExecutionLease(_ context.Context, lease ResetExecutionLease, _ time.Duration, _ time.Time) (ResetExecutionLease, error) {
	s.renews.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	return lease, s.renewErr
}

func TestResetLeaseKeeperRenewsContinuouslyAndFailsClosed(t *testing.T) {
	store := &abortTestStore{InMemoryResetStateStore: NewInMemoryResetStateStore()}
	lease := ResetExecutionLease{ConsumerGroup: "group", PlanID: "plan", Owner: "owner", Generation: 1}
	ctx, keeper := startResetLeaseKeeper(context.Background(), store, lease, 60*time.Millisecond)
	require.Eventually(t, func() bool { return store.renews.Load() >= 2 }, time.Second, 5*time.Millisecond)
	store.mu.Lock()
	store.renewErr = ErrResetFenced
	store.mu.Unlock()
	require.Eventually(t, func() bool { return context.Cause(ctx) != nil }, time.Second, 5*time.Millisecond)
	require.ErrorIs(t, keeper.stop(), ErrResetFenced)
}

type stuckRenewStore struct {
	*abortTestStore
	started chan struct{}
	release chan struct{}
}

func (s *stuckRenewStore) RenewExecutionLease(context.Context, ResetExecutionLease, time.Duration, time.Time) (ResetExecutionLease, error) {
	select {
	case <-s.started:
	default:
		close(s.started)
	}
	<-s.release // deliberately models a dependency that ignores cancellation
	return ResetExecutionLease{}, context.Canceled
}

func TestResetLeaseKeeperStopIsBoundedWhenRenewIgnoresContext(t *testing.T) {
	store := &stuckRenewStore{
		abortTestStore: &abortTestStore{InMemoryResetStateStore: NewInMemoryResetStateStore()},
		started:        make(chan struct{}), release: make(chan struct{}),
	}
	_, keeper := startResetLeaseKeeper(context.Background(), store, ResetExecutionLease{ConsumerGroup: "group", PlanID: "plan", Owner: "owner", Generation: 1}, 120*time.Millisecond)
	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("renewal did not start")
	}
	started := time.Now()
	err := keeper.stop()
	require.ErrorContains(t, err, "timed out stopping")
	require.Less(t, time.Since(started), 300*time.Millisecond)
	close(store.release)
}

func TestLocalOffsetResetControllerRejectsUnsafeLeaseTTL(t *testing.T) {
	_, admin, _, _ := newResetFixture(t)
	_, err := NewLocalOffsetResetController(LocalOffsetResetControllerConfig{
		ConsumerGroup: "vinci", Topics: []string{"employees.eu"}, Admin: admin, LeaseTTL: time.Millisecond,
	})
	require.ErrorContains(t, err, "at least 100ms")
}
func (s *abortTestStore) PutExecutionFenced(ctx context.Context, _ ResetExecutionLease, execution StoredResetExecution, _ time.Time) error {
	if s.persistErr != nil {
		return s.persistErr
	}
	return s.PutExecution(ctx, execution)
}
func (s *abortTestStore) ReleaseExecutionLease(context.Context, ResetExecutionLease) error {
	return nil
}

type abortTestCoordinator struct {
	quiesces, resumes int
	published         bool
	quiesceErr        error
	cancel            context.CancelFunc
	resumeErr         error
}

func (c *abortTestCoordinator) Quiesce(context.Context, ResetExecutionLease, string, string) (bool, error) {
	c.quiesces++
	if c.cancel != nil {
		c.cancel()
	}
	if c.published || c.quiesceErr != nil {
		return c.published, c.quiesceErr
	}
	return true, nil
}

func TestDistributedResetAbortPreservesCredentialActorAfterRequestCancellation(t *testing.T) {
	controller, _, memory, _ := newResetFixture(t)
	store := &abortTestStore{InMemoryResetStateStore: memory}
	credentialActor := strings.Repeat("a", 64)
	requestCtx, cancel := context.WithCancel(WithResetAuditActorHash(context.Background(), credentialActor))
	coordinator := &abortTestCoordinator{published: true, quiesceErr: errors.New("barrier status unavailable"), cancel: cancel}
	sink := &recordingResetAuditSink{}
	controller.store, controller.coordinator, controller.ownerID = store, coordinator, "owner"
	controller.auditor, controller.requireAudit = sink, true
	controller.auditKey = ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}
	offset := int64(25)
	plan, err := controller.PlanReset(requestCtx, ResetPlanRequest{
		ConsumerGroup: "vinci", Reason: "test",
		Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}},
	})
	require.NoError(t, err)

	_, err = controller.ExecuteReset(requestCtx, ResetExecuteRequest{PlanID: plan.ID})
	require.Error(t, err)
	require.ErrorIs(t, context.Cause(requestCtx), context.Canceled)
	require.Equal(t, 1, coordinator.resumes)
	require.GreaterOrEqual(t, len(sink.events), 2)
	intent, abort := sink.events[len(sink.events)-2], sink.events[len(sink.events)-1]
	require.Equal(t, "abort_resume_requested", intent.Outcome)
	require.Equal(t, "aborted", abort.Outcome)
	require.Equal(t, credentialActor, intent.ActorHash)
	require.Equal(t, credentialActor, abort.ActorHash)
}

func TestDistributedResetAbortResumeIsDurablyOrderedAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name             string
		failAuditOutcome string
		resumeErr        error
		wantResumes      int
		wantLastOutcome  string
		wantError        string
	}{
		{name: "intent audit failure keeps barrier gated", failAuditOutcome: "abort_resume_requested", wantLastOutcome: "abort_resume_requested", wantError: "audit reset abort resume intent"},
		{name: "resume failure remains audited", resumeErr: errors.New("resume unavailable"), wantResumes: 1, wantLastOutcome: "abort_resume_failed", wantError: "resume unavailable"},
		{name: "final audit failure propagates after represented action", failAuditOutcome: "aborted", wantResumes: 1, wantLastOutcome: "aborted", wantError: "audit completed reset abort resume"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller, _, memory, _ := newResetFixture(t)
			store := &abortTestStore{InMemoryResetStateStore: memory}
			coordinator := &abortTestCoordinator{published: true, quiesceErr: errors.New("barrier status unavailable"), resumeErr: tc.resumeErr}
			sink := &outcomeAuditSink{failFor: tc.failAuditOutcome}
			controller.store, controller.coordinator, controller.ownerID = store, coordinator, "owner"
			controller.auditor, controller.requireAudit = sink, true
			controller.auditKey = ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}
			offset := int64(25)
			plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{
				ConsumerGroup: "vinci", Reason: "test",
				Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}},
			})
			require.NoError(t, err)

			_, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
			require.ErrorContains(t, err, tc.wantError)
			require.Equal(t, tc.wantResumes, coordinator.resumes)
			require.NotEmpty(t, sink.events)
			require.Equal(t, tc.wantLastOutcome, sink.events[len(sink.events)-1].Outcome)
			if tc.wantResumes == 1 {
				require.Contains(t, auditOutcomes(sink.events), "abort_resume_requested")
			}
		})
	}
}

func auditOutcomes(events []ResetAuditEvent) []string {
	outcomes := make([]string, len(events))
	for i := range events {
		outcomes[i] = events[i].Outcome
	}
	return outcomes
}

func TestDistributedResetAmbiguousQuiesceFailurePublishesAbortResume(t *testing.T) {
	controller, _, memory, _ := newResetFixture(t)
	store := &abortTestStore{InMemoryResetStateStore: memory}
	coordinator := &abortTestCoordinator{published: true, quiesceErr: errors.New("barrier status unavailable")}
	controller.store, controller.coordinator, controller.ownerID = store, coordinator, "owner"
	offset := int64(25)
	plan, err := controller.PlanReset(context.Background(), ResetPlanRequest{
		ConsumerGroup: "vinci", Reason: "test",
		Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}},
	})
	require.NoError(t, err)

	_, err = controller.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
	require.Error(t, err)
	require.Equal(t, 1, coordinator.quiesces)
	require.Equal(t, 1, coordinator.resumes, "an ambiguously published barrier must be released")
}
func (c *abortTestCoordinator) Resume(context.Context, ResetExecutionLease, string, string) error {
	c.resumes++
	return c.resumeErr
}

type outcomeAuditSink struct {
	events  []ResetAuditEvent
	failFor string
}

func (s *outcomeAuditSink) WriteResetAudit(_ context.Context, event ResetAuditEvent) error {
	s.events = append(s.events, event)
	if event.Outcome == s.failFor {
		return errors.New("audit " + event.Outcome + " failed")
	}
	return nil
}

type failNthAudit struct{ calls, failAt int }

func (a *failNthAudit) WriteResetAudit(context.Context, ResetAuditEvent) error {
	a.calls++
	if a.calls == a.failAt {
		return errors.New("audit failed")
	}
	return nil
}

func TestDistributedResetFailuresPublishAbortResume(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fakeResetAdmin, *abortTestStore, *LocalOffsetResetController)
	}{
		{"group_not_empty", func(a *fakeResetAdmin, _ *abortTestStore, _ *LocalOffsetResetController) {
			a.group = GroupDescription{State: "Stable", Members: []string{"late"}}
		}},
		{"admin_failure", func(a *fakeResetAdmin, _ *abortTestStore, _ *LocalOffsetResetController) {
			a.alterErr = errors.New("admin failed")
		}},
		{"store_failure", func(_ *fakeResetAdmin, s *abortTestStore, _ *LocalOffsetResetController) {
			s.persistErr = errors.New("store failed")
		}},
		{"audit_failure", func(_ *fakeResetAdmin, _ *abortTestStore, c *LocalOffsetResetController) {
			c.auditor = &failNthAudit{failAt: 2}
			c.requireAudit = true
			c.auditKey = ControllerKey{APIID: "api", StreamID: "stream", ComponentID: "input"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, admin, memory, _ := newResetFixture(t)
			store := &abortTestStore{InMemoryResetStateStore: memory}
			coordinator := &abortTestCoordinator{}
			base.store, base.coordinator, base.ownerID = store, coordinator, "owner"
			offset := int64(25)
			plan, err := base.PlanReset(context.Background(), ResetPlanRequest{ConsumerGroup: "vinci", Reason: "test", Targets: []ResetTarget{{Topic: "employees.eu", Partition: 0, Offset: &offset}}})
			require.NoError(t, err)
			tc.mutate(admin, store, base)
			execution, executeErr := base.ExecuteReset(context.Background(), ResetExecuteRequest{PlanID: plan.ID})
			if tc.name == "admin_failure" {
				require.Equal(t, "partial_failed", execution.Status)
			} else {
				require.Error(t, executeErr)
			}
			require.Equal(t, 1, coordinator.quiesces)
			require.Equal(t, 1, coordinator.resumes, "every post-quiesce exit must release distributed gates")
		})
	}
}
