package kafka

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type retryAssignTransport struct {
	DurableAckTransport
	failures atomic.Int32
	calls    atomic.Int32
	entered  chan struct{}
}

func (t *retryAssignTransport) Assign(ctx context.Context, route AckRoute, owner string, identity KafkaGroupIdentity) (AckAssignment, error) {
	t.calls.Add(1)
	if t.entered != nil {
		select {
		case t.entered <- struct{}{}:
		default:
		}
	}
	if t.failures.Add(-1) >= 0 {
		return AckAssignment{}, errors.New("temporary Redis outage")
	}
	return t.DurableAckTransport.Assign(ctx, route, owner, identity)
}

type cancelAwareAckTarget struct {
	started chan struct{}
	exited  chan struct{}
	calls   atomic.Int32
}

type gatedAssignTransport struct {
	DurableAckTransport
	entered chan struct{}
	release chan struct{}
}

func (t *gatedAssignTransport) Assign(ctx context.Context, route AckRoute, owner string, identity KafkaGroupIdentity) (AckAssignment, error) {
	close(t.entered)
	select {
	case <-t.release:
	case <-ctx.Done():
		return AckAssignment{}, ctx.Err()
	}
	return t.DurableAckTransport.Assign(ctx, route, owner, identity)
}

func (t *cancelAwareAckTarget) Acknowledge(ctx context.Context, _ []string) ([]AckResult, error) {
	t.calls.Add(1)
	select {
	case <-t.started:
	default:
		close(t.started)
	}
	<-ctx.Done()
	select {
	case <-t.exited:
	default:
		close(t.exited)
	}
	return nil, ctx.Err()
}

func TestDistributedAckOwnerRevokeJoinsPartitionWorker(t *testing.T) {
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	key := testAckRoute().Key
	target := &cancelAwareAckTarget{started: make(chan struct{}), exited: make(chan struct{})}
	owner, err := NewDistributedAckOwner(transport, key, "owner", target)
	require.NoError(t, err)
	owner.interval = time.Millisecond
	route := AckRoute{Key: key, Topic: "topic", Partition: 0}
	require.NoError(t, owner.Assign(context.Background(), map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"}))
	require.NoError(t, transport.AppendBatch(context.Background(), []AckCommand{{ID: "one", Route: route, Token: "token", AppendedAt: time.Now()}}))
	require.Eventually(t, func() bool {
		select {
		case <-target.started:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, owner.RevokeContext(ctx, map[string][]int32{"topic": {0}}))
	select {
	case <-target.exited:
	default:
		t.Fatal("revoke returned before the partition worker exited")
	}
	owner.Close()
}

func TestDistributedAckOwnerCloseJoinsAllWorkers(t *testing.T) {
	transport := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	key := testAckRoute().Key
	target := &cancelAwareAckTarget{started: make(chan struct{}), exited: make(chan struct{})}
	owner, err := NewDistributedAckOwner(transport, key, "owner", target)
	require.NoError(t, err)
	owner.interval = time.Millisecond
	route := AckRoute{Key: key, Topic: "topic", Partition: 0}
	require.NoError(t, owner.Assign(context.Background(), map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"}))
	require.NoError(t, transport.AppendBatch(context.Background(), []AckCommand{{ID: "one", Route: route, Token: "token", AppendedAt: time.Now()}}))
	require.Eventually(t, func() bool { return target.calls.Load() > 0 }, time.Second, time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, owner.CloseContext(ctx))
	select {
	case <-target.exited:
	default:
		t.Fatal("close returned before the partition worker exited")
	}
}

func TestDistributedAckOwnerConcurrentAssignAndRevokeLeavesNoWorker(t *testing.T) {
	base := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	transport := &gatedAssignTransport{DurableAckTransport: base, entered: make(chan struct{}), release: make(chan struct{})}
	owner, err := NewDistributedAckOwner(transport, testAckRoute().Key, "owner", &fakeAckController{})
	require.NoError(t, err)
	assignDone := make(chan error, 1)
	go func() {
		assignDone <- owner.Assign(context.Background(), map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"})
	}()
	<-transport.entered
	revokeDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		revokeDone <- owner.RevokeContext(ctx, map[string][]int32{"topic": {0}})
	}()
	close(transport.release)
	require.NoError(t, <-assignDone)
	require.NoError(t, <-revokeDone)
	owner.mu.Lock()
	require.Empty(t, owner.workers)
	owner.mu.Unlock()
	owner.Close()
}

func TestDistributedAckOwnerRetriesTransientAssignment(t *testing.T) {
	base := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	transport := &retryAssignTransport{DurableAckTransport: base}
	transport.failures.Store(2)
	owner, err := NewDistributedAckOwner(transport, testAckRoute().Key, "owner", &fakeAckController{})
	require.NoError(t, err)
	ready := make(chan map[string][]int32, 1)
	terminal := make(chan error, 1)
	owner.AssignEventually(map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"}, nil, func(partitions map[string][]int32) {
		ready <- partitions
	}, func(err error) { terminal <- err })
	select {
	case partitions := <-ready:
		require.Equal(t, map[string][]int32{"topic": {0}}, partitions)
	case <-time.After(2 * time.Second):
		t.Fatal("ownership publication did not recover")
	}
	require.Equal(t, int32(3), transport.calls.Load())
	select {
	case err := <-terminal:
		t.Fatalf("transient error was treated as terminal: %v", err)
	default:
	}
	owner.Close()
}

func TestDistributedAckOwnerRevokeCancelsAssignmentRetry(t *testing.T) {
	base := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	transport := &retryAssignTransport{DurableAckTransport: base, entered: make(chan struct{}, 1)}
	transport.failures.Store(100)
	owner, err := NewDistributedAckOwner(transport, testAckRoute().Key, "owner", &fakeAckController{})
	require.NoError(t, err)
	ready := make(chan struct{}, 1)
	owner.AssignEventually(map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"}, nil, func(map[string][]int32) {
		ready <- struct{}{}
	}, nil)
	<-transport.entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, owner.RevokeContext(ctx, map[string][]int32{"topic": {0}}))
	calls := transport.calls.Load()
	time.Sleep(250 * time.Millisecond)
	require.Equal(t, calls, transport.calls.Load(), "revoked assignment continued retrying")
	select {
	case <-ready:
		t.Fatal("revoked assignment published stale ownership")
	default:
	}
	owner.Close()
}

func TestDistributedAckOwnerTerminalFenceDoesNotRetry(t *testing.T) {
	transport := &fencedAssignTransport{DurableAckTransport: NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})}
	owner, err := NewDistributedAckOwner(transport, testAckRoute().Key, "owner", &fakeAckController{})
	require.NoError(t, err)
	terminal := make(chan error, 1)
	owner.AssignEventually(map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"}, nil, nil, func(err error) { terminal <- err })
	select {
	case err := <-terminal:
		require.ErrorIs(t, err, ErrAckRouteFenced)
	case <-time.After(time.Second):
		t.Fatal("terminal fencing was not reported")
	}
	require.Equal(t, int32(1), transport.calls.Load())
	owner.Close()
}

func TestDistributedAckOwnerRetriesIdentityPreparation(t *testing.T) {
	base := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	transport := &retryAssignTransport{DurableAckTransport: base}
	owner, err := NewDistributedAckOwner(transport, testAckRoute().Key, "owner", &fakeAckController{})
	require.NoError(t, err)
	var prepares atomic.Int32
	ready := make(chan struct{}, 1)
	owner.AssignEventually(map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"}, func(context.Context) error {
		if prepares.Add(1) < 3 {
			return errors.New("temporary Kafka metadata error")
		}
		return nil
	}, func(map[string][]int32) { ready <- struct{}{} }, nil)
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("identity preparation did not recover")
	}
	require.Equal(t, int32(3), prepares.Load())
	require.Equal(t, int32(1), transport.calls.Load(), "ownership must publish only after identity preparation")
	owner.Close()
}

func TestDistributedAckOwnerRevokeDoesNotDeadlockWithRetryCompletion(t *testing.T) {
	base := NewInMemoryDurableAckTransport(InMemoryDurableAckOptions{})
	transport := &gatedAssignTransport{DurableAckTransport: base, entered: make(chan struct{}), release: make(chan struct{})}
	owner, err := NewDistributedAckOwner(transport, testAckRoute().Key, "owner", &fakeAckController{})
	require.NoError(t, err)
	owner.AssignEventually(map[string][]int32{"topic": {0}}, KafkaGroupIdentity{Generation: 1, MemberID: "member"}, nil, nil, nil)
	<-transport.entered
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done <- owner.RevokeContext(ctx, map[string][]int32{"topic": {0}})
	}()
	close(transport.release)
	require.NoError(t, <-done)
	owner.Close()
}

type fencedAssignTransport struct {
	DurableAckTransport
	calls atomic.Int32
}

func (t *fencedAssignTransport) Assign(context.Context, AckRoute, string, KafkaGroupIdentity) (AckAssignment, error) {
	t.calls.Add(1)
	return AckAssignment{}, ErrAckRouteFenced
}
