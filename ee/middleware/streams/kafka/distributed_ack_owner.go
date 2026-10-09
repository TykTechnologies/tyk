package kafka

import (
	"context"
	"errors"
	"sync"
	"time"
)

// DistributedAckOwner binds Kafka partition ownership to fenced durable
// acknowledgement consumers. Every partition has an independent route so a
// consumer group may distribute one connector across many gateway instances.
type DistributedAckOwner struct {
	lifecycleMu sync.Mutex
	mu          sync.Mutex
	transport   DurableAckTransport
	key         ControllerKey
	owner       string
	target      AcknowledgmentController
	ctx         context.Context
	cancel      context.CancelFunc
	workers     map[topicPartition]*distributedAckWorker
	pending     map[topicPartition]*distributedAckWorker
	lease       time.Duration
	interval    time.Duration
	batch       int
}

type distributedAckWorker struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func NewDistributedAckOwner(transport DurableAckTransport, key ControllerKey, owner string, target AcknowledgmentController) (*DistributedAckOwner, error) {
	if transport == nil || target == nil || owner == "" {
		return nil, errors.New("distributed acknowledgement owner dependencies are required")
	}
	if err := key.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &DistributedAckOwner{
		transport: transport, key: key, owner: owner, target: target,
		ctx: ctx, cancel: cancel, workers: make(map[topicPartition]*distributedAckWorker), pending: make(map[topicPartition]*distributedAckWorker),
		lease: 30 * time.Second, interval: 100 * time.Millisecond, batch: 128,
	}, nil
}

func (o *DistributedAckOwner) Assign(ctx context.Context, partitions map[string][]int32, identity KafkaGroupIdentity) error {
	o.lifecycleMu.Lock()
	defer o.lifecycleMu.Unlock()
	for topic, values := range partitions {
		for _, partition := range values {
			tp := topicPartition{topic: topic, partition: partition}
			if previous := o.takeWorker(tp); previous != nil {
				previous.cancel()
				if err := waitDistributedAckWorkers(ctx, []*distributedAckWorker{previous}); err != nil {
					return err
				}
			}
			route := AckRoute{Key: o.key, Topic: topic, Partition: partition}
			assignment, err := o.transport.Assign(ctx, route, o.owner, identity)
			if err != nil {
				return err
			}
			workerCtx, cancel := context.WithCancel(o.ctx)
			worker := &distributedAckWorker{cancel: cancel, done: make(chan struct{})}
			o.mu.Lock()
			o.workers[tp] = worker
			o.mu.Unlock()
			consumer := DurableAckConsumer{Transport: o.transport, Assignment: assignment, Consumer: o.owner, Target: o.target, Lease: o.lease, MaxAttempts: 8}
			go o.run(workerCtx, consumer, worker.done)
		}
	}
	return nil
}

// AssignEventually publishes ownership without blocking Kafka's group callback.
// Transient failures are retried with bounded exponential backoff. Revoke and
// close cancel the attempt before it can publish stale ownership locally.
func (o *DistributedAckOwner) AssignEventually(partitions map[string][]int32, identity KafkaGroupIdentity, prepare func(context.Context) error, ready func(map[string][]int32), terminal func(error)) {
	o.lifecycleMu.Lock()
	defer o.lifecycleMu.Unlock()
	for topic, values := range partitions {
		for _, partition := range values {
			tp := topicPartition{topic: topic, partition: partition}
			if previous := o.takeWorker(tp); previous != nil {
				previous.cancel()
			}
			if previous := o.takePending(tp); previous != nil {
				previous.cancel()
			}
			attemptCtx, cancel := context.WithCancel(o.ctx)
			attempt := &distributedAckWorker{cancel: cancel, done: make(chan struct{})}
			o.mu.Lock()
			o.pending[tp] = attempt
			o.mu.Unlock()
			go o.retryAssignment(attemptCtx, attempt, tp, identity, prepare, ready, terminal)
		}
	}
}

func (o *DistributedAckOwner) retryAssignment(ctx context.Context, attempt *distributedAckWorker, tp topicPartition, identity KafkaGroupIdentity, prepare func(context.Context) error, ready func(map[string][]int32), terminal func(error)) {
	defer close(attempt.done)
	delay := 100 * time.Millisecond
	for {
		route := AckRoute{Key: o.key, Topic: tp.topic, Partition: tp.partition}
		var err error
		if prepare != nil {
			err = prepare(ctx)
		}
		var assignment AckAssignment
		if err == nil {
			assignment, err = o.transport.Assign(ctx, route, o.owner, identity)
		}
		if err == nil {
			o.lifecycleMu.Lock()
			workerCtx, cancel := context.WithCancel(o.ctx)
			worker := &distributedAckWorker{cancel: cancel, done: make(chan struct{})}
			o.mu.Lock()
			if o.pending[tp] != attempt || ctx.Err() != nil {
				o.mu.Unlock()
				cancel()
				o.lifecycleMu.Unlock()
				return
			}
			delete(o.pending, tp)
			o.workers[tp] = worker
			o.mu.Unlock()
			consumer := DurableAckConsumer{Transport: o.transport, Assignment: assignment, Consumer: o.owner, Target: o.target, Lease: o.lease, MaxAttempts: 8}
			go o.run(workerCtx, consumer, worker.done)
			if ready != nil {
				ready(map[string][]int32{tp.topic: []int32{tp.partition}})
			}
			o.lifecycleMu.Unlock()
			return
		}
		if errors.Is(err, ErrAckRouteFenced) {
			o.lifecycleMu.Lock()
			o.mu.Lock()
			current := o.pending[tp] == attempt
			if current {
				delete(o.pending, tp)
			}
			o.mu.Unlock()
			if current && terminal != nil {
				terminal(err)
			}
			o.lifecycleMu.Unlock()
			return
		}
		select {
		case <-ctx.Done():
			o.removePending(tp, attempt)
			return
		case <-time.After(delay):
		}
		if delay < 5*time.Second {
			delay *= 2
			if delay > 5*time.Second {
				delay = 5 * time.Second
			}
		}
	}
}

func (o *DistributedAckOwner) removePending(tp topicPartition, attempt *distributedAckWorker) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.pending[tp] == attempt {
		delete(o.pending, tp)
	}
}

func (o *DistributedAckOwner) Revoke(partitions map[string][]int32) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = o.RevokeContext(ctx, partitions)
}

// RevokeContext stops and joins the exact workers for revoked partitions. It
// returns only after no joined worker can call the local controller again.
func (o *DistributedAckOwner) RevokeContext(ctx context.Context, partitions map[string][]int32) error {
	o.lifecycleMu.Lock()
	var workers []*distributedAckWorker
	o.mu.Lock()
	for topic, values := range partitions {
		for _, partition := range values {
			tp := topicPartition{topic: topic, partition: partition}
			if worker := o.workers[tp]; worker != nil {
				worker.cancel()
				workers = append(workers, worker)
				delete(o.workers, tp)
			}
			if attempt := o.pending[tp]; attempt != nil {
				attempt.cancel()
				workers = append(workers, attempt)
				delete(o.pending, tp)
			}
		}
	}
	o.mu.Unlock()
	o.lifecycleMu.Unlock()
	return waitDistributedAckWorkers(ctx, workers)
}

func (o *DistributedAckOwner) takeWorker(tp topicPartition) *distributedAckWorker {
	o.mu.Lock()
	defer o.mu.Unlock()
	worker := o.workers[tp]
	delete(o.workers, tp)
	return worker
}

func (o *DistributedAckOwner) takePending(tp topicPartition) *distributedAckWorker {
	o.mu.Lock()
	defer o.mu.Unlock()
	attempt := o.pending[tp]
	delete(o.pending, tp)
	return attempt
}

func waitDistributedAckWorkers(ctx context.Context, workers []*distributedAckWorker) error {
	for _, worker := range workers {
		select {
		case <-worker.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (o *DistributedAckOwner) run(ctx context.Context, consumer DurableAckConsumer, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		now := time.Now()
		heartbeatErr := consumer.Transport.Heartbeat(ctx, consumer.Assignment, now, o.lease)
		if errors.Is(heartbeatErr, ErrAckRouteFenced) || errors.Is(heartbeatErr, context.Canceled) {
			return
		}
		var err error
		if heartbeatErr == nil {
			_, err = consumer.Process(ctx, o.batch, now)
		}
		if errors.Is(err, ErrAckRouteFenced) || errors.Is(err, context.Canceled) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (o *DistributedAckOwner) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = o.CloseContext(ctx)
}

// CloseContext cancels ownership and joins all partition workers within ctx.
func (o *DistributedAckOwner) CloseContext(ctx context.Context) error {
	o.cancel()
	o.lifecycleMu.Lock()
	var workers []*distributedAckWorker
	o.mu.Lock()
	for tp, worker := range o.workers {
		worker.cancel()
		workers = append(workers, worker)
		delete(o.workers, tp)
	}
	for tp, attempt := range o.pending {
		attempt.cancel()
		workers = append(workers, attempt)
		delete(o.pending, tp)
	}
	o.mu.Unlock()
	o.lifecycleMu.Unlock()
	return waitDistributedAckWorkers(ctx, workers)
}
