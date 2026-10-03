package kafka

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrLocalSingletonHeld = errors.New("local Kafka acknowledgment component is active on another gateway")

// LocalSingletonLease prevents routing:local from running concurrently on
// multiple gateways. It borrows the Gateway-managed Redis client.
type LocalSingletonLease struct {
	client     redis.UniversalClient
	key, owner string
	ttl        time.Duration
	cancel     context.CancelFunc
	done       chan struct{}
	once       sync.Once
}

func AcquireLocalSingletonLease(ctx context.Context, client redis.UniversalClient, componentID string, ttl time.Duration) (*LocalSingletonLease, error) {
	if client == nil || componentID == "" || ttl <= 0 {
		return nil, errors.New("complete local singleton lease configuration is required")
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	owner := hex.EncodeToString(b)
	key := fmt.Sprintf("tyk:kafka:local-singleton:{%s}", componentID)
	ok, err := client.SetNX(ctx, key, owner, ttl).Result()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrLocalSingletonHeld
	}
	runCtx, cancel := context.WithCancel(context.Background())
	l := &LocalSingletonLease{client: client, key: key, owner: owner, ttl: ttl, cancel: cancel, done: make(chan struct{})}
	go l.heartbeat(runCtx)
	return l, nil
}

func (l *LocalSingletonLease) heartbeat(ctx context.Context) {
	defer close(l.done)
	ticker := time.NewTicker(l.ttl / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = l.client.Eval(ctx, `if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('pexpire',KEYS[1],ARGV[2]) else return 0 end`, []string{l.key}, l.owner, l.ttl.Milliseconds()).Err()
		}
	}
}

func (l *LocalSingletonLease) Close() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.cancel()
		<-l.done
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = l.client.Eval(ctx, `if redis.call('get',KEYS[1]) == ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end`, []string{l.key}, l.owner).Err()
	})
}
