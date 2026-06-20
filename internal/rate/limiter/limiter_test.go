package limiter

import (
	"context"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TykTechnologies/tyk/internal/redis"
	"github.com/TykTechnologies/tyk/internal/uuid"
)

// Verifies: SW-REQ-018
// SW-REQ-018:nominal:nominal
func TestNewLimiter(t *testing.T) {
	t.Parallel()

	limiter := NewLimiter(nil)

	require.NotNil(t, limiter)
	assert.Nil(t, limiter.redis)
	assert.NotNil(t, limiter.locker)
	assert.NotNil(t, limiter.logger)
	assert.NotNil(t, limiter.clock)
}

// Verifies: SW-REQ-018
// SW-REQ-018:nominal:nominal
// SW-REQ-018:boundary:nominal
// SW-REQ-018:boundary:boundary
func TestLimiter_LocalAdapters(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewLimiter(nil)

	assertLimiterAllowsFirstRequest(t, ctx, "fixed-window", limiter.FixedWindow)
	assertLimiterAllowsFirstRequest(t, ctx, "sliding-window", limiter.SlidingWindow)
	assertLimiterAllowsFirstRequest(t, ctx, "token-bucket", limiter.TokenBucket)
	assertLimiterAllowsFirstRequest(t, ctx, "leaky-bucket", limiter.LeakyBucket)
}

// Verifies: SW-REQ-018
// SW-REQ-018:nominal:nominal
// SW-REQ-018:boundary:nominal
// SW-REQ-018:boundary:boundary
func TestLimiter_RedisAdapters(t *testing.T) {
	ctx := context.Background()
	client := redis.NewClient(&goredis.Options{Addr: "localhost:6379"})
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, client.Ping(ctx).Err())

	limiter := NewLimiter(client)

	assertLimiterAllowsFirstRequest(t, ctx, "fixed-window", limiter.FixedWindow)
	assertLimiterAllowsFirstRequest(t, ctx, "sliding-window", limiter.SlidingWindow)
	assertLimiterAllowsFirstRequest(t, ctx, "token-bucket", limiter.TokenBucket)
	assertLimiterAllowsFirstRequest(t, ctx, "leaky-bucket", limiter.LeakyBucket)
}

// Verifies: SW-REQ-018
// SW-REQ-018:nominal:nominal
// SW-REQ-018:error_handling:nominal
// SW-REQ-018:error_handling:negative
func TestLimiter_Locker(t *testing.T) {
	ctx := context.Background()

	local := NewLimiter(nil)
	localLocker := local.Locker("local-" + uuid.New())
	require.NotNil(t, localLocker)
	require.NoError(t, localLocker.Lock(ctx))
	require.NoError(t, localLocker.Unlock(ctx))

	client := redis.NewClient(&goredis.Options{Addr: "localhost:6379"})
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(ctx).Err())

	redisLocker := NewLimiter(client).Locker("redis-" + uuid.New())
	require.NotNil(t, redisLocker)
	require.NoError(t, redisLocker.Lock(ctx))
	require.NoError(t, redisLocker.Unlock(ctx))
}

// Verifies: SW-REQ-018
// SW-REQ-018:error_handling:nominal
// SW-REQ-018:error_handling:negative
func TestLimiter_FixedWindowExhaustion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewLimiter(nil)
	key := "fixed-window-exhaustion-" + uuid.New()

	wait, err := limiter.FixedWindow(ctx, key, 1, 60)
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), wait)

	wait, err = limiter.FixedWindow(ctx, key, 1, 60)
	assert.Positive(t, wait)
	assert.ErrorIs(t, err, ErrLimitExhausted)
}

func assertLimiterAllowsFirstRequest(
	t *testing.T,
	ctx context.Context,
	name string,
	limiterFn Func,
) {
	t.Helper()

	wait, err := limiterFn(ctx, name+"-"+uuid.New(), 10, 60)
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), wait)
}
