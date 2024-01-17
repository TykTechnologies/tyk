package rate_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/internal/redis"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
)

// TestRollingWindow_GetCount is an integration test that tests counter behaviour.
func TestRollingWindow_GetCount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	conn := storage.NewRedisClusterPool(false, false, *conf)

	for _, tx := range []bool{true, false} {
		assertGetCount(ctx, t, conn, tx)
	}
}

// TestRollingWindow_Get is an integration test that tests log behaviour.
func TestRollingWindow_Get(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	conn := storage.NewRedisClusterPool(false, false, *conf)

	for _, tx := range []bool{true, false} {
		assertGet(ctx, t, conn, tx)
	}
}

// TestRollingWindow_pipelinerError is testing that pipeline errors are returned as expected.
func TestRollingWindow_pipelinerError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	rc := storage.NewRedisController(ctx)
	go rc.ConnectToRedis(ctx, nil, conf)

	timeout, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	connected := rc.WaitConnect(timeout)
	if !connected {
		panic("can't connect to redis '" + conf.Storage.Host + "', timeout")
	}

	rl, err := rate.NewSlidingLog(&storage.RedisCluster{KeyPrefix: "test-cluster", RedisController: rc}, false)
	assert.NoError(t, err)

	rl.PipelineFn = func(context.Context, func(redis.Pipeliner) error) error {
		return io.EOF
	}

	_, err = rl.Get(ctx, time.Now(), "test", 5)
	assert.Error(t, err, io.EOF)

	_, err = rl.GetCount(ctx, time.Now(), "test", 5)
	assert.Error(t, err, io.EOF)

	_, err = rl.Set(ctx, time.Now(), "test", 5)
	assert.Error(t, err, io.EOF)

	_, err = rl.SetCount(ctx, time.Now(), "test", 5)
	assert.Error(t, err, io.EOF)
}

const testRequestCount int = 1000

func assertPipelinerError(ctx context.Context, tb testing.TB, conn redis.UniversalClient, tx bool) {
	rl := rate.NewSlidingLogRedis(conn, tx)

	key, per := uuid.New(), int64(5)

	for i := 0; i < testRequestCount; i++ {
		now := time.Now()
		_, err := rl.SetCount(ctx, now, key, per)
		assert.NoError(tb, err)
	}

	now := time.Now()
	count, err := rl.GetCount(ctx, now, key, per)

	assert.NoError(tb, err)
	assert.Equal(tb, int64(testRequestCount), count)
}

func assertGetCount(ctx context.Context, tb testing.TB, conn redis.UniversalClient, tx bool) {
	rl := rate.NewSlidingLogRedis(conn, tx)

	key, per := uuid.New(), int64(5)

	for i := 0; i < testRequestCount; i++ {
		now := time.Now()
		_, err := rl.SetCount(ctx, now, key, per)
		assert.NoError(tb, err)
	}

	now := time.Now()
	count, err := rl.GetCount(ctx, now, key, per)

	assert.NoError(tb, err)
	assert.Equal(tb, int64(testRequestCount), count)
}

func assertGet(ctx context.Context, tb testing.TB, conn redis.UniversalClient, tx bool) {
	rl := rate.NewSlidingLogRedis(conn, tx)

	key, per := uuid.New(), int64(5)

	for i := 0; i < testRequestCount; i++ {
		now := time.Now()
		_, err := rl.Set(ctx, now, key, per)
		assert.NoError(tb, err)
	}

	now := time.Now()
	count, err := rl.Get(ctx, now, key, per)

	assert.NoError(tb, err)
	assert.Len(tb, count, testRequestCount)
}

func assertNew(ctx context.Context, tb testing.TB, conn redis.UniversalClient, tx bool) {
	rl := rate.NewSlidingLogRedis(conn, tx)
	assert.NotNil(tb, rl)
}

func BenchmarkRollingWindow_New(b *testing.B) {
	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(b, err)

	conn := storage.NewRedisClusterPool(false, false, *conf)

	b.ResetTimer()

	b.Run("constructor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertNew(ctx, b, conn, false)
		}
	})
}

func BenchmarkRollingWindow_Count(b *testing.B) {
	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(b, err)

	conn := storage.NewRedisClusterPool(false, false, *conf)

	b.ResetTimer()

	b.Run("set/get count pipelined", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGetCount(ctx, b, conn, false)
		}
	})

	b.Run("set/get count transaction", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGetCount(ctx, b, conn, true)
		}
	})

	b.Run("set/get pipelined", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGet(ctx, b, conn, false)
		}
	})

	b.Run("set/get transaction", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGet(ctx, b, conn, true)
		}
	})
}
