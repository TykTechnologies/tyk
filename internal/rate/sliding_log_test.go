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

// TestSlidingLog_Do is an integration test that tests counter behaviour.
func TestSlidingLog_Do(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	conn, err := storage.NewConnector(storage.DefaultConn, *conf)
	assert.Nil(t, err)

	var db redis.UniversalClient
	ok := conn.As(&db)
	assert.True(t, ok)

	for _, tx := range []bool{true, false} {
		rl := rate.NewSlidingLogRedis(db, tx, func(_ context.Context, key string, currentRate int64, maxAllowedRate int64) bool {
			assert.Equal(t, "key", key)
			assert.Equal(t, int64(40), maxAllowedRate)
			return true
		})
		assert.NotNil(t, rl)

		result, err := rl.Do(ctx, time.Now(), "key", 40, 10)
		assert.True(t, result)
		assert.NoError(t, err)
	}
}

type dummyClientProvider struct{}

func (*dummyClientProvider) Client() (redis.UniversalClient, error) {
	return nil, io.EOF
}

// TestSlidingLog_Errors covers some error branches.
func TestSlidingLog_Errors(t *testing.T) {
	var err error

	_, err = rate.NewSlidingLog(nil, true, nil)
	assert.Error(t, err)

	_, err = rate.NewSlidingLog(&dummyClientProvider{}, true, nil)
	assert.Error(t, io.EOF, err)
}

// TestSlidingLog_GetCount is an integration test that tests counter behaviour.
func TestSlidingLog_GetCount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	conn, err := storage.NewConnector(storage.DefaultConn, *conf)
	assert.Nil(t, err)

	var db redis.UniversalClient
	ok := conn.As(&db)
	assert.True(t, ok)

	for _, tx := range []bool{true, false} {
		assertGetCount(t, ctx, db, tx)
	}
}

// TestSlidingLog_Get is an integration test that tests log behaviour.
func TestSlidingLog_Get(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	conn, err := storage.NewConnector(storage.DefaultConn, *conf)
	assert.Nil(t, err)

	var db redis.UniversalClient
	ok := conn.As(&db)
	assert.True(t, ok)

	for _, tx := range []bool{true, false} {
		assertGet(t, ctx, db, tx)
	}
}

// TestSlidingLog_pipelinerError is testing that pipeline errors are returned as expected.
func TestSlidingLog_pipelinerError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(t, err)

	rc := storage.NewConnectionHandler(ctx)
	go rc.Connect(ctx, nil, conf)

	timeout, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	connected := rc.WaitConnect(timeout)
	if !connected {
		panic("can't connect to redis '" + conf.Storage.Host + "', timeout")
	}

	rl, err := rate.NewSlidingLog(&storage.RedisCluster{KeyPrefix: "test-cluster", ConnectionHandler: rc}, false, nil)
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
	rl := rate.NewSlidingLogRedis(conn, tx, nil)

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

func assertGetCount(tb testing.TB, ctx context.Context, conn redis.UniversalClient, tx bool) {
	tb.Helper()

	rl := rate.NewSlidingLogRedis(conn, tx, nil)

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

func assertGet(tb testing.TB, ctx context.Context, conn redis.UniversalClient, tx bool) {
	tb.Helper()

	rl := rate.NewSlidingLogRedis(conn, tx, nil)

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
	rl := rate.NewSlidingLogRedis(conn, tx, nil)
	assert.NotNil(tb, rl)
}

func BenchmarkSlidingLog_New(b *testing.B) {
	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(b, err)

	conn, err := storage.NewConnector(storage.DefaultConn, *conf)
	assert.Nil(b, err)

	var db redis.UniversalClient
	ok := conn.As(&db)
	assert.True(b, ok)
	b.ResetTimer()

	b.Run("constructor", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertNew(ctx, b, db, false)
		}
	})
}

func BenchmarkSlidingLog_Count(b *testing.B) {
	ctx := context.Background()

	conf, err := config.New()
	assert.NoError(b, err)

	conn, err := storage.NewConnector(storage.DefaultConn, *conf)
	assert.Nil(b, err)

	var db redis.UniversalClient
	ok := conn.As(&db)
	assert.True(b, ok)

	b.ResetTimer()

	b.Run("set/get count pipelined", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGetCount(b, ctx, db, false)
		}
	})

	b.Run("set/get count transaction", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGetCount(b, ctx, db, true)
		}
	})

	b.Run("set/get pipelined", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGet(b, ctx, db, false)
		}
	})

	b.Run("set/get transaction", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertGet(b, ctx, db, true)
		}
	})
}
