//go:build integration
// +build integration

package rate_test

import (
	"context"
	"testing"
	"time"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/internal/rate"
	"github.com/TykTechnologies/tyk/internal/uuid"
	"github.com/TykTechnologies/tyk/storage"
	"github.com/stretchr/testify/assert"
)

// TestRollingWindow is an integration test that tests Get/Set behaviour.
func TestRollingWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cfg, err := config.New()
	assert.NoError(t, err)

	conn := storage.NewRedisClusterPool(false, false, *cfg)

	rl := rate.NewRollingWindow(conn)

	per := int64(5)
	for _, tx := range []bool{true, false} {
		key := uuid.New()

		// Issue 3 adds
		rl.Set(ctx, time.Now(), key, per, "-1", tx)
		rl.Set(ctx, time.Now(), key, per, "-1", tx)
		got, err := rl.Set(ctx, time.Now(), key, per, "-1", tx)

		// Assert value of last set / last value.
		assert.NoError(t, err)
		assert.Len(t, got, 3)

		// pipelinedTx get
		final, err := rl.Get(ctx, time.Now(), key, per, tx)

		assert.NoError(t, err)
		assert.Equal(t, got, final)
	}
}

// TestRollingWindow is an integration test that tests Count behaviour.
func TestRollingWindow_Count(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cfg, err := config.New()
	assert.NoError(t, err)

	conn := storage.NewRedisClusterPool(false, false, *cfg)

	rl := rate.NewRollingWindow(conn)

	for _, tx := range []bool{true, false} {
		assertRateCount(ctx, t, rl, tx)
	}
}

const testRequestCount int64 = 100

func assertRateCount(ctx context.Context, tb testing.TB, rl *rate.RollingWindow, tx bool) {
	key, per := uuid.New(), int64(5)

	for i := int64(0); i < testRequestCount; i++ {
		_, err := rl.Set(ctx, time.Now(), key, per, "-1", tx)
		assert.NoError(tb, err)
	}

	// verify rl.Count implementation
	count, err := rl.Count(ctx, key, time.Now(), per)

	assert.NoError(tb, err)
	assert.Equal(tb, int64(testRequestCount), count)
}

func assertRateCountV2(ctx context.Context, tb testing.TB, rl *rate.RollingWindow) {
	key, per := uuid.New(), int64(5)

	for i := int64(0); i < testRequestCount; i++ {
		assert.NoError(tb, rl.Add(ctx, key, time.Now(), per))
	}

	// verify rl.Count implementation
	count, err := rl.Count(ctx, key, time.Now(), per)

	assert.NoError(tb, err)
	assert.Equal(tb, testRequestCount, count)
}

func assertRateCountV3(ctx context.Context, tb testing.TB, rl *rate.RollingWindow) {
	key, per := uuid.New(), int64(5)

	for i := int64(0); i < testRequestCount; i++ {
		assert.NoError(tb, rl.Increment(ctx, key, time.Now(), per))
	}

	// verify rl.Count implementation
	count, err := rl.GetCount(ctx, key, time.Now(), per)

	assert.NoError(tb, err)
	assert.Equal(tb, testRequestCount, count)
}

func BenchmarkRollingWindow_Count(b *testing.B) {
	ctx := context.Background()

	cfg, err := config.New()
	assert.NoError(b, err)

	conn := storage.NewRedisClusterPool(false, false, *cfg)

	rl := rate.NewRollingWindow(conn)

	b.ResetTimer()

	b.Run("count v2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertRateCountV3(ctx, b, rl)
		}
	})

	b.Run("count", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertRateCountV2(ctx, b, rl)
		}
	})

	b.Run("pipelineTx", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertRateCount(ctx, b, rl, false)
		}
	})

	b.Run("pipeline", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			assertRateCount(ctx, b, rl, true)
		}
	})
}
