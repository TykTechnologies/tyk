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
