package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

func TestRecoverLoop(t *testing.T) {
	t.Parallel()

	var onReconnectCounter int
	var wg sync.WaitGroup
	wg.Add(1)
	onRecover := func() {
		onReconnectCounter++
		wg.Done()
	}
	ctx := context.Background()

	conf := config.Default

	rc := NewRedisController(ctx)
	go rc.ConnectToRedis(ctx, onRecover, &conf)

	rc.DisableRedis(false)

	wg.Wait()
	assert.Equal(t, 1, onReconnectCounter)
}
