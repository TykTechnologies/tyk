package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/TykTechnologies/tyk/config"
	"github.com/TykTechnologies/tyk/test"

	"github.com/stretchr/testify/assert"
)

func TestRecoverLoop(t *testing.T) {
	test.Flaky(t)
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

	rc := NewRedisController()
	go rc.ConnectToRedis(ctx, onRecover, &conf)

	rc.DisableRedis(false)

	wg.Wait()
	assert.Equal(t, 1, onReconnectCounter)
}
