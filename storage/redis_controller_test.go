package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
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

	conf := rcConfig()

	rc := NewRedisController(ctx)
	go rc.Connect(ctx, onRecover, conf)

	rc.Disable(false)

	wg.Wait()
	assert.Equal(t, 1, onReconnectCounter)
}
