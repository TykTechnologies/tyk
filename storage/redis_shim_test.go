package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/TykTechnologies/tyk/config"
)

func TestNewRedisController(t *testing.T) {
	ctx := context.Background()
	redisController := NewRedisController(ctx)

	RunNewConnectionHandlerTest(t, redisController.connection)
}

func TestDisableRedis(t *testing.T) {
	ctx := context.Background()
	redisController := NewRedisController(ctx)

	// Initially storage should not be disabled.
	assert.True(t, redisController.connection.enabled(), "Expected storage to be disabled initially")

	// Disable storage and test.
	redisController.DisableRedis(true)
	assert.True(t, redisController.connection.disableStorage.Load().(bool), "Expected storage to be disabled")
	assert.False(t, redisController.Connected(), "Expected storage to not be connected after disabling")
}

func TestConnectToRedis(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, err := config.New()
	assert.NoError(t, err)

	onConnectCalled := make(chan bool, 1)
	onConnect := func() {
		onConnectCalled <- true
	}

	rc := NewRedisController(ctx)
	rc.connection.storageUp.Store(false)
	go rc.ConnectToRedis(ctx, onConnect, conf)

	// let's wait one statusCheck cycle
	time.Sleep(1100 * time.Millisecond)
	// Simulate a connection event
	rc.connection.storageUp.Store(false)

	// Allow some time for the goroutine to run
	time.Sleep(100 * time.Millisecond)
	<-onConnectCalled
	assert.True(t, rc.Connected(), "Expected storage to be connected")
}
